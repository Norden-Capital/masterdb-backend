package ca.nordencapital.masterdb.validation.bulk;

import ca.nordencapital.masterdb.activity.ActivityAction;
import ca.nordencapital.masterdb.activity.ActivityLog;
import ca.nordencapital.masterdb.activity.ActivityLog.Party;
import ca.nordencapital.masterdb.auth.session.AuthPrincipal;
import ca.nordencapital.masterdb.servers.ServerService.Server;
import ca.nordencapital.masterdb.validation.Category;
import ca.nordencapital.masterdb.validation.ValidationServers;
import ca.nordencapital.masterdb.validation.engine.EmailAddress;
import ca.nordencapital.masterdb.web.error.BadRequestException;
import ca.nordencapital.masterdb.web.error.ConflictException;
import ca.nordencapital.masterdb.web.error.NotFoundException;
import ca.nordencapital.masterdb.web.paging.PageResponse;
import org.springframework.data.domain.Pageable;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import java.sql.Timestamp;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/**
 * Validation, job 2: bulk validation. A job checks a set of addresses through
 * one or more servers in the background ({@link BulkRunner}); the page only
 * starts it and polls. Stop and resume; "Retry unknown" puts the unknown
 * addresses back in the same job; totals always add up to the job's size.
 */
@Service
public class BulkJobService {

    public static final int MAX_EMAILS = 50_000;
    public static final int MAX_SERVERS = 10;

    private final JdbcTemplate jdbc;
    private final ValidationServers servers;
    private final BulkRunner runner;
    private final ActivityLog activity;
    private final Clock clock;
    private final TransactionTemplate tx;

    public BulkJobService(JdbcTemplate jdbc, ValidationServers servers, BulkRunner runner, ActivityLog activity,
            Clock clock, PlatformTransactionManager transactions) {
        this.jdbc = jdbc;
        this.servers = servers;
        this.runner = runner;
        this.activity = activity;
        this.clock = clock;
        this.tx = new TransactionTemplate(transactions);
    }

    public enum Status { RUNNING, STOPPED, COMPLETED }

    /** One server of a job: how many it checked, and what it is doing now (only while the job runs). */
    public record JobServer(UUID publicId, String name, String ip, int checked, String state, String message) {
    }

    public record JobView(UUID publicId, String name, String source, Status status, int total, int pending,
            int checked, int valid, int bounce, int softBounce, int reject, int catchAll, int unknown, int duplicates,
            int invalid, int retries, String message, List<JobServer> servers, Integer perMinute, String startedBy,
            Instant createdAt, Instant startedAt, Instant finishedAt) {
    }

    public record CreateRequest(String name, String emails, List<UUID> serverIds) {
    }

    record Job(long id, UUID publicId, String name, String source, Status status, int total, int pending, int valid,
            int bounce, int softBounce, int reject, int catchAll, int unknown, int duplicates, int invalid,
            int retries, String message, String actorLabel, Instant createdAt, Instant startedAt,
            Instant finishedAt) {
    }

    static final RowMapper<Job> JOB = (rs, n) -> new Job(rs.getLong("id"), rs.getObject("public_id", UUID.class),
            rs.getString("name"), rs.getString("source"), Status.valueOf(rs.getString("status")), rs.getInt("total"),
            rs.getInt("pending"), rs.getInt("valid"), rs.getInt("bounce"), rs.getInt("soft_bounce"),
            rs.getInt("reject"), rs.getInt("catch_all"), rs.getInt("unknown"), rs.getInt("duplicates"),
            rs.getInt("invalid"), rs.getInt("retries"), rs.getString("message"), rs.getString("actor_label"),
            ts(rs.getTimestamp("created_at")), ts(rs.getTimestamp("started_at")),
            ts(rs.getTimestamp("finished_at")));

    // ---- start -------------------------------------------------------------------

    /** What a paste holds: the addresses to check, and what was dropped. */
    record Parsed(List<String> emails, int duplicates, int invalid) {
    }

    /**
     * One address per line. A line may be a CSV row: its first field with an
     * {@code @} is taken. Blank lines are skipped; duplicates (case ignored) and
     * malformed addresses are counted and dropped.
     */
    static Parsed parse(String text) {
        Set<String> seen = new HashSet<>();
        List<String> out = new ArrayList<>();
        int duplicates = 0;
        int invalid = 0;
        for (String line : (text == null ? "" : text).split("\\r?\\n|\\r")) {
            if (line.isBlank()) {
                continue;
            }
            String candidate = null;
            for (String field : line.split("[,;\\t]")) {
                String f = field.trim();
                if (f.length() >= 2 && f.startsWith("\"") && f.endsWith("\"")) {
                    f = f.substring(1, f.length() - 1).trim();
                }
                if (f.contains("@")) {
                    candidate = f;
                    break;
                }
            }
            var email = EmailAddress.parse(candidate);
            if (email.isEmpty()) {
                invalid++;
            } else if (!seen.add(email.get().normalized())) {
                duplicates++;
            } else {
                out.add(email.get().address());
            }
        }
        return new Parsed(out, duplicates, invalid);
    }

    public JobView create(AuthPrincipal caller, CreateRequest req) {
        List<Server> chosen = chosenServers(req.serverIds());
        Parsed p = parse(req.emails());
        if (p.emails().isEmpty()) {
            throw BadRequestException.validation("emails", p.invalid() > 0 ? "has no valid email address"
                    : "is empty: paste one email address per line");
        }
        if (p.emails().size() > MAX_EMAILS) {
            throw BadRequestException.validation("emails", "has " + p.emails().size() + " addresses; at most "
                    + MAX_EMAILS + " per job");
        }
        String name = req.name() == null || req.name().isBlank()
                ? "Pasted list · " + p.emails().size() + " emails" : req.name().trim();
        if (name.length() > 120) {
            throw BadRequestException.validation("name", "is longer than 120 characters");
        }
        Instant now = clock.instant();
        Timestamp t = Timestamp.from(now);
        UUID publicId = UUID.randomUUID();
        long jobId = tx.execute(s -> {
            Long id = jdbc.queryForObject("insert into validation_jobs (public_id, name, source, status, total, "
                            + "pending, duplicates, invalid, actor_public_id, actor_label, created_at, started_at, "
                            + "updated_at) values (?,?,'PASTE','RUNNING',?,?,?,?,?,?,?,?,?) returning id", Long.class,
                    publicId, name, p.emails().size(), p.emails().size(), p.duplicates(), p.invalid(),
                    caller.userPublicId(), cut(caller.email(), 254), t, t, t);
            saveServers(id, chosen);
            List<Object[]> rows = new ArrayList<>(p.emails().size());
            for (int i = 0; i < p.emails().size(); i++) {
                rows.add(new Object[] {id, i + 1, p.emails().get(i)});
            }
            jdbc.batchUpdate("insert into validation_job_emails (job_id, seq, email) values (?,?,?)", rows);
            activity.record(ActivityAction.VALIDATION_JOB_STARTED, Party.of(caller), Party.label(name),
                    details(publicId, p.emails().size(), chosen));
            return id;
        });
        runner.start(jobId);
        return get(publicId);
    }

    private List<Server> chosenServers(List<UUID> ids) {
        if (ids == null || ids.isEmpty()) {
            throw BadRequestException.validation("serverIds", "choose at least one server");
        }
        Set<UUID> distinct = new LinkedHashSet<>(ids);
        if (distinct.size() > MAX_SERVERS) {
            throw BadRequestException.validation("serverIds", "at most " + MAX_SERVERS + " servers per job");
        }
        List<Server> out = new ArrayList<>();
        for (UUID id : distinct) {
            out.add(servers.ready(id));
        }
        return out;
    }

    private void saveServers(long jobId, List<Server> chosen) {
        jdbc.update("delete from validation_job_servers where job_id = ?", jobId);
        for (Server s : chosen) {
            jdbc.update("insert into validation_job_servers (job_id, server_id) values (?,?)", jobId, s.id());
        }
    }

    // ---- control -----------------------------------------------------------------

    public JobView stop(AuthPrincipal caller, UUID publicId) {
        Job j = find(publicId);
        if (j.status() != Status.RUNNING) {
            throw new ConflictException("This job is not running.");
        }
        tx.executeWithoutResult(s -> {
            jdbc.update("update validation_jobs set status = 'STOPPED', message = ?, updated_at = ? where id = ? "
                    + "and status = 'RUNNING'", "Stopped by " + caller.email() + ".", Timestamp.from(clock.instant()),
                    j.id());
            activity.record(ActivityAction.VALIDATION_JOB_STOPPED, Party.of(caller), Party.label(j.name()),
                    Map.of("job", j.publicId().toString(), "pending", j.pending()));
        });
        runner.stop(j.id());
        return get(publicId);
    }

    /** Goes on with the addresses still to check; {@code serverIds} (optional) changes the servers. */
    public JobView resume(AuthPrincipal caller, UUID publicId, List<UUID> serverIds) {
        Job j = find(publicId);
        if (j.status() != Status.STOPPED) {
            throw new ConflictException(j.status() == Status.RUNNING ? "This job is already running."
                    : "This job is finished. Retry unknown checks its unknown addresses again.");
        }
        if (j.pending() == 0) {
            throw new ConflictException("Nothing is left to check in this job.");
        }
        List<Server> chosen = serverIds == null || serverIds.isEmpty() ? currentServers(j.id())
                : chosenServers(serverIds);
        tx.executeWithoutResult(s -> {
            saveServers(j.id(), chosen);
            jdbc.update("update validation_jobs set status = 'RUNNING', message = null, finished_at = null, "
                    + "updated_at = ? where id = ?", Timestamp.from(clock.instant()), j.id());
            activity.record(ActivityAction.VALIDATION_JOB_RESUMED, Party.of(caller), Party.label(j.name()),
                    details(j.publicId(), j.pending(), chosen));
        });
        runner.start(j.id());
        return get(publicId);
    }

    /** The unknown addresses go back to "to check", in the same job (counted once, never twice). */
    public JobView retryUnknown(AuthPrincipal caller, UUID publicId, List<UUID> serverIds) {
        Job j = find(publicId);
        if (j.status() == Status.RUNNING) {
            throw new ConflictException("Wait for the job to finish (or stop it) before retrying unknown.");
        }
        if (j.unknown() == 0) {
            throw new ConflictException("This job has no unknown addresses.");
        }
        List<Server> chosen = serverIds == null || serverIds.isEmpty() ? currentServers(j.id())
                : chosenServers(serverIds);
        tx.executeWithoutResult(s -> {
            saveServers(j.id(), chosen);
            int n = jdbc.update("update validation_job_emails set category = null, claimed_by = null, attempts = 0 "
                    + "where job_id = ? and category = 'UNKNOWN'", j.id());
            jdbc.update("update validation_jobs set unknown = unknown - ?, pending = pending + ?, retries = retries "
                    + "+ 1, status = 'RUNNING', message = null, finished_at = null, updated_at = ? where id = ?", n, n,
                    Timestamp.from(clock.instant()), j.id());
            activity.record(ActivityAction.VALIDATION_JOB_RETRIED, Party.of(caller), Party.label(j.name()),
                    details(j.publicId(), n, chosen));
        });
        runner.start(j.id());
        return get(publicId);
    }

    public void delete(AuthPrincipal caller, UUID publicId) {
        Job j = find(publicId);
        if (j.status() == Status.RUNNING || runner.isRunning(j.id())) {
            throw new ConflictException("Stop the job and wait for it to stop before deleting it.");
        }
        tx.executeWithoutResult(s -> {
            jdbc.update("delete from validation_jobs where id = ?", j.id());
            activity.record(ActivityAction.VALIDATION_JOB_DELETED, Party.of(caller), Party.label(j.name()),
                    Map.of("job", j.publicId().toString(), "total", j.total()));
        });
    }

    private List<Server> currentServers(long jobId) {
        List<UUID> ids = jdbc.queryForList("select s.public_id from validation_job_servers js join servers s on "
                + "s.id = js.server_id where js.job_id = ? order by s.id", UUID.class, jobId);
        if (ids.isEmpty()) {
            throw BadRequestException.validation("serverIds", "the job's servers were deleted: choose a server");
        }
        return chosenServers(ids);
    }

    // ---- read --------------------------------------------------------------------

    Job find(UUID publicId) {
        List<Job> found = jdbc.query("select * from validation_jobs where public_id = ?", JOB, publicId);
        if (found.isEmpty()) {
            throw new NotFoundException("This validation job is not in MasterDB.");
        }
        return found.getFirst();
    }

    public JobView get(UUID publicId) {
        return view(find(publicId), true);
    }

    public PageResponse<JobView> list(Status status, Pageable pageable) {
        String where = status == null ? "" : " where status = '" + status.name() + "'";
        Long total = jdbc.queryForObject("select count(*) from validation_jobs" + where, Long.class);
        List<JobView> items = jdbc.query("select * from validation_jobs" + where
                        + " order by created_at desc, id desc limit ? offset ?", JOB, pageable.getPageSize(),
                pageable.getOffset()).stream().map(j -> view(j, false)).toList();
        long count = total == null ? 0 : total;
        int pages = (int) ((count + pageable.getPageSize() - 1) / pageable.getPageSize());
        return new PageResponse<>(items, pageable.getPageNumber(), pageable.getPageSize(), count, pages);
    }

    private JobView view(Job j, boolean live) {
        Map<Long, Integer> checked = new LinkedHashMap<>();
        if (live) {
            jdbc.query("select server_id, count(*) from validation_job_emails where job_id = ? and category is not "
                    + "null and server_id is not null group by server_id", rs -> {
                        checked.put(rs.getLong(1), rs.getInt(2));
                    }, j.id());
        }
        List<JobServer> list = new ArrayList<>();
        jdbc.query("select s.id, s.public_id, s.name, s.ip from validation_job_servers js join servers s on s.id = "
                + "js.server_id where js.job_id = ? order by s.name", rs -> {
                    long sid = rs.getLong(1);
                    BulkRunner.WorkerState w = live && j.status() == Status.RUNNING ? runner.state(j.id(), sid) : null;
                    list.add(new JobServer(rs.getObject(2, UUID.class), rs.getString(3), rs.getString(4),
                            checked.getOrDefault(sid, 0), w == null ? null : w.state(),
                            w == null ? null : w.message()));
                }, j.id());
        Integer perMinute = null;
        if (live && j.status() == Status.RUNNING) {
            Integer recent = jdbc.queryForObject("select count(*) from validation_job_emails where job_id = ? and "
                    + "checked_at > ?", Integer.class, j.id(), Timestamp.from(clock.instant().minusSeconds(300)));
            perMinute = recent == null ? 0 : Math.round(recent / 5f);
        }
        int done = j.total() - j.pending();
        return new JobView(j.publicId(), j.name(), j.source(), j.status(), j.total(), j.pending(), done, j.valid(),
                j.bounce(), j.softBounce(), j.reject(), j.catchAll(), j.unknown(), j.duplicates(), j.invalid(),
                j.retries(), j.message(), list, perMinute, j.actorLabel(), j.createdAt(), j.startedAt(),
                j.finishedAt());
    }

    /** The job's counter column for a category (fixed names, never user input). */
    static String column(Category c) {
        return switch (c) {
            case VALID -> "valid";
            case BOUNCE -> "bounce";
            case SOFT_BOUNCE -> "soft_bounce";
            case REJECT -> "reject";
            case CATCH_ALL -> "catch_all";
            case UNKNOWN -> "unknown";
        };
    }

    private static Map<String, Object> details(UUID job, int emails, List<Server> chosen) {
        Map<String, Object> d = new LinkedHashMap<>();
        d.put("job", job.toString());
        d.put("emails", emails);
        d.put("servers", String.join(", ", chosen.stream().map(s -> s.item().name()).toList()));
        return d;
    }

    private static String cut(String v, int max) {
        return v == null ? null : v.length() <= max ? v : v.substring(0, max);
    }

    private static Instant ts(Timestamp t) {
        return t == null ? null : t.toInstant();
    }
}
