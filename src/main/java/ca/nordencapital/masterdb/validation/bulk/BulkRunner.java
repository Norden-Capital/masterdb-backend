package ca.nordencapital.masterdb.validation.bulk;

import ca.nordencapital.masterdb.activity.ActivityAction;
import ca.nordencapital.masterdb.activity.ActivityLog;
import ca.nordencapital.masterdb.activity.ActivityLog.Party;
import ca.nordencapital.masterdb.servers.ServerService.Server;
import ca.nordencapital.masterdb.servers.ServerSsh;
import ca.nordencapital.masterdb.servers.ssh.SshRunner.Tunnel;
import ca.nordencapital.masterdb.validation.Category;
import ca.nordencapital.masterdb.validation.Pacing;
import ca.nordencapital.masterdb.validation.ValidationServers;
import ca.nordencapital.masterdb.validation.engine.EmailAddress;
import ca.nordencapital.masterdb.validation.engine.SmtpProber;
import ca.nordencapital.masterdb.validation.engine.SmtpProber.Verdict;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.DisposableBean;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import java.sql.Timestamp;
import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Runs bulk jobs in the background: one worker per server of the job, each
 * with its own SSH connection. Workers take the next address still to check
 * (so the work rotates between the servers), skip providers that are paused
 * for their server (another server takes them), and save each result with
 * the job's counters in one transaction. A backend restart resumes every
 * running job.
 */
@Component
public class BulkRunner implements DisposableBean {

    /** A "slow down" answer puts the address back this many times before it is saved as unknown. */
    static final int MAX_ATTEMPTS = 3;
    private static final int MAX_CONNECT_FAILURES = 3;
    private static final Duration SSH_TIMEOUT = Duration.ofSeconds(20);
    private static final Logger log = LoggerFactory.getLogger(BulkRunner.class);

    private final JdbcTemplate jdbc;
    private final ValidationServers servers;
    private final ServerSsh ssh;
    private final SmtpProber prober;
    private final Pacing pacing;
    private final ActivityLog activity;
    private final Clock clock;
    private final TransactionTemplate tx;
    private final long idleMs;
    private final ExecutorService pool = Executors.newCachedThreadPool(r -> {
        Thread t = new Thread(r, "validation-worker");
        t.setDaemon(true);
        return t;
    });
    private final Map<Long, Run> runs = new ConcurrentHashMap<>();
    /** Copies the addresses of jobs on a list, one job at a time. */
    private final ExecutorService preparer = Executors.newSingleThreadExecutor(r -> {
        Thread t = new Thread(r, "validation-prepare");
        t.setDaemon(true);
        return t;
    });
    /** Members copied per statement while a job on a list is prepared. */
    static final int PREPARE_CHUNK = 50_000;
    private final ListValidation summaries;

    public BulkRunner(JdbcTemplate jdbc, ValidationServers servers, ServerSsh ssh, SmtpProber prober, Pacing pacing,
            ActivityLog activity, Clock clock, PlatformTransactionManager transactions, ListValidation summaries,
            @Value("${app.validation.worker-idle:3s}") Duration idle) {
        this.summaries = summaries;
        this.jdbc = jdbc;
        this.servers = servers;
        this.ssh = ssh;
        this.prober = prober;
        this.pacing = pacing;
        this.activity = activity;
        this.clock = clock;
        this.tx = new TransactionTemplate(transactions);
        this.idleMs = idle.toMillis();
    }

    /** What one server is doing in a running job, for the page. */
    public record WorkerState(String state, String message) {
    }

    private static final class Run {
        final long jobId;
        volatile boolean stop;
        final AtomicInteger alive = new AtomicInteger();
        final Map<Long, WorkerState> states = new ConcurrentHashMap<>();

        Run(long jobId) {
            this.jobId = jobId;
        }
    }

    private record Row(long id, String email, String provider, int attempts) {
    }

    // ---- control -----------------------------------------------------------------

    /** Starts the workers of a RUNNING job (no-op if they are already running). */
    public synchronized void start(long jobId) {
        Run current = runs.get(jobId);
        if (current != null && !current.stop) {
            return;
        }
        Run run = new Run(jobId);
        List<Object[]> chosen = jdbc.query("select s.id, s.public_id from validation_job_servers js join servers s "
                + "on s.id = js.server_id where js.job_id = ?", (rs, n) -> new Object[] {rs.getLong(1),
                rs.getObject(2, UUID.class)}, jobId);
        if (chosen.isEmpty()) {
            stopped(jobId, "None of this job's servers exists any more. Resume it with another server.");
            return;
        }
        runs.put(jobId, run);
        for (Object[] s : chosen) {
            run.alive.incrementAndGet();
            run.states.put((Long) s[0], new WorkerState("STARTING", null));
            pool.submit(() -> work(run, (Long) s[0], (UUID) s[1]));
        }
    }

    public void stop(long jobId) {
        Run run = runs.get(jobId);
        if (run != null) {
            run.stop = true;
        }
    }

    public boolean isRunning(long jobId) {
        Run run = runs.get(jobId);
        return run != null && run.alive.get() > 0;
    }

    public WorkerState state(long jobId, long serverId) {
        Run run = runs.get(jobId);
        return run == null ? null : run.states.get(serverId);
    }

    /**
     * Copies a list's addresses into a PREPARING job (in chunks, each address
     * once, in list order; the counters grow as it goes), then starts it. An
     * address repeated in the list is taken at its first place in the list
     * (or the part) and counted as a duplicate.
     */
    public void prepare(long jobId) {
        preparer.submit(() -> {
            try {
                copyFromList(jobId);
            } catch (RuntimeException e) {
                log.error("validation job {}: preparing from the list failed", jobId, e);
                jdbc.update("update validation_jobs set status = 'STOPPED', message = ?, updated_at = ? where id = ? "
                        + "and status = 'PREPARING'", "The list's addresses could not be read. Delete this job and "
                        + "start it again.", Timestamp.from(clock.instant()), jobId);
            }
        });
    }

    private void copyFromList(long jobId) {
        List<Map<String, Object>> found = jdbc.queryForList("select list_id, list_part from validation_jobs where id = ? "
                + "and status = 'PREPARING'", jobId);
        if (found.isEmpty()) {
            return;
        }
        Object listObj = found.getFirst().get("list_id");
        Object partObj = found.getFirst().get("list_part");
        if (listObj == null) {
            jdbc.update("update validation_jobs set status = 'STOPPED', message = ? where id = ? and status = "
                    + "'PREPARING'", "The list was deleted before its addresses were copied.", jobId);
            return;
        }
        long listId = ((Number) listObj).longValue();
        List<int[]> range = partObj == null
                ? jdbc.query("select 1, records from lists where id = ?", (rs, n) -> new int[] {rs.getInt(1),
                        rs.getInt(2)}, listId)
                : jdbc.query("select first_seq, last_seq from list_parts where list_id = ? and part_no = ?",
                        (rs, n) -> new int[] {rs.getInt(1), rs.getInt(2)}, listId, ((Number) partObj).intValue());
        int first = range.isEmpty() ? 1 : range.getFirst()[0];
        int last = range.isEmpty() ? 0 : range.getFirst()[1];
        int members = Math.max(0, last - first + 1);
        jdbc.update("delete from validation_job_emails where job_id = ?", jobId);
        jdbc.update("update validation_jobs set total = 0, pending = 0, valid = 0, bounce = 0, soft_bounce = 0, "
                + "reject = 0, catch_all = 0, unknown = 0 where id = ?", jobId);
        int copied = 0;
        for (int from = first; from <= last; from += PREPARE_CHUNK) {
            int base = copied;
            int to = Math.min(last, from + PREPARE_CHUNK - 1);
            int start = from;
            Integer n = tx.execute(s -> {
                int added = jdbc.update("insert into validation_job_emails (job_id, seq, email, member_id) select ?, "
                        + "? + row_number() over (order by m.seq), m.email, m.id from list_members m where m.list_id = ? "
                        + "and m.seq between ? and ? and not exists (select 1 from list_members p where p.contact_id = "
                        + "m.contact_id and p.list_id = m.list_id and p.seq < m.seq and p.seq >= ?)", jobId, base,
                        listId, start, to, first);
                jdbc.update("update validation_jobs set total = total + ?, pending = pending + ?, message = ?, "
                        + "updated_at = ? where id = ? and status = 'PREPARING'", added, added, "Copying the list's "
                        + "addresses: " + String.format(java.util.Locale.ROOT, "%,d", to - first + 1) + " of "
                        + String.format(java.util.Locale.ROOT, "%,d", members) + ".", Timestamp.from(clock.instant()),
                        jobId);
                return added;
            });
            copied += n == null ? 0 : n;
        }
        int total = copied;
        int n = jdbc.update("update validation_jobs set status = 'RUNNING', duplicates = ?, message = null, updated_at = "
                + "? where id = ? and status = 'PREPARING'", members - total, Timestamp.from(clock.instant()), jobId);
        if (n == 1) {
            log.info("validation job {}: {} addresses copied from list {}", jobId, total, listId);
            start(jobId);
        }
    }

    /** After a restart: claims of the old workers are free again, and every running job goes on. */
    @EventListener(ApplicationReadyEvent.class)
    public void resumeAfterRestart() {
        for (long id : jdbc.queryForList("select id from validation_jobs where status = 'PREPARING' order by id",
                Long.class)) {
            log.info("validation job {}: copying its list again after a restart", id);
            prepare(id);
        }
        jdbc.update("update validation_job_emails set claimed_by = null where claimed_by is not null");
        List<Long> running = jdbc.queryForList("select id from validation_jobs where status = 'RUNNING' order by id",
                Long.class);
        for (long id : running) {
            log.info("validation job {} resumed after a restart", id);
            start(id);
        }
    }

    @Override
    public void destroy() {
        runs.values().forEach(r -> r.stop = true);
        preparer.shutdownNow();
        pool.shutdownNow();
        try {
            pool.awaitTermination(5, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    // ---- one worker --------------------------------------------------------------

    private void work(Run run, long serverId, UUID serverPublicId) {
        Tunnel tunnel = null;
        Server server = null;
        Row current = null;
        int failures = 0;
        try {
            while (!run.stop && running(run.jobId)) {
                if (tunnel == null || !tunnel.isOpen()) {
                    close(tunnel);
                    tunnel = null;
                    try {
                        server = servers.ready(serverPublicId);
                        tunnel = ssh.tunnel(server, SSH_TIMEOUT);
                        failures = 0;
                        run.states.put(serverId, new WorkerState("CHECKING", null));
                    } catch (RuntimeException e) {
                        failures++;
                        String why = e.getMessage() == null ? "It could not be reached." : e.getMessage();
                        run.states.put(serverId, new WorkerState("ERROR", why));
                        log.info("validation job {}: server {} not usable ({} in a row): {}", run.jobId,
                                serverPublicId, failures, why);
                        if (failures >= MAX_CONNECT_FAILURES) {
                            break;
                        }
                        sleep(run, idleMs * failures * 3);
                        continue;
                    }
                }
                List<String> paused = pacing.paused(serverId);
                current = claim(run.jobId, serverId, paused);
                if (current == null) {
                    if (finishIfDone(run.jobId)) {
                        break;
                    }
                    run.states.put(serverId, new WorkerState("WAITING", paused.isEmpty()
                            ? "The last addresses are being checked by the other servers."
                            : "Paused for " + String.join(", ", paused.stream().map(pacing::label).toList())
                            + " after a \"slow down\" answer; nothing else to check."));
                    sleep(run, idleMs);
                    continue;
                }
                EmailAddress email = EmailAddress.parse(current.email()).orElseThrow();
                String provider = current.provider() != null ? current.provider()
                        : pacing.provider(prober.destinations(email).primary(email.domain()));
                if (paused.contains(provider) || !pacing.check(serverId, provider).allowed()) {
                    release(current.id(), provider, false);
                    current = null;
                    continue;
                }
                run.states.put(serverId, new WorkerState("CHECKING", null));
                if (!pacing.acquire(serverId, provider, () -> run.stop)) {
                    break;
                }
                Verdict v = prober.verify(tunnel, ValidationServers.identity(server), email);
                if (!tunnel.isOpen()) {
                    // The SSH connection broke during the check: its answer can't be trusted.
                    release(current.id(), provider, false);
                    current = null;
                    continue;
                }
                pacing.observe(serverId, provider, v);
                if (v.rateLimited() && current.attempts() + 1 < MAX_ATTEMPTS) {
                    release(current.id(), provider, true);
                } else {
                    save(run.jobId, current, v, server, provider);
                }
                current = null;
            }
        } catch (RuntimeException e) {
            log.error("validation job {}: worker for server {} failed", run.jobId, serverPublicId, e);
            run.states.put(serverId, new WorkerState("ERROR", "Stopped by an unexpected error."));
        } finally {
            close(tunnel);
            if (current != null) {
                try {
                    release(current.id(), current.provider(), false);
                } catch (RuntimeException ignored) {
                    // freed at the next start anyway
                }
            }
            workerDone(run, serverId);
        }
    }

    private void workerDone(Run run, long serverId) {
        WorkerState last = run.states.get(serverId);
        if (run.alive.decrementAndGet() > 0) {
            return;
        }
        synchronized (this) {
            runs.remove(run.jobId, run);
        }
        if (run.stop || finishIfDone(run.jobId) || !running(run.jobId)) {
            return;
        }
        List<String> why = new ArrayList<>();
        run.states.values().forEach(w -> {
            if (w.message() != null && !why.contains(w.message())) {
                why.add(w.message());
            }
        });
        stopped(run.jobId, "Stopped: no server could check. " + (why.isEmpty() ? "" : String.join(" ", why))
                + " Resume it when the server is fixed.");
        if (last != null) {
            log.info("validation job {} stopped: no worker left", run.jobId);
        }
    }

    private void stopped(long jobId, String message) {
        summaries.refreshLater(jdbc.queryForList("select list_id from validation_jobs where id = ?", Long.class, jobId)
                .stream().filter(java.util.Objects::nonNull).findFirst().orElse(null));
        jdbc.update("update validation_jobs set status = 'STOPPED', message = ?, updated_at = ? where id = ? and "
                + "status = 'RUNNING'", cut(message, 500), Timestamp.from(clock.instant()), jobId);
    }

    // ---- database ----------------------------------------------------------------

    private boolean running(long jobId) {
        List<String> s = jdbc.queryForList("select status from validation_jobs where id = ?", String.class, jobId);
        return !s.isEmpty() && s.getFirst().equals("RUNNING");
    }

    /** The next address to check, skipping providers paused for this server. */
    private Row claim(long jobId, long serverId, List<String> paused) {
        List<Object> args = new ArrayList<>(List.of(serverId, jobId));
        String skip = "";
        if (!paused.isEmpty()) {
            skip = " and (provider is null or provider not in (" + String.join(",", paused.stream().map(p -> "?")
                    .toList()) + "))";
            args.addAll(paused);
        }
        List<Row> rows = jdbc.query("update validation_job_emails set claimed_by = ? where id = (select id from "
                + "validation_job_emails where job_id = ? and category is null and claimed_by is null" + skip
                + " order by seq limit 1 for update skip locked) returning id, email, provider, attempts",
                (rs, n) -> new Row(rs.getLong(1), rs.getString(2), rs.getString(3), rs.getInt(4)), args.toArray());
        return rows.isEmpty() ? null : rows.getFirst();
    }

    private void release(long rowId, String provider, boolean attempted) {
        jdbc.update("update validation_job_emails set claimed_by = null, provider = coalesce(?, provider), "
                + "attempts = attempts + ? where id = ?", provider, attempted ? 1 : 0, rowId);
    }

    private void save(long jobId, Row row, Verdict v, Server server, String provider) {
        String col = BulkJobService.column(v.category());
        Timestamp now = Timestamp.from(clock.instant());
        tx.executeWithoutResult(s -> {
            int n = jdbc.update("update validation_job_emails set category = ?, smtp_code = ?, mx_host = ?, reason = "
                            + "?, reply = ?, server_id = ?, server_name = ?, checked_at = ?, attempts = attempts + 1, "
                            + "provider = ?, claimed_by = null where id = ? and category is null", v.category().name(),
                    v.code(), cut(v.mx(), 253), cut(v.reason(), 500), cut(v.reply(), 500), server.id(),
                    server.item().name(), now, provider, row.id());
            if (n == 1) {
                jdbc.update("update validation_jobs set pending = pending - 1, " + col + " = " + col + " + 1, "
                        + "message = null, updated_at = ? where id = ?", now, jobId);
            }
        });
    }

    /** True when nothing is left: the job is (now) completed. */
    private boolean finishIfDone(long jobId) {
        return Boolean.TRUE.equals(tx.execute(s -> {
            List<Map<String, Object>> j = jdbc.queryForList("select public_id, name, status, pending, total, valid, "
                    + "bounce, soft_bounce, reject, catch_all, unknown, list_id from validation_jobs where id = ? for update",
                    jobId);
            if (j.isEmpty()) {
                return true;
            }
            Map<String, Object> job = j.getFirst();
            if (((Number) job.get("pending")).intValue() > 0) {
                return false;
            }
            if (!"RUNNING".equals(job.get("status"))) {
                return true;
            }
            jdbc.update("update validation_jobs set status = 'COMPLETED', message = null, finished_at = ?, "
                    + "updated_at = ? where id = ?", Timestamp.from(clock.instant()), Timestamp.from(clock.instant()),
                    jobId);
            Map<String, Object> d = new java.util.LinkedHashMap<>();
            d.put("job", String.valueOf(job.get("public_id")));
            d.put("total", job.get("total"));
            for (Category c : Category.values()) {
                d.put(c.name().toLowerCase(), job.get(BulkJobService.column(c)));
            }
            activity.record(ActivityAction.VALIDATION_JOB_FINISHED, Party.label("MasterDB"),
                    Party.label(String.valueOf(job.get("name"))), d);
            if (job.get("list_id") != null) {
                summaries.refreshLater(((Number) job.get("list_id")).longValue());
            }
            log.info("validation job {} completed", jobId);
            return true;
        }));
    }

    // ---- small helpers -------------------------------------------------------------

    private static void close(Tunnel t) {
        if (t != null) {
            t.close();
        }
    }

    private static void sleep(Run run, long ms) {
        long end = System.currentTimeMillis() + ms;
        while (!run.stop && System.currentTimeMillis() < end) {
            try {
                Thread.sleep(Math.min(200, Math.max(1, end - System.currentTimeMillis())));
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            }
        }
    }

    private static String cut(String v, int max) {
        return v == null ? null : v.length() <= max ? v : v.substring(0, max);
    }
}
