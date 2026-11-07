package ca.nordencapital.masterdb.mta;

import ca.nordencapital.masterdb.activity.ActivityAction;
import ca.nordencapital.masterdb.activity.ActivityLog;
import ca.nordencapital.masterdb.activity.ActivityLog.Party;
import ca.nordencapital.masterdb.auth.permission.Action;
import ca.nordencapital.masterdb.auth.permission.ForbiddenException;
import ca.nordencapital.masterdb.auth.permission.Module;
import ca.nordencapital.masterdb.auth.session.AuthPrincipal;
import ca.nordencapital.masterdb.dns.records.DnsRecordService;
import ca.nordencapital.masterdb.mta.MtaPlan.Step;
import ca.nordencapital.masterdb.servers.ServerNotReadyException;
import ca.nordencapital.masterdb.servers.ServerService;
import ca.nordencapital.masterdb.servers.ServerService.ConnectionStatus;
import ca.nordencapital.masterdb.servers.ServerService.Server;
import ca.nordencapital.masterdb.servers.ServerSsh;
import ca.nordencapital.masterdb.servers.ssh.SshFailure;
import ca.nordencapital.masterdb.servers.ssh.SshRunner.Result;
import ca.nordencapital.masterdb.web.error.BadRequestException;
import ca.nordencapital.masterdb.web.error.FieldViolation;
import ca.nordencapital.masterdb.web.error.NotFoundException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.DisposableBean;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import java.sql.Timestamp;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

/**
 * Installs the MTA on a server as a background job stored in the database.
 * The page only starts it and then polls; closing the page changes nothing.
 * Progress is real: steps done of total, plus the scrubbed command output.
 * A backend restart marks running jobs INTERRUPTED; running the install again
 * repeats every step, which is safe. The DKIM key is made on the server and
 * only its public key comes back; it is saved in the domain's DNS settings,
 * and writing the DNS records stays the DNS module's preview → confirm flow.
 */
@Service
public class MtaInstallService implements DisposableBean {

    static final int MAX_LOG = 256 * 1024;
    static final Set<String> SUPPORTED = Set.of("ubuntu:22.04", "ubuntu:24.04", "almalinux:8", "almalinux:9",
            "almalinux:10");
    private static final Logger log = LoggerFactory.getLogger(MtaInstallService.class);

    private final JdbcTemplate jdbc;
    private final ServerService servers;
    private final ServerSsh ssh;
    private final DnsRecordService dnsRecords;
    private final ActivityLog activity;
    private final Clock clock;
    private final TransactionTemplate tx;
    private final ExecutorService workers = Executors.newFixedThreadPool(2, r -> {
        Thread t = new Thread(r, "mta-install");
        t.setDaemon(true);
        return t;
    });
    /** Webmail passwords, in memory only while their job runs (never stored). */
    private final Map<Long, String> passwords = new ConcurrentHashMap<>();

    public MtaInstallService(JdbcTemplate jdbc, ServerService servers, ServerSsh ssh, DnsRecordService dnsRecords,
            ActivityLog activity, Clock clock, PlatformTransactionManager transactions) {
        this.jdbc = jdbc;
        this.servers = servers;
        this.ssh = ssh;
        this.dnsRecords = dnsRecords;
        this.activity = activity;
        this.clock = clock;
        this.tx = new TransactionTemplate(transactions);
    }

    public enum Status { QUEUED, RUNNING, SUCCEEDED, FAILED, INTERRUPTED }

    public record StepView(String key, String label, String state) {
    }

    public record InstallView(UUID publicId, UUID serverId, String serverName, String domain, String heloHost,
            boolean webmail, String webmailLogin, Status status, int stepsDone, int stepsTotal, String currentStep,
            String error, List<StepView> steps, String log, int logLength, int logFrom, String dkimSelector,
            String dkimPublicKey, UUID domainId, String startedBy, Instant createdAt, Instant startedAt,
            Instant finishedAt) {
    }

    public record StartRequest(UUID serverId, boolean webmail, String webmailLogin, String webmailPassword) {
    }

    /** A server as the Install MTA page sees it: can it get an MTA now, and if not, why. */
    public record Candidate(UUID publicId, String name, String ip, String os, String domain, String heloHost,
            boolean ready, String reason, Instant mtaInstalledAt, UUID lastInstallId, Status lastInstallStatus) {
    }

    private record Job(long id, UUID publicId, long serverId, Long domainId, String domain, String heloHost,
            boolean webmail, String webmailLogin, Status status, int stepsDone, int stepsTotal, String currentStep,
            String error, String log, String dkimSelector, String dkimKey, String actorLabel, Instant createdAt,
            Instant startedAt, Instant finishedAt) {
    }

    private static final RowMapper<Job> JOB = (rs, n) -> new Job(rs.getLong("id"), rs.getObject("public_id",
            UUID.class), rs.getLong("server_id"), (Long) rs.getObject("domain_id"), rs.getString("domain_name"),
            rs.getString("helo_host"), rs.getBoolean("webmail"), rs.getString("webmail_login"),
            Status.valueOf(rs.getString("status")), rs.getInt("steps_done"), rs.getInt("steps_total"),
            rs.getString("current_step"), rs.getString("error"), rs.getString("log"), rs.getString("dkim_selector"),
            rs.getString("dkim_public_key"), rs.getString("actor_label"), ts(rs.getTimestamp("created_at")),
            ts(rs.getTimestamp("started_at")), ts(rs.getTimestamp("finished_at")));

    // ---- start -----------------------------------------------------------------

    public InstallView start(AuthPrincipal caller, StartRequest req) {
        if (req.serverId() == null) {
            throw BadRequestException.validation("serverId", "is required");
        }
        Server s = servers.find(req.serverId());
        // A server that already has an MTA: running the install again is an edit.
        Timestamp installed = jdbc.queryForObject("select mta_installed_at from servers where id = ?",
                Timestamp.class, s.id());
        if (installed != null && !caller.can(Module.MTA, Action.EDIT)) {
            throw new ForbiddenException("This server already has an MTA: running the install again needs the "
                    + "MTA edit permission.");
        }
        String why = notReady(s);
        if (why != null) {
            throw new ServerNotReadyException(why);
        }
        String login = req.webmail() ? blankToNull(req.webmailLogin()) : null;
        String password = req.webmail() ? req.webmailPassword() : null;
        if (req.webmail()) {
            List<FieldViolation> errors = new ArrayList<>();
            if (login == null || !MtaPlan.LOGIN.matcher(login).matches()
                    || List.of("root", "postfix", "opendkim", "dovecot").contains(login)) {
                errors.add(new FieldViolation("webmailLogin", "must start with a letter: a-z, 0-9, . _ - (up to 32), "
                        + "not root or a service user"));
            }
            if (password == null || password.length() < 12 || password.length() > 200
                    || password.chars().anyMatch(c -> c < 32 || c == 127)) {
                errors.add(new FieldViolation("webmailPassword", "must be 12 to 200 characters, no control "
                        + "characters"));
            }
            if (!errors.isEmpty()) {
                throw BadRequestException.validation(errors);
            }
        }
        List<Step> steps = MtaPlan.steps(new MtaPlan.Input(s.item().domain().name(), s.item().heloHost(),
                req.webmail(), login, password));
        Timestamp now = Timestamp.from(clock.instant());
        UUID id = UUID.randomUUID();
        Long domainId = s.domainId();
        try {
            tx.executeWithoutResult(t -> {
                jdbc.update("insert into mta_installs (public_id, server_id, domain_id, domain_name, helo_host, webmail, "
                                + "webmail_login, status, steps_total, dkim_selector, actor_public_id, actor_label, "
                                + "created_at, updated_at) values (?, ?, ?, ?, ?, ?, ?, 'QUEUED', ?, ?, ?, ?, ?, ?)",
                        id, s.id(), domainId, s.item().domain().name(), s.item().heloHost(), req.webmail(), login,
                        steps.size(), MtaPlan.SELECTOR, caller.userPublicId(), caller.email(), now, now);
                Map<String, Object> details = new LinkedHashMap<>();
                details.put("install", id.toString());
                details.put("domain", s.item().domain().name());
                details.put("webmail", req.webmail());
                activity.record(ActivityAction.MTA_INSTALL_STARTED, Party.of(caller), ServerService.party(s), details);
            });
        } catch (DuplicateKeyException e) {
            throw new MtaBusyException("An MTA install is already running on this server. Wait for it to finish.");
        }
        Job job = job(id);
        if (password != null) {
            passwords.put(job.id(), password);
        }
        workers.submit(() -> run(job.id()));
        log.info("mta install {} queued on server {} by {}", id, s.item().publicId(), caller.userPublicId());
        return view(job, 0);
    }

    /** Why this server can't get an MTA now, or null. */
    static String notReady(Server s) {
        if (s.item().connectionStatus() == ConnectionStatus.KEY_CHANGED) {
            return "This server is blocked: its host key changed. The Owner must accept the new key first.";
        }
        if (s.pinnedKey() == null || s.item().connectionStatus() != ConnectionStatus.CONNECTED) {
            return "Connect to this server first (Server list → the server → Connect).";
        }
        if (!Boolean.TRUE.equals(s.item().privileged())) {
            return "The SSH user is not root and has no passwordless sudo: the MTA can't be installed.";
        }
        if (s.item().domain() == null || s.item().heloHost() == null) {
            return "Link a domain to this server first: the MTA's host name and DKIM key are for that domain.";
        }
        String os = (s.osId() == null ? "" : s.osId()) + ":" + major(s.osId(), s.osVersion());
        if (!SUPPORTED.contains(os)) {
            return "Unsupported operating system (" + (s.item().os() == null ? "unknown" : s.item().os())
                    + "). Supported: Ubuntu 22.04 / 24.04, AlmaLinux 8 / 9 / 10.";
        }
        return null;
    }

    private static String major(String id, String version) {
        if (version == null) {
            return "";
        }
        return "almalinux".equals(id) && version.contains(".") ? version.substring(0, version.indexOf('.')) : version;
    }

    // ---- the job -----------------------------------------------------------------

    void run(long jobId) {
        Job job = jdbc.query("select * from mta_installs where id = ?", JOB, jobId).stream().findFirst().orElse(null);
        if (job == null || job.status() != Status.QUEUED) {
            return;
        }
        String password = passwords.remove(jobId);
        LogBuffer out = new LogBuffer(jobId, new LogScrubber(password == null ? List.of() : List.of(password)));
        Server s;
        List<Step> steps;
        try {
            s = servers.find(serverPublicId(job.serverId()));
            steps = MtaPlan.steps(new MtaPlan.Input(job.domain(), job.heloHost(), job.webmail(), job.webmailLogin(),
                    password == null ? "" : password));
        } catch (RuntimeException e) {
            finish(job, Status.FAILED, "The install couldn't start: the server or its domain changed.", out);
            return;
        }
        if (job.webmail() && password == null) {
            finish(job, Status.FAILED, "The webmail password is no longer known (the backend restarted). Start the "
                    + "install again.", out);
            return;
        }
        update(jobId, "update mta_installs set status = 'RUNNING', started_at = ?, updated_at = ? where id = ?",
                Timestamp.from(clock.instant()), Timestamp.from(clock.instant()), jobId);
        String dkim = null;
        int done = 0;
        for (Step step : steps) {
            // Marked INTERRUPTED meanwhile (restart recovery): this worker stops and changes nothing more.
            Integer mine = tx.execute(t -> jdbc.update("update mta_installs set current_step = ?, updated_at = ? "
                    + "where id = ? and status = 'RUNNING'", step.key(), Timestamp.from(clock.instant()), jobId));
            if (mine == null || mine == 0) {
                return;
            }
            out.add("▶ Step " + (done + 1) + " of " + steps.size() + ": " + step.label());
            out.flush();
            try {
                if (step.local()) {
                    if (dkim == null) {
                        throw new IllegalStateException("no DKIM key");
                    }
                    handToDns(job, s, dkim);
                    out.add("DKIM public key saved in the DNS settings of " + job.domain() + " (selector "
                            + MtaPlan.SELECTOR + "). Review and write the records from the install page.");
                } else {
                    Result r = ssh.runScript(s, step.script(), step.timeout(), out::add);
                    if (r.exitCode() != 0) {
                        out.flush();
                        finish(job, Status.FAILED, "Step \"" + step.label() + "\" failed (exit code " + r.exitCode()
                                + "). See the log; fix the cause and run the install again.", out);
                        return;
                    }
                    if (step.key().equals("dkim-read")) {
                        dkim = MtaPlan.dkimPublicKey(r.output());
                        if (dkim == null) {
                            out.flush();
                            finish(job, Status.FAILED, "The DKIM public key couldn't be read from the server.", out);
                            return;
                        }
                        String key = dkim;
                        update(jobId, "update mta_installs set dkim_public_key = ? where id = ?", key, jobId);
                    }
                }
            } catch (SshFailure f) {
                out.add("SSH: " + f.getMessage());
                out.flush();
                finish(job, Status.FAILED, f.getMessage(), out);
                return;
            } catch (RuntimeException e) {
                log.warn("mta install {} step {} failed", job.publicId(), step.key(), e);
                out.flush();
                finish(job, Status.FAILED, "Step \"" + step.label() + "\" failed on MasterDB's side. Run the install "
                        + "again; if it repeats, quote this install's id.", out);
                return;
            }
            done++;
            out.flush();
            update(jobId, "update mta_installs set steps_done = ?, updated_at = ? where id = ?", done,
                    Timestamp.from(clock.instant()), jobId);
        }
        Timestamp now = Timestamp.from(clock.instant());
        tx.executeWithoutResult(t -> jdbc.update("update servers set mta_installed_at = ?, mta_domain = ?, "
                + "mta_webmail = coalesce(mta_webmail, false) or ?, updated_at = ? where id = ?", now, job.domain(),
                job.webmail(), now, job.serverId()));
        out.add("✓ MTA installed.");
        finish(job, Status.SUCCEEDED, null, out);
    }

    private void handToDns(Job job, Server s, String dkim) {
        if (job.domainId() == null) {
            throw new IllegalStateException("domain deleted");
        }
        tx.executeWithoutResult(t -> dnsRecords.dkimFromServer(job.domainId(), MtaPlan.SELECTOR, dkim,
                ServerService.party(s)));
    }

    private void finish(Job job, Status status, String error, LogBuffer out) {
        out.flush();
        Timestamp now = Timestamp.from(clock.instant());
        tx.executeWithoutResult(t -> {
            int rows = jdbc.update("update mta_installs set status = ?, error = ?, current_step = case when ? then null "
                    + "else current_step end, finished_at = ?, updated_at = ? where id = ? and status in ('QUEUED', "
                    + "'RUNNING')", status.name(), cut(error, 1000), status == Status.SUCCEEDED, now, now, job.id());
            if (rows == 0) {
                return;
            }
            Map<String, Object> details = new LinkedHashMap<>();
            details.put("install", job.publicId().toString());
            details.put("status", status.name());
            details.put("domain", job.domain());
            Job after = jdbc.query("select * from mta_installs where id = ?", JOB, job.id()).getFirst();
            details.put("steps", after.stepsDone() + "/" + after.stepsTotal());
            String name = jdbc.queryForList("select name from servers where id = ?", String.class, job.serverId())
                    .stream().findFirst().orElse("server");
            activity.record(ActivityAction.MTA_INSTALL_FINISHED, Party.label(job.actorLabel()),
                    new Party(serverPublicId(job.serverId()), name), details);
        });
        log.info("mta install {} {}", job.publicId(), status);
    }

    /** After a restart nothing is running: jobs that were are marked INTERRUPTED, to be run again. */
    @EventListener(ApplicationReadyEvent.class)
    public int recoverInterrupted() {
        Timestamp now = Timestamp.from(clock.instant());
        int n = jdbc.update("update mta_installs set status = 'INTERRUPTED', error = ?, finished_at = ?, updated_at = ? "
                        + "where status in ('QUEUED', 'RUNNING')", "The backend restarted during the install. Run it "
                        + "again: every step is safe to repeat.", now, now);
        if (n > 0) {
            log.warn("{} MTA install(s) were interrupted by a restart", n);
        }
        return n;
    }

    @Override
    public void destroy() throws InterruptedException {
        workers.shutdownNow();
        workers.awaitTermination(5, TimeUnit.SECONDS);
    }

    // ---- read --------------------------------------------------------------------

    public InstallView get(UUID publicId, int logFrom) {
        return view(job(publicId), logFrom);
    }

    /** Newest first, at most 20, for one server. */
    public List<InstallView> history(UUID serverId) {
        Server s = servers.find(serverId);
        return jdbc.query("select * from mta_installs where server_id = ? order by created_at desc, id desc limit 20",
                JOB, s.id()).stream().map(j -> view(j, Integer.MAX_VALUE)).toList();
    }

    public List<Candidate> candidates() {
        List<Candidate> out = new ArrayList<>();
        for (Server s : servers.all()) {
            Timestamp installed = jdbc.queryForObject("select mta_installed_at from servers where id = ?",
                    Timestamp.class, s.id());
            Job last = jdbc.query("select * from mta_installs where server_id = ? order by created_at desc, id desc "
                    + "limit 1", JOB, s.id()).stream().findFirst().orElse(null);
            String why = notReady(s);
            out.add(new Candidate(s.item().publicId(), s.item().name(), s.item().ip(), s.item().os(),
                    s.item().domain() == null ? null : s.item().domain().name(), s.item().heloHost(), why == null, why,
                    ts(installed), last == null ? null : last.publicId(), last == null ? null : last.status()));
        }
        return out;
    }

    private Job job(UUID publicId) {
        List<Job> found = jdbc.query("select * from mta_installs where public_id = ?", JOB, publicId);
        if (found.isEmpty()) {
            throw new NotFoundException("This MTA install does not exist.");
        }
        return found.getFirst();
    }

    private InstallView view(Job j, int logFrom) {
        List<Step> steps = MtaPlan.steps(new MtaPlan.Input(j.domain(), j.heloHost(), j.webmail(),
                j.webmailLogin() == null ? "user" : j.webmailLogin(), ""));
        List<StepView> views = new ArrayList<>();
        for (int i = 0; i < steps.size(); i++) {
            Step st = steps.get(i);
            String state = i < j.stepsDone() ? "DONE"
                    : st.key().equals(j.currentStep()) ? switch (j.status()) {
                        case RUNNING -> "RUNNING";
                        case FAILED, INTERRUPTED -> "FAILED";
                        default -> "PENDING";
                    } : "PENDING";
            views.add(new StepView(st.key(), st.label(), state));
        }
        String all = j.log();
        int from = Math.max(0, Math.min(logFrom, all.length()));
        UUID serverPublicId = serverPublicId(j.serverId());
        String serverName = jdbc.queryForList("select name from servers where id = ?", String.class, j.serverId())
                .stream().findFirst().orElse(null);
        UUID domainPublicId = j.domainId() == null ? null : jdbc.queryForList("select public_id from domains where "
                + "id = ?", UUID.class, j.domainId()).stream().findFirst().orElse(null);
        return new InstallView(j.publicId(), serverPublicId, serverName, j.domain(), j.heloHost(), j.webmail(),
                j.webmailLogin(), j.status(), j.stepsDone(), j.stepsTotal(), j.currentStep(), j.error(), views,
                all.substring(from), all.length(), from, j.dkimSelector(), j.dkimKey(), domainPublicId, j.actorLabel(),
                j.createdAt(), j.startedAt(), j.finishedAt());
    }

    private UUID serverPublicId(long id) {
        return jdbc.queryForObject("select public_id from servers where id = ?", UUID.class, id);
    }

    private void update(long jobId, String sql, Object... args) {
        tx.executeWithoutResult(t -> jdbc.update(sql, args));
    }

    /**
     * Lines go through the scrubber into memory and are appended to the
     * stored log at each step boundary and at least every second, so the page
     * sees the output while a long step (packages) runs.
     */
    private final class LogBuffer {
        private final long jobId;
        private final LogScrubber scrubber;
        private final StringBuilder pending = new StringBuilder();
        private long lastFlush = System.nanoTime();

        LogBuffer(long jobId, LogScrubber scrubber) {
            this.jobId = jobId;
            this.scrubber = scrubber;
        }

        synchronized void add(String raw) {
            String line = scrubber.line(raw);
            if (line != null) {
                pending.append(line.length() > 2000 ? line.substring(0, 2000) + "…" : line).append('\n');
            }
            if (System.nanoTime() - lastFlush > 1_000_000_000L || pending.length() > 16 * 1024) {
                flush();
            }
        }

        synchronized void flush() {
            lastFlush = System.nanoTime();
            if (pending.isEmpty()) {
                return;
            }
            String chunk = pending.toString();
            pending.setLength(0);
            // Keep the newest MAX_LOG characters.
            tx.executeWithoutResult(t -> jdbc.update("update mta_installs set log = right(log || ?, ?), updated_at = ? "
                    + "where id = ?", chunk, MAX_LOG, Timestamp.from(clock.instant()), jobId));
        }
    }

    private static String blankToNull(String v) {
        return v == null || v.isBlank() ? null : v.trim().toLowerCase(java.util.Locale.ROOT);
    }

    private static String cut(String v, int max) {
        return v == null || v.length() <= max ? v : v.substring(0, max);
    }

    private static Instant ts(Timestamp t) {
        return t == null ? null : t.toInstant();
    }
}
