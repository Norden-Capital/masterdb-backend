package ca.nordencapital.masterdb.mta;

import ca.nordencapital.masterdb.activity.ActivityAction;
import ca.nordencapital.masterdb.activity.ActivityLog;
import ca.nordencapital.masterdb.activity.ActivityLog.Party;
import ca.nordencapital.masterdb.auth.session.AuthPrincipal;
import ca.nordencapital.masterdb.servers.ServerNotReadyException;
import ca.nordencapital.masterdb.servers.ServerService;
import ca.nordencapital.masterdb.servers.ServerService.Server;
import ca.nordencapital.masterdb.servers.ServerSsh;
import ca.nordencapital.masterdb.servers.ssh.SshFailure;
import ca.nordencapital.masterdb.servers.ssh.SshRunner.Result;
import ca.nordencapital.masterdb.web.error.BadRequestException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

import java.sql.Timestamp;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * MTA list and manager (job 5), ported from the old app's MtaControl: the
 * state of postfix, dovecot and opendkim, start / stop / restart / reset per
 * service or all, plus recent logs and the mail queue (size, list, flush).
 * Every command is a fixed script with checked arguments, run as root on a
 * server that has an MTA. Changes are activity-logged.
 */
@Service
public class MtaControlService {

    public static final List<String> SERVICES = List.of("postfix", "dovecot", "opendkim");
    static final Map<String, String> VERBS = Map.of("start", "start", "stop", "stop", "restart", "restart",
            "reset", "reset-failed");
    static final List<String> STATES = List.of("active", "inactive", "failed", "activating", "deactivating",
            "reloading", "unknown");
    /** Logs: one service's units, or every mail log line (syslog facility "mail"). */
    static final Map<String, String> LOG_SOURCES = Map.of(
            "postfix", "-u 'postfix*'",
            "dovecot", "-u 'dovecot*'",
            "opendkim", "-u 'opendkim*'",
            "mail", "SYSLOG_FACILITY=2");
    static final String STATUS_SCRIPT = """
            echo MASTERDB_MTA_STATUS
            for s in postfix dovecot opendkim; do printf 'SERVICE %s %s\\n' "$s" "$(systemctl is-active "$s" 2>/dev/null || true)"; done
            printf 'VERSION postfix %s\\n' "$(postconf -h mail_version 2>/dev/null || echo unknown)"
            printf 'VERSION dovecot %s\\n' "$(dovecot --version 2>/dev/null | head -n1 || echo unknown)"
            printf 'VERSION opendkim %s\\n' "$(opendkim -V 2>/dev/null | head -n1 | sed 's/^.*v\\([0-9][0-9.]*\\).*$/\\1/' || echo unknown)"
            printf 'QUEUE %s\\n' "$(postqueue -j 2>/dev/null | wc -l || echo -1)"
            """;
    private static final JsonMapper JSON = JsonMapper.builder().build();
    private static final Logger log = LoggerFactory.getLogger(MtaControlService.class);

    private final JdbcTemplate jdbc;
    private final ServerService servers;
    private final ServerSsh ssh;
    private final ActivityLog activity;
    private final Clock clock;
    private final TransactionTemplate tx;

    public MtaControlService(JdbcTemplate jdbc, ServerService servers, ServerSsh ssh, ActivityLog activity,
            Clock clock, PlatformTransactionManager transactions) {
        this.jdbc = jdbc;
        this.servers = servers;
        this.ssh = ssh;
        this.activity = activity;
        this.clock = clock;
        this.tx = new TransactionTemplate(transactions);
    }

    public record ServiceState(String name, String state) {
    }

    public record Status(List<ServiceState> services, Map<String, String> versions, Integer queue) {
    }

    /** One row of the MTA list: the server, its MTA and the last status read. */
    public record MtaItem(UUID serverId, String name, String ip, String domain, String heloHost, Instant installedAt,
            boolean webmail, Status status, Instant checkedAt, String message, String connectionStatus) {
    }

    public record LogView(String source, int lines, String text, Instant readAt) {
    }

    public record QueueEntry(String queueId, String queue, Instant arrivedAt, long size, String sender,
            int recipients, String reason) {
    }

    public record QueueView(int count, List<QueueEntry> entries, Instant readAt) {
    }

    // ---- list ------------------------------------------------------------------

    public List<MtaItem> list() {
        return jdbc.query("select public_id from servers where mta_installed_at is not null order by lower(name)",
                (rs, n) -> rs.getObject(1, UUID.class)).stream().map(this::item).toList();
    }

    public MtaItem item(UUID serverId) {
        Server s = servers.find(serverId);
        Map<String, Object> row = jdbc.queryForMap("select mta_installed_at, mta_domain, mta_webmail, "
                + "mta_status::text as status, mta_checked_at, mta_status_message from servers where id = ?", s.id());
        if (row.get("mta_installed_at") == null) {
            throw new ServerNotReadyException("This server has no MTA installed by MasterDB (Install MTA).");
        }
        Status status = row.get("status") == null ? null : JSON.readValue((String) row.get("status"), Status.class);
        return new MtaItem(s.item().publicId(), s.item().name(), s.item().ip(), (String) row.get("mta_domain"),
                s.item().heloHost(), ((Timestamp) row.get("mta_installed_at")).toInstant(),
                Boolean.TRUE.equals(row.get("mta_webmail")), status, row.get("mta_checked_at") == null ? null
                : ((Timestamp) row.get("mta_checked_at")).toInstant(), (String) row.get("mta_status_message"),
                s.item().connectionStatus().name());
    }

    /** Reads the services, versions and queue size over SSH and keeps them for the list. */
    public MtaItem refresh(UUID serverId) {
        Server s = mtaServer(serverId);
        Timestamp now = Timestamp.from(clock.instant());
        Result r;
        try {
            r = ssh.runScript(s, STATUS_SCRIPT, Duration.ofSeconds(40), null);
        } catch (SshFailure f) {
            tx.executeWithoutResult(t -> jdbc.update("update servers set mta_checked_at = ?, mta_status_message = ? "
                    + "where id = ?", now, cut(f.getMessage(), 500), s.id()));
            throw f;
        }
        Status status = parseStatus(r.output());
        String message = status == null ? "The status couldn't be read (exit " + r.exitCode() + ")." : null;
        tx.executeWithoutResult(t -> jdbc.update("update servers set mta_status = coalesce(?::jsonb, mta_status), "
                        + "mta_checked_at = ?, mta_status_message = ? where id = ?",
                status == null ? null : JSON.writeValueAsString(status), now, message, s.id()));
        return item(serverId);
    }

    static Status parseStatus(String output) {
        if (output == null || !output.contains("MASTERDB_MTA_STATUS")) {
            return null;
        }
        Map<String, String> states = new LinkedHashMap<>();
        Map<String, String> versions = new LinkedHashMap<>();
        Integer queue = null;
        for (String line : output.split("\\R")) {
            String[] p = line.trim().split("\\s+", 3);
            if (p.length >= 2 && p[0].equals("SERVICE") && SERVICES.contains(p[1])) {
                String st = p.length == 3 ? p[2].trim() : "unknown";
                states.put(p[1], STATES.contains(st) ? st : "unknown");
            } else if (p.length == 3 && p[0].equals("VERSION") && SERVICES.contains(p[1])) {
                versions.put(p[1], cut(p[2].trim(), 60));
            } else if (p.length == 2 && p[0].equals("QUEUE")) {
                try {
                    int q = Integer.parseInt(p[1]);
                    queue = q < 0 ? null : q;
                } catch (NumberFormatException ignored) {
                    queue = null;
                }
            }
        }
        List<ServiceState> services = new ArrayList<>();
        for (String name : SERVICES) {
            services.add(new ServiceState(name, states.getOrDefault(name, "unknown")));
        }
        return new Status(services, versions, queue);
    }

    // ---- actions ---------------------------------------------------------------

    /** start / stop / restart / reset (reset-failed) of one service or all, then the new status. */
    public MtaItem serviceAction(AuthPrincipal caller, UUID serverId, String service, String action) {
        String verb = VERBS.get(action);
        if (verb == null || !(SERVICES.contains(service) || service.equals("all"))) {
            throw new BadRequestException("Choose a service (postfix, dovecot, opendkim or all) and an action "
                    + "(start, stop, restart, reset).");
        }
        Server s = mtaServer(serverId);
        String names = service.equals("all") ? "opendkim postfix dovecot" : service;
        Result r = ssh.runScript(s, "systemctl " + verb + " " + names + "\n", Duration.ofSeconds(60), null);
        boolean ok = r.exitCode() == 0;
        Map<String, Object> details = new LinkedHashMap<>();
        details.put("service", service);
        details.put("action", action);
        details.put("ok", ok);
        tx.executeWithoutResult(t -> activity.record(ActivityAction.MTA_SERVICE_ACTION, Party.of(caller),
                ServerService.party(s), details));
        log.info("mta {} {} on server {} by {}: exit {}", action, service, s.item().publicId(), caller.userPublicId(),
                r.exitCode());
        if (!ok) {
            throw new SshFailure(SshFailure.Kind.PROTOCOL, "systemctl " + verb + " " + names + " failed (exit "
                    + r.exitCode() + "): " + cut(new LogScrubber(List.of()).line(r.output().strip()), 300));
        }
        return refresh(serverId);
    }

    public LogView logs(UUID serverId, String source, int lines) {
        String selector = LOG_SOURCES.get(source);
        if (selector == null) {
            throw BadRequestException.validation("source", "must be postfix, dovecot, opendkim or mail");
        }
        int n = Math.max(10, Math.min(500, lines));
        Server s = mtaServer(serverId);
        Result r = ssh.runScript(s, "journalctl --no-pager -o short-iso -n " + n + " " + selector + "\n",
                Duration.ofSeconds(40), null);
        LogScrubber scrubber = new LogScrubber(List.of());
        StringBuilder out = new StringBuilder();
        for (String line : r.output().split("\\R")) {
            String clean = scrubber.line(line);
            if (clean != null) {
                out.append(clean).append('\n');
            }
        }
        return new LogView(source, n, out.toString(), clock.instant());
    }

    public QueueView queue(UUID serverId) {
        Server s = mtaServer(serverId);
        Result r = ssh.runScript(s, "postqueue -j\n", Duration.ofSeconds(40), null);
        if (r.exitCode() != 0) {
            throw new SshFailure(SshFailure.Kind.PROTOCOL, "postqueue -j failed (exit " + r.exitCode() + ").");
        }
        return parseQueue(r.output(), clock.instant());
    }

    /** postqueue -j: one JSON object per queued message. The first 100 are listed; the count is all of them. */
    static QueueView parseQueue(String output, Instant readAt) {
        List<QueueEntry> entries = new ArrayList<>();
        int count = 0;
        for (String line : output.split("\\R")) {
            if (!line.trim().startsWith("{")) {
                continue;
            }
            count++;
            if (entries.size() >= 100) {
                continue;
            }
            try {
                JsonNode m = JSON.readTree(line);
                JsonNode recipients = m.path("recipients");
                String reason = recipients.size() > 0 ? recipients.get(0).path("delay_reason").asString(null) : null;
                entries.add(new QueueEntry(m.path("queue_id").asString(""), m.path("queue_name").asString(""),
                        m.path("arrival_time").isNumber() ? Instant.ofEpochSecond(m.path("arrival_time").asLong()) : null,
                        m.path("message_size").asLong(0), m.path("sender").asString(""), recipients.size(),
                        cut(reason, 300)));
            } catch (RuntimeException e) {
                // A line that isn't JSON: counted, not listed.
            }
        }
        return new QueueView(count, entries, readAt);
    }

    /** postqueue -f: try every deferred message now. */
    public QueueView flush(AuthPrincipal caller, UUID serverId) {
        Server s = mtaServer(serverId);
        Result r = ssh.runScript(s, "postqueue -f\n", Duration.ofSeconds(40), null);
        tx.executeWithoutResult(t -> activity.record(ActivityAction.MTA_QUEUE_FLUSHED, Party.of(caller),
                ServerService.party(s), Map.of("ok", r.exitCode() == 0)));
        if (r.exitCode() != 0) {
            throw new SshFailure(SshFailure.Kind.PROTOCOL, "postqueue -f failed (exit " + r.exitCode() + ").");
        }
        return queue(serverId);
    }

    /** Forgets the MTA in MasterDB (MTA list); nothing changes on the server. */
    public void forget(AuthPrincipal caller, UUID serverId) {
        Server s = servers.find(serverId);
        busyCheck(s);
        tx.executeWithoutResult(t -> {
            int rows = jdbc.update("update servers set mta_installed_at = null, mta_domain = null, mta_webmail = null, "
                    + "mta_status = null, mta_checked_at = null, mta_status_message = null where id = ? and "
                    + "mta_installed_at is not null", s.id());
            if (rows == 0) {
                throw new ServerNotReadyException("This server has no MTA in MasterDB.");
            }
            activity.record(ActivityAction.MTA_REMOVED, Party.of(caller), ServerService.party(s), Map.of());
        });
    }

    private Server mtaServer(UUID serverId) {
        Server s = servers.find(serverId);
        Timestamp installed = jdbc.queryForObject("select mta_installed_at from servers where id = ?",
                Timestamp.class, s.id());
        if (installed == null) {
            throw new ServerNotReadyException("This server has no MTA installed by MasterDB (Install MTA).");
        }
        busyCheck(s);
        return s;
    }

    private void busyCheck(Server s) {
        Integer running = jdbc.queryForObject("select count(*) from mta_installs where server_id = ? and status in "
                + "('QUEUED', 'RUNNING')", Integer.class, s.id());
        if (running != null && running > 0) {
            throw new MtaBusyException("An MTA install is running on this server. Wait for it to finish.");
        }
    }

    private static String cut(String v, int max) {
        return v == null || v.length() <= max ? v : v.substring(0, max);
    }
}
