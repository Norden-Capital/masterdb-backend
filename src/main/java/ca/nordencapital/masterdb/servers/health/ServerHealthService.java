package ca.nordencapital.masterdb.servers.health;

import ca.nordencapital.masterdb.activity.ActivityAction;
import ca.nordencapital.masterdb.activity.ActivityLog;
import ca.nordencapital.masterdb.activity.ActivityLog.Party;
import ca.nordencapital.masterdb.auth.session.AuthPrincipal;
import ca.nordencapital.masterdb.dns.health.DnsLookup;
import ca.nordencapital.masterdb.dns.health.DnsLookup.LookupFailed;
import ca.nordencapital.masterdb.servers.ServerService;
import ca.nordencapital.masterdb.servers.ServerService.ConnectionStatus;
import ca.nordencapital.masterdb.servers.ServerService.Server;
import ca.nordencapital.masterdb.servers.ServerSsh;
import ca.nordencapital.masterdb.servers.health.Dnsbl.Answer;
import ca.nordencapital.masterdb.servers.health.Dnsbl.Outcome;
import ca.nordencapital.masterdb.servers.ssh.SshFailure;
import ca.nordencapital.masterdb.servers.ssh.SshRunner.Result;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionTemplate;

import java.nio.charset.StandardCharsets;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.stream.Collectors;

/**
 * Server health (job 2): SSH and outbound port 25 are checked ON the server
 * over SSH; reverse DNS and blocklists from the backend; expiry from the
 * date. Results are stored per check; every server is re-checked daily.
 * Remote and DNS work runs outside any transaction.
 */
@Service
public class ServerHealthService {

    /** Big mail providers' MX hosts: an SMTP greeting from one proves port 25 out is open. */
    static final List<String> MX_HOSTS = List.of("gmail-smtp-in.l.google.com", "mta5.am0.yahoodns.net",
            "outlook-com.olc.protection.outlook.com");
    static final String PORT25_SCRIPT = "echo MASTERDB_PORT25_CHECK\n"
            + "for h in " + String.join(" ", MX_HOSTS) + "; do\n"
            + "  if g=$(timeout 10 bash -c \"exec 3<>/dev/tcp/$h/25 && head -c 3 <&3\" 2>/dev/null) "
            + "&& [ \"$g\" = 220 ]; then echo \"MASTERDB_PORT25_OK $h\"; exit 0; fi\n"
            + "  echo \"MASTERDB_PORT25_FAIL $h\"\n"
            + "done\n"
            + "echo MASTERDB_PORT25_BLOCKED\n";
    static final int EXPIRY_WARNING_DAYS = 14;
    private static final List<String> ORDER = List.of("SSH", "PORT25", "PTR", "DNSBL", "EXPIRY");
    private static final Logger log = LoggerFactory.getLogger(ServerHealthService.class);

    private final JdbcTemplate jdbc;
    private final ServerService servers;
    private final ServerSsh ssh;
    private final DnsLookup dns;
    private final DnsblLookup dnsbl;
    private final ActivityLog activity;
    private final Clock clock;
    private final TransactionTemplate tx;
    private final AtomicBoolean dailyRunning = new AtomicBoolean();

    public ServerHealthService(JdbcTemplate jdbc, ServerService servers, ServerSsh ssh, DnsLookup dns,
            DnsblLookup dnsbl, ActivityLog activity, Clock clock, PlatformTransactionManager transactions) {
        this.jdbc = jdbc;
        this.servers = servers;
        this.ssh = ssh;
        this.dns = dns;
        this.dnsbl = dnsbl;
        this.activity = activity;
        this.clock = clock;
        this.tx = new TransactionTemplate(transactions);
    }

    public enum Status { OK, WARNING, PROBLEM, ERROR, NOT_CHECKED }

    public record CheckResult(String check, Status status, String detail, String found) {
    }

    public record Report(UUID serverId, String status, Instant checkedAt, List<CheckResult> checks) {
    }

    @Transactional(readOnly = true)
    public Report report(UUID serverId) {
        Server s = servers.find(serverId);
        List<CheckResult> rows = jdbc.query("select check_name, status, detail, found from server_health_checks "
                + "where server_id = ?", (rs, n) -> new CheckResult(rs.getString(1), Status.valueOf(rs.getString(2)),
                rs.getString(3), rs.getString(4)), s.id());
        rows.sort((a, b) -> Integer.compare(ORDER.indexOf(a.check()), ORDER.indexOf(b.check())));
        String status = jdbc.queryForObject("select health_status from servers where id = ?", String.class, s.id());
        Timestamp at = jdbc.queryForObject("select health_checked_at from servers where id = ?", Timestamp.class,
                s.id());
        return new Report(serverId, status, at == null ? null : at.toInstant(), rows);
    }

    /** "Re-check" on one server. */
    public Report check(AuthPrincipal caller, UUID serverId) {
        Server s = servers.find(serverId);
        Status overall = run(s);
        tx.executeWithoutResult(t -> activity.record(ActivityAction.SERVER_HEALTH_CHECKED, Party.of(caller),
                ServerService.party(s), Map.of("status", overall.name())));
        return report(serverId);
    }

    /** Daily, every server one after the other (UTC, {@code app.servers.health-cron}). */
    @Scheduled(cron = "${app.servers.health-cron:0 30 4 * * *}", zone = "UTC")
    public void checkAllDaily() {
        if (!dailyRunning.compareAndSet(false, true)) {
            return;
        }
        try {
            Map<Status, Integer> counts = new LinkedHashMap<>();
            List<Server> all = servers.all();
            for (Server s : all) {
                Status st;
                try {
                    st = run(s);
                } catch (RuntimeException e) {
                    st = Status.ERROR;
                    log.warn("server health of {} failed: {}", s.item().publicId(), e.getClass().getSimpleName());
                }
                counts.merge(st, 1, Integer::sum);
            }
            Map<String, Object> details = new LinkedHashMap<>();
            details.put("servers", all.size());
            counts.forEach((k, v) -> details.put(k.name().toLowerCase(), v));
            tx.executeWithoutResult(t -> activity.record(ActivityAction.SERVER_HEALTH_CHECKED,
                    Party.label("Daily check"), Party.label("All servers"), details));
            log.info("daily server health: {}", details);
        } finally {
            dailyRunning.set(false);
        }
    }

    /** Runs every check and stores the results; returns the overall status. */
    public Status run(Server s) {
        List<CheckResult> results = new ArrayList<>();
        results.addAll(sshAndPort25(s));
        results.add(ptr(s));
        results.add(blocklists(s));
        results.add(expiry(s));
        Status overall = overall(results);
        Timestamp now = Timestamp.from(clock.instant());
        tx.executeWithoutResult(t -> {
            jdbc.update("delete from server_health_checks where server_id = ?", s.id());
            for (CheckResult r : results) {
                jdbc.update("insert into server_health_checks (server_id, check_name, status, detail, found, "
                                + "checked_at) values (?, ?, ?, ?, ?, ?)", s.id(), r.check(), r.status().name(),
                        cut(r.detail(), 1000), cut(r.found(), 2000), now);
            }
            jdbc.update("update servers set health_status = ?, health_checked_at = ? where id = ?", overall.name(),
                    now, s.id());
        });
        return overall;
    }

    /** PROBLEM, else ERROR (couldn't tell), else WARNING, else OK. NOT_CHECKED doesn't count. */
    static Status overall(List<CheckResult> results) {
        for (Status st : List.of(Status.PROBLEM, Status.ERROR, Status.WARNING)) {
            if (results.stream().anyMatch(r -> r.status() == st)) {
                return st;
            }
        }
        return Status.OK;
    }

    /** One SSH session for both: logging in is the SSH check, the script's answer is the port 25 check. */
    List<CheckResult> sshAndPort25(Server s) {
        if (s.pinnedKey() == null) {
            return List.of(new CheckResult("SSH", Status.PROBLEM, "Not connected yet: press Connect and trust the "
                    + "host key.", null), notChecked("PORT25", "Checked from the server once SSH works."));
        }
        if (s.item().connectionStatus() == ConnectionStatus.KEY_CHANGED) {
            return List.of(new CheckResult("SSH", Status.PROBLEM, "Blocked: the host key changed. The Owner must "
                    + "accept the new key.", null), notChecked("PORT25", "Not checked while the server is blocked."));
        }
        long start = System.nanoTime();
        Result r;
        try {
            r = ssh.run(s, "bash -s", PORT25_SCRIPT.getBytes(StandardCharsets.UTF_8), Duration.ofSeconds(60), null);
        } catch (SshFailure f) {
            return List.of(new CheckResult("SSH", Status.PROBLEM, f.getMessage(), null),
                    notChecked("PORT25", "Checked from the server once SSH works."));
        }
        long ms = Duration.ofNanos(System.nanoTime() - start).toMillis();
        CheckResult sshOk = new CheckResult("SSH", Status.OK, "MasterDB's key logs in as " + s.item().sshUser()
                + " (" + ms + " ms).", null);
        return List.of(sshOk, port25(r));
    }

    static CheckResult port25(Result r) {
        String out = r.output();
        List<String> failed = out.lines().filter(l -> l.startsWith("MASTERDB_PORT25_FAIL "))
                .map(l -> l.substring(21).trim()).toList();
        String ok = out.lines().filter(l -> l.startsWith("MASTERDB_PORT25_OK ")).map(l -> l.substring(19).trim())
                .findFirst().orElse(null);
        if (ok != null) {
            return new CheckResult("PORT25", Status.OK, "Outbound port 25 is open: " + ok + " answered with an SMTP "
                    + "greeting.", ok);
        }
        if (out.contains("MASTERDB_PORT25_BLOCKED")) {
            return new CheckResult("PORT25", Status.PROBLEM, "Outbound port 25 looks blocked: no SMTP greeting from "
                    + String.join(", ", failed) + " within 10 seconds each. Many VPS providers close it until you "
                    + "ask them to open it.", String.join(", ", failed));
        }
        return new CheckResult("PORT25", Status.ERROR, "The check didn't run on the server (exit " + r.exitCode()
                + "): it needs bash and timeout.", null);
    }

    /** Reverse DNS of the IP must be the mail host of the linked domain. */
    CheckResult ptr(Server s) {
        String expected = expectedPtr(s);
        if (expected == null) {
            return notChecked("PTR", "Link a domain to this server to check its reverse DNS.");
        }
        List<String> found;
        try {
            found = dns.ptr(s.item().ip());
        } catch (LookupFailed e) {
            return new CheckResult("PTR", Status.ERROR, e.getMessage() + ". Try again later.", null);
        }
        String list = found.isEmpty() ? null : String.join(", ", found);
        if (found.stream().noneMatch(h -> h.equalsIgnoreCase(expected))) {
            return new CheckResult("PTR", Status.PROBLEM, "Reverse DNS of " + s.item().ip() + " is "
                    + (list == null ? "not set" : list) + ", not " + expected + ". Set it at the VPS provider.", list);
        }
        return new CheckResult("PTR", Status.OK, "Reverse DNS of " + s.item().ip() + " is " + expected + ".", list);
    }

    /** The host the PTR must show: the linked domain's mail host. */
    static String expectedPtr(Server s) {
        return s.item().domain() == null ? null : "mail." + s.item().domain().name();
    }

    CheckResult blocklists(Server s) {
        List<Answer> answers = Dnsbl.check(dnsbl, s.item().ip());
        String found = answers.stream().map(a -> a.zone().label() + ": " + a.text())
                .collect(Collectors.joining("; "));
        List<Answer> listed = answers.stream().filter(a -> a.outcome() == Outcome.LISTED).toList();
        List<Answer> unknown = answers.stream().filter(a -> a.outcome() == Outcome.UNKNOWN).toList();
        if (!listed.isEmpty()) {
            return new CheckResult("DNSBL", Status.PROBLEM, "Listed on " + listed.stream()
                    .map(a -> a.zone().label() + " (" + a.text() + ")").collect(Collectors.joining(", ")) + ".", found);
        }
        if (!unknown.isEmpty()) {
            return new CheckResult("DNSBL", Status.ERROR, "Not listed on " + (answers.size() - unknown.size())
                    + " of " + answers.size() + " lists; couldn't check " + unknown.stream()
                    .map(a -> a.zone().label() + " (" + a.text() + ")").collect(Collectors.joining(", ")) + ".", found);
        }
        return new CheckResult("DNSBL", Status.OK, "Not listed on " + answers.size() + " blocklists ("
                + answers.stream().map(a -> a.zone().label()).collect(Collectors.joining(", ")) + ").", found);
    }

    static CheckResult expiry(Server s) {
        long days = s.item().daysLeft();
        String date = s.item().expiresOn().toString();
        if (days < 0) {
            return new CheckResult("EXPIRY", Status.PROBLEM, "The VPS plan ended on " + date + ".", date);
        }
        if (days <= EXPIRY_WARNING_DAYS) {
            return new CheckResult("EXPIRY", Status.WARNING, days == 0 ? "The VPS plan ends today (" + date + ")."
                    : "The VPS plan ends in " + days + " day" + (days == 1 ? "" : "s") + " (" + date + ").", date);
        }
        return new CheckResult("EXPIRY", Status.OK, "The VPS plan ends on " + date + " (" + days + " days).", date);
    }

    private static CheckResult notChecked(String check, String why) {
        return new CheckResult(check, Status.NOT_CHECKED, why, null);
    }

    private static String cut(String v, int max) {
        return v == null || v.length() <= max ? v : v.substring(0, max);
    }
}
