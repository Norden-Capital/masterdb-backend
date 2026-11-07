package ca.nordencapital.masterdb.validation;

import ca.nordencapital.masterdb.auth.session.AuthPrincipal;
import ca.nordencapital.masterdb.servers.ServerService.Server;
import ca.nordencapital.masterdb.servers.ServerSsh;
import ca.nordencapital.masterdb.servers.ssh.SshRunner.Tunnel;
import ca.nordencapital.masterdb.validation.engine.EmailAddress;
import ca.nordencapital.masterdb.validation.engine.SmtpProber;
import ca.nordencapital.masterdb.validation.engine.SmtpProber.Verdict;
import ca.nordencapital.masterdb.web.error.BadRequestException;
import ca.nordencapital.masterdb.web.paging.PageResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.sql.Timestamp;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;

/**
 * Validation, job 1: check one address through a chosen server, now, and keep
 * the result in the history (90 days). Used to test the system.
 */
@Service
public class SingleCheckService {

    static final Map<String, String> SORT_COLUMNS = Map.of("createdAt", "c.created_at", "email", "lower(c.email)",
            "category", "c.category", "serverName", "lower(c.server_name)");
    private static final Duration SSH_TIMEOUT = Duration.ofSeconds(20);
    private static final Logger log = LoggerFactory.getLogger(SingleCheckService.class);

    private final JdbcTemplate jdbc;
    private final ValidationServers servers;
    private final ServerSsh ssh;
    private final SmtpProber prober;
    private final Pacing pacing;
    private final Clock clock;
    private final Duration retention;

    public SingleCheckService(JdbcTemplate jdbc, ValidationServers servers, ServerSsh ssh, SmtpProber prober,
            Pacing pacing, Clock clock, @Value("${app.validation.check-retention:90d}") Duration retention) {
        this.jdbc = jdbc;
        this.servers = servers;
        this.ssh = ssh;
        this.prober = prober;
        this.pacing = pacing;
        this.clock = clock;
        this.retention = retention;
    }

    public record CheckView(UUID publicId, String email, UUID serverId, String serverName, String serverIp,
            String heloHost, String mailFrom, Category category, int smtpCode, String mxHost, String reason,
            String reply, List<String> transcript, int durationMs, String checkedBy, Instant createdAt) {
    }

    public record Filter(String q, Category category) {
    }

    private static final RowMapper<CheckView> ROW = (rs, n) -> new CheckView(rs.getObject("public_id", UUID.class),
            rs.getString("email"), rs.getObject("server_public_id", UUID.class), rs.getString("server_name"),
            rs.getString("server_ip"), rs.getString("helo_host"), rs.getString("mail_from"),
            Category.valueOf(rs.getString("category")), rs.getInt("smtp_code"), rs.getString("mx_host"),
            rs.getString("reason"), rs.getString("reply"), lines(rs.getString("transcript")),
            rs.getInt("duration_ms"), rs.getString("actor_label"), rs.getTimestamp("created_at").toInstant());

    private static final String SELECT = "select c.*, s.public_id as server_public_id from validation_checks c "
            + "left join servers s on s.id = c.server_id";

    public CheckView check(AuthPrincipal caller, String rawEmail, UUID serverId) {
        if (serverId == null) {
            throw BadRequestException.validation("serverId", "is required");
        }
        EmailAddress email = EmailAddress.parse(rawEmail).orElseThrow(() ->
                BadRequestException.validation("email", "is not a valid email address"));
        Server s = servers.ready(serverId);
        Instant started = clock.instant();
        long t0 = System.nanoTime();
        Verdict v;
        String mxHost = prober.destinations(email).primary(email.domain());
        String provider = pacing.provider(mxHost);
        Pacing.Decision wait = pacing.check(s.id(), provider);
        if (!wait.allowed()) {
            v = new Verdict(Category.UNKNOWN, 0, mxHost, wait.reason(), "", List.of(), false, false);
        } else {
            try (Tunnel tunnel = ssh.tunnel(s, SSH_TIMEOUT)) {
                pacing.claim(s.id(), provider);
                v = prober.verify(tunnel, ValidationServers.identity(s), email);
            }
            pacing.observe(s.id(), provider, v);
        }
        int ms = (int) Math.min(Integer.MAX_VALUE, (System.nanoTime() - t0) / 1_000_000);
        UUID id = UUID.randomUUID();
        var i = s.item();
        jdbc.update("insert into validation_checks (public_id, email, domain, server_id, server_name, server_ip, "
                        + "helo_host, mail_from, category, smtp_code, mx_host, reason, reply, transcript, duration_ms, "
                        + "actor_public_id, actor_label, created_at) values (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                id, email.address(), email.domain(), s.id(), i.name(), i.ip(), i.heloHost(), i.mailFrom(),
                v.category().name(), v.code(), cut(v.mx(), 253), cut(v.reason(), 500), cut(v.reply(), 500),
                String.join("\n", v.transcript()), ms, caller.userPublicId(), cut(caller.email(), 254),
                Timestamp.from(started));
        log.info("single check through server {}: {} ({} ms)", i.publicId(), v.category(), ms);
        return get(id);
    }

    public CheckView get(UUID publicId) {
        List<CheckView> found = jdbc.query(SELECT + " where c.public_id = ?", ROW, publicId);
        if (found.isEmpty()) {
            throw new ca.nordencapital.masterdb.web.error.NotFoundException("This check is not in the history.");
        }
        return found.getFirst();
    }

    public PageResponse<CheckView> history(Filter f, Pageable pageable) {
        List<Object> args = new ArrayList<>();
        List<String> parts = new ArrayList<>();
        if (f.q() != null && !f.q().isBlank()) {
            parts.add("lower(c.email) like ? escape '\\'");
            args.add("%" + f.q().trim().toLowerCase(Locale.ROOT).replace("\\", "\\\\").replace("%", "\\%")
                    .replace("_", "\\_") + "%");
        }
        if (f.category() != null) {
            parts.add("c.category = ?");
            args.add(f.category().name());
        }
        String where = parts.isEmpty() ? "" : " where " + String.join(" and ", parts);
        Long total = jdbc.queryForObject("select count(*) from validation_checks c" + where, Long.class,
                args.toArray());
        StringBuilder order = new StringBuilder(" order by ");
        for (Sort.Order o : pageable.getSort()) {
            order.append(SORT_COLUMNS.get(o.getProperty())).append(o.isAscending() ? " asc" : " desc").append(", ");
        }
        order.append("c.id desc");
        args.add(pageable.getPageSize());
        args.add(pageable.getOffset());
        String sql = SELECT + where + order + " limit ? offset ?";
        List<CheckView> items = jdbc.query(sql, ROW, args.toArray());
        long count = total == null ? 0 : total;
        int pages = (int) ((count + pageable.getPageSize() - 1) / pageable.getPageSize());
        return new PageResponse<>(items, pageable.getPageNumber(), pageable.getPageSize(), count, pages);
    }

    /** Daily at 03:50 UTC: checks older than the retention go. */
    @Scheduled(cron = "${app.validation.check-prune-cron:0 50 3 * * *}", zone = "UTC")
    public int prune() {
        int n = jdbc.update("delete from validation_checks where created_at < ?",
                Timestamp.from(clock.instant().minus(retention)));
        if (n > 0) {
            log.info("validation history pruned: {} checks", n);
        }
        return n;
    }

    private static List<String> lines(String v) {
        return v == null || v.isEmpty() ? List.of() : Arrays.asList(v.split("\n"));
    }

    private static String cut(String v, int max) {
        return v == null ? "" : v.length() <= max ? v : v.substring(0, max);
    }
}
