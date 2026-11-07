package ca.nordencapital.masterdb.dashboard;

import ca.nordencapital.masterdb.auth.AuthProperties;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowCallbackHandler;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.sql.Timestamp;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

/**
 * Counts for the dashboard, straight from the database. Only what exists
 * today; contacts and validation get their numbers when those modules exist.
 *
 * Not included on purpose: the last backup. Its status file
 * (/var/backups/masterdb/status.json) lives in a root-only folder on the
 * server, outside the backend container, so the app cannot read it without
 * root. Better no number than a made-up one.
 */
@Service
public class DashboardService {

    /** Every user status, so a status nobody has still shows as 0. */
    private static final String[] STATUSES = {"ACTIVE", "INVITED", "DISABLED"};

    private final JdbcTemplate jdbc;
    private final Clock clock;
    private final Duration idleTimeout;

    public DashboardService(JdbcTemplate jdbc, Clock clock, AuthProperties auth) {
        this.jdbc = jdbc;
        this.clock = clock;
        this.idleTimeout = auth.session().idleTimeout();
    }

    public record Summary(Instant generatedAt, Users users, long openSessions, Activity activity) {
    }

    /** People with an account; the Owner counts as active. */
    public record Users(long total, long active, long invited, long disabled) {
    }

    /** Activity log entries (sign-ins, account changes, exports…). */
    public record Activity(long last24Hours, long last7Days) {
    }

    /** One read-only transaction, so the numbers belong together. */
    @Transactional(readOnly = true)
    public Summary summary() {
        Instant now = clock.instant();

        Map<String, Long> byStatus = new HashMap<>();
        jdbc.query("select status, count(*) from users group by status",
                (RowCallbackHandler) rs -> byStatus.put(rs.getString(1), rs.getLong(2)));
        long total = 0;
        for (String s : STATUSES) {
            total += byStatus.getOrDefault(s, 0L);
        }
        Users users = new Users(total, byStatus.getOrDefault("ACTIVE", 0L), byStatus.getOrDefault("INVITED", 0L),
                byStatus.getOrDefault("DISABLED", 0L));

        // Same rule as SessionService: not revoked, before the absolute end,
        // seen within the idle limit, and the account may still sign in.
        Long open = jdbc.queryForObject("""
                select count(*) from user_sessions s join users u on u.id = s.user_id
                where s.revoked_at is null and s.expires_at > ? and s.last_seen_at > ? and u.status = 'ACTIVE'
                """, Long.class, Timestamp.from(now), Timestamp.from(now.minus(idleTimeout)));

        Instant dayAgo = now.minus(Duration.ofHours(24));
        Instant weekAgo = now.minus(Duration.ofDays(7));
        Activity activity = jdbc.queryForObject("""
                select count(*) filter (where occurred_at >= ?), count(*)
                from activity_log where occurred_at >= ?
                """, (rs, i) -> new Activity(rs.getLong(1), rs.getLong(2)),
                Timestamp.from(dayAgo), Timestamp.from(weekAgo));

        return new Summary(now, users, open == null ? 0 : open, activity);
    }
}
