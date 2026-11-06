package ca.nordencapital.masterdb.activity;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

import java.sql.Timestamp;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.UUID;
import java.util.function.Consumer;

/** Reading, exporting and pruning the activity log. */
@Service
public class ActivityQuery {

    public static final int EXPORT_MAX_ROWS = 100_000;
    private static final Logger log = LoggerFactory.getLogger(ActivityQuery.class);
    private static final JsonMapper JSON = JsonMapper.builder().build();

    private final JdbcTemplate jdbc;
    private final Duration retention;
    private final Clock clock;

    public ActivityQuery(JdbcTemplate jdbc, @Value("${app.activity.retention:365d}") Duration retention,
            Clock clock) {
        this.jdbc = jdbc;
        this.retention = retention;
        this.clock = clock;
    }

    public record Entry(long id, Instant occurredAt, String action, UUID actorPublicId, String actorLabel,
            UUID targetPublicId, String targetLabel, String ip, String userAgent, String requestId,
            JsonNode details) {
    }

    /**
     * @param actions empty = all
     * @param user    entries where this person is the actor or the target
     * @param q       free text in the actor and target labels
     */
    public record Filter(List<ActivityAction> actions, UUID user, String q, Instant from, Instant to) {
    }

    public record Page(List<Entry> items, long total) {
    }

    @Transactional(readOnly = true)
    public Page list(Filter filter, int page, int size, boolean ascending) {
        List<Object> args = new ArrayList<>();
        String where = where(filter, args);
        Long total = jdbc.queryForObject("select count(*) from activity_log" + where, Long.class, args.toArray());
        args.add(size);
        args.add((long) page * size);
        List<Entry> items = jdbc.query("select * from activity_log" + where + " order by occurred_at "
                + (ascending ? "asc" : "desc") + ", id " + (ascending ? "asc" : "desc") + " limit ? offset ?",
                ROW, args.toArray());
        return new Page(items, total == null ? 0 : total);
    }

    /** Streams matching rows, newest first, at most {@link #EXPORT_MAX_ROWS}. Returns the count. */
    @Transactional(readOnly = true)
    public int export(Filter filter, Consumer<Entry> sink) {
        List<Object> args = new ArrayList<>();
        String where = where(filter, args);
        args.add(EXPORT_MAX_ROWS);
        int[] count = {0};
        jdbc.query("select * from activity_log" + where + " order by occurred_at desc, id desc limit ?", rs -> {
            sink.accept(ROW.mapRow(rs, count[0]));
            count[0]++;
        }, args.toArray());
        return count[0];
    }

    /** Deletes entries older than the retention (one year by default). Daily at 03:40 UTC. */
    @Scheduled(cron = "${app.activity.prune-cron:0 40 3 * * *}", zone = "UTC")
    @Transactional
    public int prune() {
        Instant cutoff = clock.instant().minus(retention);
        int deleted = jdbc.update("delete from activity_log where occurred_at < ?", Timestamp.from(cutoff));
        if (deleted > 0) {
            log.info("activity log pruned: {} entries older than {}", deleted, cutoff);
        }
        return deleted;
    }

    private static String where(Filter f, List<Object> args) {
        List<String> parts = new ArrayList<>();
        if (f.actions() != null && !f.actions().isEmpty()) {
            parts.add("action in (" + String.join(",", f.actions().stream().map(a -> "?").toList()) + ")");
            f.actions().forEach(a -> args.add(a.name()));
        }
        if (f.user() != null) {
            parts.add("(actor_public_id = ? or target_public_id = ?)");
            args.add(f.user());
            args.add(f.user());
        }
        if (f.q() != null && !f.q().isBlank()) {
            String like = "%" + f.q().trim().toLowerCase(Locale.ROOT).replace("\\", "\\\\").replace("%", "\\%")
                    .replace("_", "\\_") + "%";
            parts.add("(lower(coalesce(actor_label,'')) like ? or lower(coalesce(target_label,'')) like ?)");
            args.add(like);
            args.add(like);
        }
        if (f.from() != null) {
            parts.add("occurred_at >= ?");
            args.add(Timestamp.from(f.from()));
        }
        if (f.to() != null) {
            parts.add("occurred_at < ?");
            args.add(Timestamp.from(f.to()));
        }
        return parts.isEmpty() ? "" : " where " + String.join(" and ", parts);
    }

    private static final RowMapper<Entry> ROW = (rs, n) -> new Entry(
            rs.getLong("id"),
            rs.getTimestamp("occurred_at").toInstant(),
            rs.getString("action"),
            rs.getObject("actor_public_id", UUID.class),
            rs.getString("actor_label"),
            rs.getObject("target_public_id", UUID.class),
            rs.getString("target_label"),
            rs.getString("ip"),
            rs.getString("user_agent"),
            rs.getString("request_id"),
            JSON.readTree(rs.getString("details")));
}
