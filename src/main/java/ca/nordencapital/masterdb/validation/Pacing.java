package ca.nordencapital.masterdb.validation;

import ca.nordencapital.masterdb.validation.engine.SmtpProber.Verdict;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

import java.sql.Timestamp;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ThreadLocalRandom;
import java.util.function.BooleanSupplier;

/**
 * Pacing per email provider and server, ported from the old app's
 * {@code ValidationPacer}, with its numbers and cooldowns <b>in the database</b>
 * ({@code validation_providers}, {@code validation_cooldowns}), so a cooldown
 * survives a restart. The short waits between two checks are kept in memory.
 *
 * <ul>
 *   <li>between two checks of one server at one provider: the provider's gap (+ up to 20 % at random);</li>
 *   <li>between two checks at one provider from all servers: its global gap;</li>
 *   <li>between two checks of one server, any provider: 1.5 s;</li>
 *   <li>a "slow down" or "blocked" answer pauses that provider for that server, doubling each time
 *       (at most 5 steps, capped); a normal answer takes one step back.</li>
 * </ul>
 */
@Component
public class Pacing {

    static final long SERVER_GAP_MS = 1500;
    private static final DateTimeFormatter TIME = DateTimeFormatter.ofPattern("HH:mm 'UTC'", Locale.ROOT)
            .withZone(ZoneOffset.UTC);
    private static final Logger log = LoggerFactory.getLogger(Pacing.class);

    private final JdbcTemplate jdbc;
    private final Clock clock;
    private final double scale;
    private final Object lock = new Object();
    /** Next allowed time (System.nanoTime based, in ms) per key. */
    private final Map<String, Long> next = new HashMap<>();
    private volatile List<Provider> providers;
    private volatile long providersLoadedAt;

    public Pacing(JdbcTemplate jdbc, Clock clock, @Value("${app.validation.gap-scale:1.0}") double scale) {
        this.jdbc = jdbc;
        this.clock = clock;
        this.scale = scale;
    }

    public record Provider(String key, String label, List<String> suffixes, int gapMs, int globalGapMs,
            int rateCooldownS, int blockCooldownS, int maxCooldownS) {
    }

    public record Decision(boolean allowed, Instant until, String reason) {
        static final Decision GO = new Decision(true, null, null);
    }

    // ---- providers ---------------------------------------------------------------

    public List<Provider> providers() {
        List<Provider> p = providers;
        if (p == null || System.currentTimeMillis() - providersLoadedAt > 60_000) {
            p = jdbc.query("select * from validation_providers order by sort_order", (rs, n) -> new Provider(
                    rs.getString("key"), rs.getString("label"), splitSuffixes(rs.getString("mx_suffixes")),
                    rs.getInt("gap_ms"), rs.getInt("global_gap_ms"), rs.getInt("rate_cooldown_s"),
                    rs.getInt("block_cooldown_s"), rs.getInt("max_cooldown_s")));
            providers = p;
            providersLoadedAt = System.currentTimeMillis();
        }
        return p;
    }

    /** After an edit: read the numbers again on the next use. */
    public void reload() {
        providers = null;
    }

    /** GOOGLE, MICROSOFT, YAHOO, or OTHER:&lt;mail server&gt; (each other server paced on its own). */
    public String provider(String mxHost) {
        String host = mxHost == null ? "" : mxHost.toLowerCase(Locale.ROOT);
        for (Provider p : providers()) {
            for (String suffix : p.suffixes()) {
                if (host.endsWith(suffix) || host.equals(suffix.substring(1))) {
                    return p.key();
                }
            }
        }
        return "OTHER:" + host;
    }

    public String label(String providerKey) {
        Provider p = rules(providerKey);
        return providerKey.startsWith("OTHER:") ? providerKey.substring(6) : p.label();
    }

    Provider rules(String providerKey) {
        String key = providerKey.startsWith("OTHER:") ? "OTHER" : providerKey;
        return providers().stream().filter(p -> p.key().equals(key)).findFirst()
                .orElseGet(() -> providers().stream().filter(p -> p.key().equals("OTHER")).findFirst()
                        .orElse(new Provider("OTHER", "Other", List.of(), 3000, 1000, 120, 1800, 3600)));
    }

    // ---- cooldowns (database) -----------------------------------------------------

    /** Is this provider cooling down for this server? */
    public Decision check(long serverId, String provider) {
        List<Timestamp> until = jdbc.queryForList("select cooldown_until from validation_cooldowns where "
                + "server_id = ? and provider = ? and cooldown_until > ?", Timestamp.class, serverId, provider,
                Timestamp.from(clock.instant()));
        if (until.isEmpty()) {
            return Decision.GO;
        }
        Instant u = until.getFirst().toInstant();
        return new Decision(false, u, label(provider) + " is paused for this server until " + TIME.format(u)
                + " after a \"slow down\" or \"blocked\" answer, so no check was made. Retry after that.");
    }

    /** Providers paused for this server right now (bulk workers skip their addresses). */
    public List<String> paused(long serverId) {
        return jdbc.queryForList("select provider from validation_cooldowns where server_id = ? and "
                + "cooldown_until > ?", String.class, serverId, Timestamp.from(clock.instant()));
    }

    /** Every pause that is still running, for the pages. */
    public record CooldownView(String serverName, String serverIp, String provider, String label, int failures,
            Instant until, String reason) {
    }

    public List<CooldownView> active() {
        List<CooldownView> out = new ArrayList<>();
        jdbc.query("select c.*, s.name, s.ip from validation_cooldowns c join servers s on s.id = c.server_id "
                + "where c.cooldown_until > ? order by c.cooldown_until desc", rs -> {
                    out.add(new CooldownView(rs.getString("name"), rs.getString("ip"), rs.getString("provider"),
                            label(rs.getString("provider")), rs.getInt("failures"),
                            rs.getTimestamp("cooldown_until").toInstant(), rs.getString("reason")));
                }, Timestamp.from(clock.instant()));
        return out;
    }

    /** Changes one provider's numbers (gaps in ms, pauses in seconds). */
    public Provider update(String key, int gapMs, int globalGapMs, int rateCooldownS, int blockCooldownS,
            int maxCooldownS) {
        int n = jdbc.update("update validation_providers set gap_ms = ?, global_gap_ms = ?, rate_cooldown_s = ?, "
                + "block_cooldown_s = ?, max_cooldown_s = ?, updated_at = ? where key = ?", gapMs, globalGapMs,
                rateCooldownS, blockCooldownS, maxCooldownS, Timestamp.from(clock.instant()), key);
        if (n == 0) {
            throw new ca.nordencapital.masterdb.web.error.NotFoundException("No provider " + key + ".");
        }
        reload();
        return rules(key);
    }

    /** After a check: a pause after "slow down" / "blocked", one step back after a normal answer. */
    public void observe(long serverId, String provider, Verdict v) {
        Instant now = clock.instant();
        if (v.rateLimited() || v.blocked()) {
            Provider p = rules(provider);
            Integer before = jdbc.query("select failures from validation_cooldowns where server_id = ? and "
                    + "provider = ?", rs -> rs.next() ? rs.getInt(1) : 0, serverId, provider);
            int failures = Math.min(5, (before == null ? 0 : before) + 1);
            long base = v.blocked() ? p.blockCooldownS() : p.rateCooldownS();
            long seconds = Math.min(p.maxCooldownS(), base << (failures - 1));
            Instant until = now.plusSeconds(seconds);
            String reason = (v.code() > 0 ? v.code() + " " : "") + (v.reply() == null ? "" : v.reply());
            jdbc.update("insert into validation_cooldowns (server_id, provider, failures, cooldown_until, reason, "
                    + "updated_at) values (?,?,?,?,?,?) on conflict (server_id, provider) do update set "
                    + "failures = excluded.failures, cooldown_until = greatest(validation_cooldowns.cooldown_until, "
                    + "excluded.cooldown_until), reason = excluded.reason, updated_at = excluded.updated_at",
                    serverId, provider, failures, Timestamp.from(until), cut(reason, 500), Timestamp.from(now));
            log.info("validation pacing: {} paused for server {} until {} ({} in a row)", provider, serverId, until,
                    failures);
        } else if (v.code() == 250 || v.code() == 251 || v.category() == Category.BOUNCE
                || v.category() == Category.SOFT_BOUNCE) {
            jdbc.update("update validation_cooldowns set failures = greatest(0, failures - 1), updated_at = ? "
                    + "where server_id = ? and provider = ? and failures > 0", Timestamp.from(now), serverId, provider);
        }
    }

    // ---- gaps (memory) -------------------------------------------------------------

    /**
     * Waits until this server may check at this provider, then books the slot.
     * Returns false if {@code cancelled} became true while waiting.
     */
    public boolean acquire(long serverId, String provider, BooleanSupplier cancelled) {
        Provider p = rules(provider);
        String local = serverId + "/" + provider;
        String global = "*/" + provider;
        String server = serverId + "/*";
        while (true) {
            if (cancelled.getAsBoolean()) {
                return false;
            }
            long now = nowMs();
            long due;
            synchronized (lock) {
                due = Math.max(next.getOrDefault(local, 0L), Math.max(next.getOrDefault(global, 0L),
                        next.getOrDefault(server, 0L)));
                if (due <= now) {
                    long base = scaled(p.gapMs());
                    long jitter = base / 5 > 0 ? ThreadLocalRandom.current().nextLong(base / 5) : 0;
                    next.put(local, now + base + jitter);
                    next.put(global, now + scaled(p.globalGapMs()));
                    next.put(server, now + scaled(SERVER_GAP_MS));
                    if (next.size() > 20_000) {
                        next.entrySet().removeIf(e -> e.getValue() < now);
                    }
                    return true;
                }
            }
            try {
                Thread.sleep(Math.min(500, Math.max(1, due - now)));
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return false;
            }
        }
    }

    /** A single check: wait for the slot (never more than one gap) and book it. */
    public void claim(long serverId, String provider) {
        acquire(serverId, provider, () -> false);
    }

    private long scaled(long ms) {
        return Math.round(ms * scale);
    }

    private static long nowMs() {
        return System.nanoTime() / 1_000_000;
    }

    private static List<String> splitSuffixes(String v) {
        List<String> out = new ArrayList<>();
        for (String s : (v == null ? "" : v).split(",")) {
            String t = s.trim().toLowerCase(Locale.ROOT);
            if (!t.isEmpty()) {
                out.add(t.startsWith(".") ? t : "." + t);
            }
        }
        return out;
    }

    private static String cut(String v, int max) {
        return v == null ? null : v.length() <= max ? v : v.substring(0, max);
    }
}
