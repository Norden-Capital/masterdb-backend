package ca.nordencapital.masterdb.web.security;

import ca.nordencapital.masterdb.auth.AuthProperties;
import org.springframework.stereotype.Component;

import java.time.Clock;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.OptionalLong;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * How many login attempts one client address may make: {@code per-minute}
 * (10) and {@code per-hour} (50), in fixed windows, counted whatever the
 * outcome.
 *
 * <p>The account lockout stops guessing one person's password; this stops one
 * address guessing across many accounts. In memory: there is one backend
 * instance, and a restart forgetting the counts is harmless. With several
 * instances this would move to the database or Redis.
 */
@Component
public class LoginRateLimiter {

    private record Rule(Duration window, int limit) {
    }

    private record Window(long startMillis, int count) {
    }

    private static final int CLEANUP_EVERY = 1_000;

    private final List<Rule> rules;
    private final List<Map<String, Window>> windows;
    private final Clock clock;
    private final AtomicInteger sinceCleanup = new AtomicInteger();

    public LoginRateLimiter(AuthProperties properties, Clock clock) {
        AuthProperties.RateLimit limits = properties.rateLimit();
        this.rules = List.of(new Rule(Duration.ofMinutes(1), limits.perMinute()),
                new Rule(Duration.ofHours(1), limits.perHour()));
        this.windows = List.of(new ConcurrentHashMap<>(), new ConcurrentHashMap<>());
        this.clock = clock;
    }

    /**
     * Counts one attempt from {@code address}. Empty when it is allowed;
     * otherwise the seconds until the address may try again.
     */
    public OptionalLong tryAcquire(String address) {
        long now = clock.millis();
        long retryAfterMillis = 0;
        for (int i = 0; i < rules.size(); i++) {
            Rule rule = rules.get(i);
            long length = rule.window().toMillis();
            Window window = windows.get(i).compute(address, (key, current) ->
                    current == null || now - current.startMillis() >= length
                            ? new Window(now, 1)
                            : new Window(current.startMillis(), current.count() + 1));
            if (window.count() > rule.limit()) {
                retryAfterMillis = Math.max(retryAfterMillis, window.startMillis() + length - now);
            }
        }
        cleanupNowAndThen(now);
        return retryAfterMillis > 0 ? OptionalLong.of(Math.max(1, (retryAfterMillis + 999) / 1000))
                : OptionalLong.empty();
    }

    /** Tests only: forget every count. */
    public void clear() {
        windows.forEach(Map::clear);
    }

    /** Ended windows are dropped every so often, so the maps cannot grow without end. */
    private void cleanupNowAndThen(long now) {
        if (sinceCleanup.incrementAndGet() < CLEANUP_EVERY) {
            return;
        }
        sinceCleanup.set(0);
        for (int i = 0; i < rules.size(); i++) {
            long length = rules.get(i).window().toMillis();
            windows.get(i).values().removeIf(w -> now - w.startMillis() >= length);
        }
    }
}
