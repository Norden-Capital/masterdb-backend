package ca.nordencapital.masterdb.auth.login;

import ca.nordencapital.masterdb.web.error.ApiException;
import ca.nordencapital.masterdb.web.error.ErrorCode;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;

/**
 * 429 {@code ACCOUNT_LOCKED} with {@code Retry-After} (seconds) and
 * {@code retryAfterSeconds} / {@code lockedUntil} in the body.
 *
 * <p>429 rather than 423: 423 Locked is WebDAV's "this resource is locked for
 * editing", while 429 is the status clients and proxies already understand as
 * "slow down, come back after Retry-After". The code tells it apart from the
 * per-address {@code RATE_LIMITED}. It is sent whatever the password was, so it
 * never says whether the password was right.
 */
public class AccountLockedException extends ApiException {

    private final long retryAfterSeconds;
    private final Instant lockedUntil;

    public AccountLockedException(Instant lockedUntil, Instant now) {
        super(HttpStatus.TOO_MANY_REQUESTS, ErrorCode.ACCOUNT_LOCKED, message(lockedUntil, now), null);
        this.lockedUntil = lockedUntil;
        this.retryAfterSeconds = seconds(lockedUntil, now);
    }

    @Override
    public HttpHeaders getHeaders() {
        HttpHeaders headers = new HttpHeaders();
        headers.set(HttpHeaders.RETRY_AFTER, Long.toString(retryAfterSeconds));
        return headers;
    }

    @Override
    public Map<String, Object> getProperties() {
        return Map.of("retryAfterSeconds", retryAfterSeconds, "lockedUntil", lockedUntil);
    }

    private static long seconds(Instant until, Instant now) {
        long millis = Duration.between(now, until).toMillis();
        return Math.max(1, (millis + 999) / 1000);
    }

    private static String message(Instant until, Instant now) {
        long minutes = Math.max(1, (seconds(until, now) + 59) / 60);
        return "Too many failed sign-in attempts. Try again in " + minutes + (minutes == 1 ? " minute." : " minutes.");
    }
}
