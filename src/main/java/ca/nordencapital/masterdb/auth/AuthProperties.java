package ca.nordencapital.masterdb.auth;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;
import java.util.Objects;

/**
 * Login and session settings ({@code app.auth.*} in application.yml). Every
 * value has a default there; environment variables override them.
 */
@ConfigurationProperties("app.auth")
public record AuthProperties(Session session, Cookie cookie, Lockout lockout, RateLimit rateLimit,
        TwoFactor twoFactor) {

    public AuthProperties {
        Objects.requireNonNull(session, "app.auth.session");
        Objects.requireNonNull(cookie, "app.auth.cookie");
        Objects.requireNonNull(lockout, "app.auth.lockout");
        Objects.requireNonNull(rateLimit, "app.auth.rate-limit");
        Objects.requireNonNull(twoFactor, "app.auth.two-factor");
    }

    /**
     * @param issuer        name shown in the authenticator app (default MasterDB)
     * @param challengeTtl  time between password and code (default 10 min)
     * @param maxAttempts   wrong codes per challenge before signing in again (default 5)
     */
    public record TwoFactor(String issuer, Duration challengeTtl, int maxAttempts) {
        public TwoFactor {
            if (issuer == null || issuer.isBlank()) {
                throw new IllegalArgumentException("app.auth.two-factor.issuer must be set");
            }
            positive(challengeTtl, "app.auth.two-factor.challenge-ttl");
            if (maxAttempts < 1) {
                throw new IllegalArgumentException("app.auth.two-factor.max-attempts must be at least 1");
            }
        }
    }

    /**
     * @param idleTimeout     unused this long → the session ends (default 12 h)
     * @param absoluteTimeout after this long the session ends however much it is used (default 7 days)
     * @param touchInterval   {@code last_seen_at} is written at most this often per session (default 1 min)
     */
    public record Session(Duration idleTimeout, Duration absoluteTimeout, Duration touchInterval) {
        public Session {
            positive(idleTimeout, "app.auth.session.idle-timeout");
            positive(absoluteTimeout, "app.auth.session.absolute-timeout");
            positive(touchInterval, "app.auth.session.touch-interval");
            if (touchInterval.compareTo(idleTimeout) >= 0) {
                throw new IllegalArgumentException("app.auth.session.touch-interval must be shorter than idle-timeout");
            }
        }
    }

    /** @param secure the cookie's Secure flag: true everywhere except plain-http local development */
    public record Cookie(boolean secure) {
    }

    /** @param maxAttempts wrong passwords in a row before the account is locked (default 5) */
    public record Lockout(int maxAttempts, Duration duration) {
        public Lockout {
            if (maxAttempts < 1) {
                throw new IllegalArgumentException("app.auth.lockout.max-attempts must be at least 1");
            }
            positive(duration, "app.auth.lockout.duration");
        }
    }

    /** Login attempts allowed per client address (default 10 a minute and 50 an hour). */
    public record RateLimit(int perMinute, int perHour) {
        public RateLimit {
            if (perMinute < 1 || perHour < 1) {
                throw new IllegalArgumentException("app.auth.rate-limit values must be at least 1");
            }
        }
    }

    private static void positive(Duration value, String name) {
        if (value == null || value.isNegative() || value.isZero()) {
            throw new IllegalArgumentException(name + " must be a positive duration");
        }
    }
}
