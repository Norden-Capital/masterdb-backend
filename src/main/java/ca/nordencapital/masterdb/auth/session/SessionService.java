package ca.nordencapital.masterdb.auth.session;

import ca.nordencapital.masterdb.auth.AuthProperties;
import ca.nordencapital.masterdb.auth.user.User;
import ca.nordencapital.masterdb.auth.user.UserStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

/**
 * Sign-in sessions: start one at login, check one on every request, end one
 * at logout.
 *
 * <p><b>Opaque token, not a JWT.</b> The cookie carries 256 random bits and
 * the database keeps their SHA-256. Every request looks the row up anyway (so
 * that a revoked session stops working at once), and then a JWT would add
 * nothing but a signing key to keep secret and rotate, and claims that can be
 * stale. With an opaque token the row is the single truth: revoke it, disable
 * the user, or let it expire, and the very next request is refused.
 */
@Service
public class SessionService {

    static final int USER_AGENT_MAX = 255;
    static final int IP_MAX = 45;

    private final UserSessionRepository sessions;
    private final AuthProperties.Session settings;
    private final Clock clock;

    public SessionService(UserSessionRepository sessions, AuthProperties properties, Clock clock) {
        this.sessions = sessions;
        this.settings = properties.session();
        this.clock = clock;
    }

    /**
     * A new session for {@code user}. The returned token goes into the cookie
     * and nowhere else: it is not stored, logged or returned again.
     */
    @Transactional
    public IssuedSession start(User user, String ip, String userAgent) {
        String token = SessionTokens.generate();
        UserSession session = sessions.save(UserSession.start(user, SessionTokens.hash(token), clock.instant(),
                settings.absoluteTimeout(), truncate(ip, IP_MAX), truncate(userAgent, USER_AGENT_MAX)));
        return new IssuedSession(token, session.getPublicId(), session.getExpiresAt());
    }

    /**
     * The caller behind a cookie's token, or empty when the token is unknown,
     * revoked, expired, idle too long, or its user can no longer sign in.
     * Moves {@code last_seen_at} forward at most once per touch interval.
     */
    @Transactional
    public Optional<AuthPrincipal> authenticate(String token) {
        if (!SessionTokens.isWellFormed(token)) {
            return Optional.empty();
        }
        Instant now = clock.instant();
        Optional<UserSession> found = sessions.findByTokenHashWithUser(SessionTokens.hash(token));
        if (found.isEmpty()) {
            return Optional.empty();
        }
        UserSession session = found.get();
        User user = session.getUser();
        if (!session.isUsable(now, settings.idleTimeout()) || user.getStatus() != UserStatus.ACTIVE) {
            return Optional.empty();
        }
        if (!now.isBefore(session.getLastSeenAt().plus(settings.touchInterval()))) {
            sessions.touch(session.getId(), now);
        }
        return Optional.of(new AuthPrincipal(user.getId(), user.getPublicId(), user.getEmail(), user.getFullName(),
                user.isOwner(), session.getId(), session.getPublicId()));
    }

    /** Ends one session. Ending an ended session changes nothing. */
    @Transactional
    public void revoke(Long sessionId) {
        sessions.revoke(sessionId, clock.instant());
    }

    /** How long the cookie should live: the session's absolute limit. */
    public Duration cookieMaxAge() {
        return settings.absoluteTimeout();
    }

    private static String truncate(String value, int max) {
        if (value == null || value.isBlank()) {
            return null;
        }
        String trimmed = value.strip();
        return trimmed.length() <= max ? trimmed : trimmed.substring(0, max);
    }

    /** A freshly started session. {@link #toString()} never shows the token. */
    public record IssuedSession(String token, UUID publicId, Instant expiresAt) {
        @Override
        public String toString() {
            return "IssuedSession[" + publicId + "]";
        }
    }
}
