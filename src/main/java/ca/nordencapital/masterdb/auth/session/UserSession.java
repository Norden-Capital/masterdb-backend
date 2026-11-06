package ca.nordencapital.masterdb.auth.session;

import ca.nordencapital.masterdb.auth.user.User;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/**
 * One sign-in. Schema: V2__user_sessions.sql.
 *
 * <p>Holds the SHA-256 of the cookie's token, never the token. No Lombok
 * {@code @ToString}: {@link #toString()} shows the public id only.
 */
@Entity
@Table(name = "user_sessions")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class UserSession {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "public_id", nullable = false, unique = true, updatable = false)
    private UUID publicId;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "user_id", nullable = false, updatable = false)
    private User user;

    @Column(name = "token_hash", nullable = false, unique = true, updatable = false, length = 64)
    private String tokenHash;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @Column(name = "last_seen_at", nullable = false)
    private Instant lastSeenAt;

    @Column(name = "expires_at", nullable = false, updatable = false)
    private Instant expiresAt;

    @Column(name = "revoked_at")
    private Instant revokedAt;

    @Column(length = 45, updatable = false)
    private String ip;

    @Column(name = "user_agent", length = 255, updatable = false)
    private String userAgent;

    static UserSession start(User user, String tokenHash, Instant now, Duration lifetime, String ip,
            String userAgent) {
        UserSession session = new UserSession();
        session.publicId = UUID.randomUUID();
        session.user = Objects.requireNonNull(user, "user");
        session.tokenHash = Objects.requireNonNull(tokenHash, "tokenHash");
        session.createdAt = now;
        session.lastSeenAt = now;
        session.expiresAt = now.plus(lifetime);
        session.ip = ip;
        session.userAgent = userAgent;
        return session;
    }

    /** Usable at {@code now}: not revoked, not past its absolute end, not idle too long. */
    boolean isUsable(Instant now, Duration idleTimeout) {
        return revokedAt == null && now.isBefore(expiresAt) && now.isBefore(lastSeenAt.plus(idleTimeout));
    }

    void revoke(Instant now) {
        if (revokedAt == null) {
            revokedAt = now;
        }
    }

    @Override
    public String toString() {
        return "UserSession[" + publicId + "]";
    }
}
