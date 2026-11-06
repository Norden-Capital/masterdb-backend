package ca.nordencapital.masterdb.auth.twofactor;

import ca.nordencapital.masterdb.auth.user.User;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
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
import lombok.Setter;

import java.time.Instant;

/** "Password right, code still needed". Schema: V3__two_factor.sql. */
@Entity
@Table(name = "login_challenges")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class LoginChallenge {

    public enum Purpose { VERIFY, SETUP }

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "user_id", nullable = false, updatable = false)
    private User user;

    @Column(name = "token_hash", nullable = false, unique = true, updatable = false, length = 64)
    private String tokenHash;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 10, updatable = false)
    private Purpose purpose;

    @Setter
    @Column(name = "pending_secret_enc", length = 200)
    private String pendingSecretEnc;

    @Column(nullable = false)
    private int attempts;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @Column(name = "expires_at", nullable = false, updatable = false)
    private Instant expiresAt;

    @Column(name = "used_at")
    private Instant usedAt;

    @Column(length = 45, updatable = false)
    private String ip;

    @Column(name = "user_agent", length = 255, updatable = false)
    private String userAgent;

    static LoginChallenge start(User user, String tokenHash, Purpose purpose, Instant now, Instant expiresAt,
            String ip, String userAgent) {
        LoginChallenge c = new LoginChallenge();
        c.user = user;
        c.tokenHash = tokenHash;
        c.purpose = purpose;
        c.createdAt = now;
        c.expiresAt = expiresAt;
        c.ip = ip;
        c.userAgent = userAgent;
        return c;
    }

    boolean isUsable(Instant now, int maxAttempts) {
        return usedAt == null && now.isBefore(expiresAt) && attempts < maxAttempts;
    }

    /** Counts a wrong code. Returns true when that was the last allowed attempt. */
    boolean recordFailure(int maxAttempts) {
        attempts++;
        return attempts >= maxAttempts;
    }

    void consume(Instant now) {
        if (usedAt == null) {
            usedAt = now;
        }
    }

    @Override
    public String toString() {
        return "LoginChallenge[" + id + "]";
    }
}
