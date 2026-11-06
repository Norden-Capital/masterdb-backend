package ca.nordencapital.masterdb.auth.token;

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

import java.time.Instant;

/** A one-time emailed link (invite, password reset). Schema: V5__account_tokens.sql. */
@Entity
@Table(name = "account_tokens")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class AccountToken {

    public enum Purpose { INVITE, PASSWORD_RESET }

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "user_id", nullable = false, updatable = false)
    private User user;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20, updatable = false)
    private Purpose purpose;

    @Column(name = "token_hash", nullable = false, unique = true, updatable = false, length = 64)
    private String tokenHash;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @Column(name = "expires_at", nullable = false, updatable = false)
    private Instant expiresAt;

    @Column(name = "used_at")
    private Instant usedAt;

    @Column(name = "revoked_at")
    private Instant revokedAt;

    @Column(name = "created_by", updatable = false)
    private Long createdBy;

    static AccountToken issue(User user, Purpose purpose, String tokenHash, Instant now, Instant expiresAt,
            Long createdBy) {
        AccountToken t = new AccountToken();
        t.user = user;
        t.purpose = purpose;
        t.tokenHash = tokenHash;
        t.createdAt = now;
        t.expiresAt = expiresAt;
        t.createdBy = createdBy;
        return t;
    }

    public boolean isUsable(Instant now) {
        return usedAt == null && revokedAt == null && now.isBefore(expiresAt);
    }

    void use(Instant now) {
        usedAt = now;
    }

    @Override
    public String toString() {
        return "AccountToken[" + id + ", " + purpose + "]";
    }
}
