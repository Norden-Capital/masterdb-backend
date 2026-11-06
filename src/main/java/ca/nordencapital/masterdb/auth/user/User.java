package ca.nordencapital.masterdb.auth.user;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.PrePersist;
import jakarta.persistence.PreUpdate;
import jakarta.persistence.Table;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/**
 * One row per person who can (or will be able to) sign in. Schema: V1__users.sql.
 *
 * <p>Deliberately no Lombok {@code @Data}/{@code @ToString}: a generated
 * {@code toString()} would print the password hash into any log line that
 * mentions a user. {@link #toString()} below shows the public id only.
 *
 * <p>Only {@link #publicId} ever leaves the server; {@link #id} is for joins.
 */
@Entity
@Table(name = "users")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "public_id", nullable = false, unique = true, updatable = false)
    private UUID publicId;

    /** Always stored normalised ({@link Emails#normalize}). */
    @Column(nullable = false, length = Emails.MAX_LENGTH)
    private String email;

    @Setter
    @Column(name = "full_name", nullable = false, length = 200)
    private String fullName;

    /** "{bcrypt}..." from the PasswordEncoder, never the password. Null while invited. */
    @Setter
    @Column(name = "password_hash")
    private String passwordHash;

    @Setter
    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    private UserStatus status = UserStatus.INVITED;

    /** Set only by the bootstrap; nothing in the API grants or removes it. */
    @Column(name = "is_owner", nullable = false)
    private boolean owner;

    @Setter
    @Column(name = "failed_login_attempts", nullable = false)
    private int failedLoginAttempts;

    @Setter
    @Column(name = "locked_until")
    private Instant lockedUntil;

    @Setter
    @Column(name = "last_login_at")
    private Instant lastLoginAt;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;

    /** The first account: active, with a password, and the Owner. */
    public static User newOwner(String email, String fullName, String passwordHash) {
        User user = new User();
        user.setEmail(email);
        user.fullName = Objects.requireNonNull(fullName, "fullName");
        user.passwordHash = Objects.requireNonNull(passwordHash, "passwordHash");
        user.status = UserStatus.ACTIVE;
        user.owner = true;
        return user;
    }

    /** Someone invited by the Owner; no password until they accept. */
    public static User newInvited(String email, String fullName) {
        User user = new User();
        user.setEmail(email);
        user.fullName = Objects.requireNonNull(fullName, "fullName");
        return user;
    }

    public void setEmail(String email) {
        this.email = Objects.requireNonNull(Emails.normalize(email), "email");
    }

    @PrePersist
    void onCreate() {
        if (publicId == null) {
            publicId = UUID.randomUUID();
        }
        Instant now = Instant.now();
        if (createdAt == null) {
            createdAt = now;
        }
        updatedAt = now;
    }

    @PreUpdate
    void onUpdate() {
        updatedAt = Instant.now();
    }

    @Override
    public String toString() {
        return "User[" + publicId + "]";
    }
}
