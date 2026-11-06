package ca.nordencapital.masterdb.auth.permission;

import jakarta.persistence.Column;
import jakarta.persistence.Embeddable;
import jakarta.persistence.EmbeddedId;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Table;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.io.Serializable;
import java.time.Instant;
import java.util.Objects;

/** One grant. Schema: V4__user_permissions.sql. */
@Entity
@Table(name = "user_permissions")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class UserPermission {

    @EmbeddedId
    private Key key;

    @Column(name = "granted_at", nullable = false, updatable = false)
    private Instant grantedAt;

    @Column(name = "granted_by", updatable = false)
    private Long grantedBy;

    UserPermission(Long userId, Permission permission, Instant now, Long grantedBy) {
        this.key = new Key(userId, permission.module(), permission.action());
        this.grantedAt = now;
        this.grantedBy = grantedBy;
    }

    public Permission permission() {
        return new Permission(key.module, key.action);
    }

    @Embeddable
    @Getter
    @NoArgsConstructor(access = AccessLevel.PROTECTED)
    public static class Key implements Serializable {
        @Column(name = "user_id", nullable = false)
        private Long userId;

        @Enumerated(EnumType.STRING)
        @Column(nullable = false, length = 30)
        private Module module;

        @Enumerated(EnumType.STRING)
        @Column(nullable = false, length = 20)
        private Action action;

        Key(Long userId, Module module, Action action) {
            this.userId = userId;
            this.module = module;
            this.action = action;
        }

        @Override
        public boolean equals(Object o) {
            return o instanceof Key k && Objects.equals(userId, k.userId) && module == k.module && action == k.action;
        }

        @Override
        public int hashCode() {
            return Objects.hash(userId, module, action);
        }
    }
}
