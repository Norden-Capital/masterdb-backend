package ca.nordencapital.masterdb.auth.session;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.Instant;
import java.util.Optional;

public interface UserSessionRepository extends JpaRepository<UserSession, Long> {

    /** The session and its user in one query (runs on every authenticated request). */
    @Query("select s from UserSession s join fetch s.user where s.tokenHash = :tokenHash")
    Optional<UserSession> findByTokenHashWithUser(@Param("tokenHash") String tokenHash);

    /** Moves last_seen_at forward; never backwards, never on a revoked row. */
    @Modifying
    @Query("update UserSession s set s.lastSeenAt = :now "
            + "where s.id = :id and s.revokedAt is null and s.lastSeenAt < :now")
    int touch(@Param("id") Long id, @Param("now") Instant now);

    @Modifying
    @Query("update UserSession s set s.revokedAt = :now where s.id = :id and s.revokedAt is null")
    int revoke(@Param("id") Long id, @Param("now") Instant now);
}
