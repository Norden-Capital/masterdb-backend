package ca.nordencapital.masterdb.auth.session;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

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

    /** Not revoked and before the absolute end; the idle limit is checked by the caller. */
    @Query("select s from UserSession s where s.user.id = :userId and s.revokedAt is null and s.expiresAt > :now "
            + "order by s.lastSeenAt desc")
    List<UserSession> findOpen(@Param("userId") Long userId, @Param("now") Instant now);

    @Query("select s from UserSession s where s.user.id = :userId and s.publicId = :publicId")
    Optional<UserSession> findByUserAndPublicId(@Param("userId") Long userId, @Param("publicId") UUID publicId);

    @Modifying
    @Query("update UserSession s set s.revokedAt = :now where s.user.id = :userId and s.revokedAt is null")
    int revokeAllForUser(@Param("userId") Long userId, @Param("now") Instant now);

    @Modifying
    @Query("update UserSession s set s.revokedAt = :now where s.user.id = :userId and s.id <> :keep "
            + "and s.revokedAt is null")
    int revokeAllExcept(@Param("userId") Long userId, @Param("keep") Long keep, @Param("now") Instant now);
}
