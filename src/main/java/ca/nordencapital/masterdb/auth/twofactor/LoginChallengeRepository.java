package ca.nordencapital.masterdb.auth.twofactor;

import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.Instant;
import java.util.Optional;

public interface LoginChallengeRepository extends JpaRepository<LoginChallenge, Long> {

    /** Locked, so two parallel code attempts on one challenge count one after the other. */
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select c from LoginChallenge c join fetch c.user where c.tokenHash = :tokenHash")
    Optional<LoginChallenge> findForUpdate(@Param("tokenHash") String tokenHash);

    /** Ends every open challenge of a user (2FA reset, password change, disable). */
    @Modifying
    @Query("update LoginChallenge c set c.usedAt = :now where c.user.id = :userId and c.usedAt is null")
    int consumeAllForUser(@Param("userId") Long userId, @Param("now") Instant now);
}
