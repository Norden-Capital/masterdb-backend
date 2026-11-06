package ca.nordencapital.masterdb.auth.token;

import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

public interface AccountTokenRepository extends JpaRepository<AccountToken, Long> {

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select t from AccountToken t join fetch t.user where t.tokenHash = :hash")
    Optional<AccountToken> findForUpdate(@Param("hash") String hash);

    @Query("select t from AccountToken t where t.user.id in :userIds and t.purpose = :purpose "
            + "and t.usedAt is null and t.revokedAt is null")
    List<AccountToken> findOpen(@Param("userIds") List<Long> userIds, @Param("purpose") AccountToken.Purpose purpose);

    @Modifying
    @Query("update AccountToken t set t.revokedAt = :now where t.user.id = :userId and t.purpose = :purpose "
            + "and t.usedAt is null and t.revokedAt is null")
    int revokeOpen(@Param("userId") Long userId, @Param("purpose") AccountToken.Purpose purpose,
            @Param("now") Instant now);
}
