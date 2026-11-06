package ca.nordencapital.masterdb.auth.user;

import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;
import java.util.UUID;

public interface UserRepository extends JpaRepository<User, Long>, JpaSpecificationExecutor<User> {

    /** Any case and surrounding spaces; matches the lower(email) unique index, so it uses it. */
    @Query("select u from User u where lower(u.email) = lower(trim(:email))")
    Optional<User> findByEmail(@Param("email") String email);

    /**
     * Same, with the row locked until the transaction ends (SELECT ... FOR
     * UPDATE). Login uses it so that parallel attempts on one account count
     * their failures one after the other instead of overwriting each other.
     */
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select u from User u where lower(u.email) = lower(trim(:email))")
    Optional<User> findByEmailForUpdate(@Param("email") String email);

    Optional<User> findByPublicId(UUID publicId);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select u from User u where u.publicId = :publicId")
    Optional<User> findByPublicIdForUpdate(@Param("publicId") UUID publicId);

    boolean existsByOwnerTrue();
}
