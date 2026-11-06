package ca.nordencapital.masterdb.auth.user;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;
import java.util.UUID;

public interface UserRepository extends JpaRepository<User, Long> {

    /** Any case and surrounding spaces; matches the lower(email) unique index, so it uses it. */
    @Query("select u from User u where lower(u.email) = lower(trim(:email))")
    Optional<User> findByEmail(@Param("email") String email);

    Optional<User> findByPublicId(UUID publicId);

    boolean existsByOwnerTrue();
}
