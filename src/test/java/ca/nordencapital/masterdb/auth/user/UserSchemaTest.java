package ca.nordencapital.masterdb.auth.user;

import ca.nordencapital.testsupport.TestDatabase;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import java.time.Instant;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * V1__users.sql against a real PostgreSQL 16, with Hibernate validating the
 * entity against it at startup (ddl-auto: validate; the context would not
 * start otherwise). The rules that matter are the database's own.
 */
@SpringBootTest
class UserSchemaTest {

    @DynamicPropertySource
    static void database(DynamicPropertyRegistry registry) {
        TestDatabase.register(registry);
    }

    @Autowired
    UserRepository users;

    @Autowired
    JdbcTemplate jdbc;

    /** The database is shared by every test class: leave it empty. */
    @AfterEach
    void cleanUp() {
        jdbc.update("delete from users");
    }

    @Test
    void migrationAppliedAndEntityRoundTrips() {
        assertThat(jdbc.queryForObject(
                "select count(*) from flyway_schema_history where version = '1' and success", Integer.class))
                .isEqualTo(1);

        Instant before = Instant.now().minusSeconds(1);
        User saved = users.saveAndFlush(User.newOwner("  Jane.Doe@Example.COM ", "Jane Doe", "{bcrypt}x"));

        User loaded = users.findByPublicId(saved.getPublicId()).orElseThrow();
        assertThat(loaded.getId()).isNotNull();
        assertThat(loaded.getPublicId()).isNotNull();
        assertThat(loaded.getEmail()).isEqualTo("jane.doe@example.com");
        assertThat(loaded.getFullName()).isEqualTo("Jane Doe");
        assertThat(loaded.getStatus()).isEqualTo(UserStatus.ACTIVE);
        assertThat(loaded.isOwner()).isTrue();
        assertThat(loaded.getFailedLoginAttempts()).isZero();
        assertThat(loaded.getLockedUntil()).isNull();
        assertThat(loaded.getLastLoginAt()).isNull();
        assertThat(loaded.getCreatedAt()).isAfter(before);
        assertThat(loaded.getUpdatedAt()).isAfterOrEqualTo(loaded.getCreatedAt());
        // toString never carries the hash or the email.
        assertThat(loaded.toString()).doesNotContain("bcrypt", "jane");
    }

    @Test
    void findByEmailIgnoresCaseAndSpaces() {
        users.saveAndFlush(User.newInvited("ann@example.com", "Ann"));
        assertThat(users.findByEmail(" ANN@Example.com ")).isPresent();
        assertThat(users.findByEmail("bob@example.com")).isEmpty();
    }

    @Test
    void emailIsUniqueWhateverTheCase() {
        users.saveAndFlush(User.newInvited("ann@example.com", "Ann"));

        // Through the application: normalised, so it collides.
        assertThatThrownBy(() -> users.saveAndFlush(User.newInvited("ANN@example.com", "Ann 2")))
                .isInstanceOf(DataIntegrityViolationException.class);

        // Even a row written by hand in another case is refused by lower(email).
        assertThatThrownBy(() -> jdbc.update(
                "insert into users (email, full_name) values ('Ann@Example.COM', 'Hand-made')"))
                .isInstanceOf(DataIntegrityViolationException.class)
                .hasMessageContaining("uq_users_email_lower");
    }

    @Test
    void secondOwnerIsRefusedByTheDatabase() {
        users.saveAndFlush(User.newOwner("one@example.com", "One", "{bcrypt}x"));

        assertThatThrownBy(() -> users.saveAndFlush(User.newOwner("two@example.com", "Two", "{bcrypt}y")))
                .isInstanceOf(DataIntegrityViolationException.class);
        assertThatThrownBy(() -> jdbc.update("insert into users (email, full_name, password_hash, status, is_owner) "
                + "values ('three@example.com', 'Three', 'h', 'ACTIVE', true)"))
                .isInstanceOf(DataIntegrityViolationException.class)
                .hasMessageContaining("uq_users_single_owner");
        assertThat(users.existsByOwnerTrue()).isTrue();
        assertThat(users.count()).isEqualTo(1);
    }

    @Test
    void checkConstraintsHold() {
        // Unknown status.
        assertThatThrownBy(() -> jdbc.update(
                "insert into users (email, full_name, status) values ('a@example.com', 'A', 'ADMIN')"))
                .hasMessageContaining("chk_users_status");
        // Active without a password.
        assertThatThrownBy(() -> jdbc.update(
                "insert into users (email, full_name, status) values ('b@example.com', 'B', 'ACTIVE')"))
                .hasMessageContaining("chk_users_active_has_password");
        // A disabled Owner.
        assertThatThrownBy(() -> jdbc.update("insert into users (email, full_name, password_hash, status, is_owner) "
                + "values ('c@example.com', 'C', 'h', 'DISABLED', true)"))
                .hasMessageContaining("chk_users_owner_active");

        // Invited without a password is fine, and gets a public id by default.
        jdbc.update("insert into users (email, full_name) values ('d@example.com', 'D')");
        UUID publicId = jdbc.queryForObject("select public_id from users where email = 'd@example.com'", UUID.class);
        assertThat(publicId).isNotNull();
        assertThat(users.findByPublicId(publicId).orElseThrow().getStatus()).isEqualTo(UserStatus.INVITED);
    }

    @Test
    void updatedAtMovesOnChange() throws Exception {
        User user = users.saveAndFlush(User.newInvited("e@example.com", "E"));
        Instant created = user.getUpdatedAt();
        Thread.sleep(5);
        user.setFullName("E2");
        User changed = users.saveAndFlush(user);
        assertThat(changed.getUpdatedAt()).isAfter(created);
        assertThat(changed.getCreatedAt()).isEqualTo(user.getCreatedAt());
    }
}
