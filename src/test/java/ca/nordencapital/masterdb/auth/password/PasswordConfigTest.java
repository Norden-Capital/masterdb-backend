package ca.nordencapital.masterdb.auth.password;

import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.password.PasswordEncoder;

import static org.assertj.core.api.Assertions.assertThat;

class PasswordConfigTest {

    /** A test value only. */
    static final String PASSWORD = "correct-horse-battery-staple";

    final PasswordEncoder encoder = new PasswordConfig().passwordEncoder();

    @Test
    void hashesWithBcryptCost12AndAnAlgorithmPrefix() {
        String hash = encoder.encode(PASSWORD);
        assertThat(hash).startsWith("{bcrypt}$2a$12$").doesNotContain(PASSWORD);
        assertThat(encoder.encode(PASSWORD)).as("salted").isNotEqualTo(hash);
    }

    @Test
    void matchesOnlyTheRightPassword() {
        String hash = encoder.encode(PASSWORD);
        assertThat(encoder.matches(PASSWORD, hash)).isTrue();
        assertThat(encoder.matches(PASSWORD + "x", hash)).isFalse();
        assertThat(encoder.matches(PASSWORD.toUpperCase(), hash)).isFalse();
        assertThat(encoder.upgradeEncoding(hash)).isFalse();
    }

    /** A hash with no or an unknown {id} is a failed match, not a crash at login. */
    @Test
    void unknownAlgorithmNeverMatches() {
        String bare = encoder.encode(PASSWORD).substring("{bcrypt}".length());
        assertThat(encoder.matches(PASSWORD, bare)).isFalse();
        assertThat(encoder.matches(PASSWORD, "{md5}" + bare)).isFalse();
    }
}
