package ca.nordencapital.masterdb.auth.password;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.DelegatingPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Map;

/**
 * How passwords are hashed. The only place that decides it.
 *
 * <p><b>BCrypt, cost 12</b> (2^12 rounds, a few hundred ms per hash on the
 * VPS): slow enough that a stolen table is expensive to attack, fast enough
 * for a login. Chosen over Argon2id because Spring's Argon2 encoder needs
 * BouncyCastle as an extra dependency and a per-login memory budget to tune on
 * a server shared with Postgres, for a handful of staff accounts that also
 * have mandatory 2FA. Same choice as the LMS.
 *
 * <p>BCrypt reads only the first 72 bytes of a password, and Spring refuses
 * longer ones with an error; callers check {@link #MAX_BYTES} first.
 *
 * <p><b>Delegating</b>: every stored hash starts with its algorithm's id
 * ({@code {bcrypt}$2a$12$...}). To move to Argon2id later, add it to the map
 * and make it the default: new and changed passwords get the new algorithm,
 * old hashes keep working, and {@link PasswordEncoder#upgradeEncoding} tells
 * the login code when to re-hash one. A hash with an unknown or missing id
 * never matches (it is not an error).
 */
@Configuration
public class PasswordConfig {

    public static final String DEFAULT_ID = "bcrypt";
    public static final int BCRYPT_STRENGTH = 12;
    /** BCrypt's input limit, in UTF-8 bytes. */
    public static final int MAX_BYTES = 72;

    @Bean
    public PasswordEncoder passwordEncoder() {
        DelegatingPasswordEncoder encoder = new DelegatingPasswordEncoder(DEFAULT_ID,
                Map.of(DEFAULT_ID, new BCryptPasswordEncoder(BCRYPT_STRENGTH)));
        encoder.setDefaultPasswordEncoderForMatches(new NeverMatches());
        return encoder;
    }

    /** For hashes without a known {id}: never a match, never an exception at login. */
    private static final class NeverMatches implements PasswordEncoder {
        @Override
        public String encode(CharSequence rawPassword) {
            throw new UnsupportedOperationException("encode is done by the default encoder");
        }

        @Override
        public boolean matches(CharSequence rawPassword, String encodedPassword) {
            return false;
        }
    }
}
