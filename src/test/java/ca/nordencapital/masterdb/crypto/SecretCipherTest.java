package ca.nordencapital.masterdb.crypto;

import org.junit.jupiter.api.Test;
import org.springframework.boot.env.YamlPropertySourceLoader;
import org.springframework.core.env.PropertySource;
import org.springframework.core.io.ClassPathResource;

import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class SecretCipherTest {

    /** Test value only. */
    static final String KEY = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

    @Test
    void roundTripsAndBindsToTheContext() {
        SecretCipher cipher = new SecretCipher(KEY, true);
        byte[] secret = "authenticator-secret".getBytes(StandardCharsets.UTF_8);
        String stored = cipher.encrypt(secret, "totp:1");

        assertThat(stored).startsWith("v1:").doesNotContain("authenticator");
        assertThat(cipher.encrypt(secret, "totp:1")).isNotEqualTo(stored); // fresh IV each time
        assertThat(cipher.decrypt(stored, "totp:1")).isEqualTo(secret);
        // Copied to another user's row: does not decrypt.
        assertThatThrownBy(() -> cipher.decrypt(stored, "totp:2")).isInstanceOf(IllegalStateException.class);
        // Another key: does not decrypt.
        SecretCipher other = new SecretCipher(KEY.replace('0', '1'), true);
        assertThatThrownBy(() -> other.decrypt(stored, "totp:1")).isInstanceOf(IllegalStateException.class);
    }

    @Test
    void keyedHashDependsOnTheKey() {
        SecretCipher cipher = new SecretCipher(KEY, true);
        assertThat(cipher.keyedHash("abcde12345")).hasSize(64).isEqualTo(cipher.keyedHash("abcde12345"));
        assertThat(new SecretCipher(KEY.replace('0', '1'), true).keyedHash("abcde12345"))
                .isNotEqualTo(cipher.keyedHash("abcde12345"));
    }

    @Test
    void failsClosedWithoutAValidKeyAndNeverEchoesIt() {
        assertThatThrownBy(() -> new SecretCipher("", true)).hasMessageContaining("ENCRYPTION_KEY is not set");
        assertThatThrownBy(() -> new SecretCipher("not-a-hex-key-but-secret-looking", true))
                .hasMessageContaining("64 hex characters").message().doesNotContain("secret-looking");
        assertThatThrownBy(() -> new SecretCipher(KEY.substring(2), true)).hasMessageContaining("64 hex");
        // Only when not required: a random key for this run.
        assertThat(new SecretCipher("", false).encrypt(new byte[] {1}, "x")).startsWith("v1:");
    }

    @Test
    void productionRequiresTheKey() throws Exception {
        YamlPropertySourceLoader yaml = new YamlPropertySourceLoader();
        PropertySource<?> main = yaml.load("main", new ClassPathResource("application.yml")).getFirst();
        PropertySource<?> local = yaml.load("local", new ClassPathResource("application-local.yml")).getFirst();
        assertThat(main.getProperty("app.encryption.required")).hasToString("true");
        assertThat(main.getProperty("app.encryption.key")).hasToString("${ENCRYPTION_KEY:}");
        assertThat(local.getProperty("app.encryption.required")).hasToString("false");
    }
}
