package ca.nordencapital.masterdb.auth.twofactor;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

/** RFC 6238 appendix B test vectors (SHA1 secret "12345678901234567890"), last 6 digits. */
class TotpTest {

    static final byte[] RFC_SECRET = "12345678901234567890".getBytes(StandardCharsets.US_ASCII);

    @Test
    void matchesTheRfcVectors() {
        assertThat(Totp.code(RFC_SECRET, Totp.step(Instant.ofEpochSecond(59)))).isEqualTo("287082");
        assertThat(Totp.code(RFC_SECRET, Totp.step(Instant.ofEpochSecond(1111111109)))).isEqualTo("081804");
        assertThat(Totp.code(RFC_SECRET, Totp.step(Instant.ofEpochSecond(1234567890)))).isEqualTo("005924");
        assertThat(Totp.code(RFC_SECRET, Totp.step(Instant.ofEpochSecond(2000000000)))).isEqualTo("279037");
    }

    @Test
    void base32MatchesTheRfcEncoding() {
        assertThat(Totp.base32(RFC_SECRET)).isEqualTo("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
    }

    @Test
    void acceptsOneStepOfDriftEitherWayAndNothingMore() {
        Instant now = Instant.ofEpochSecond(1_800_000_000L);
        long step = Totp.step(now);
        for (long s = step - 1; s <= step + 1; s++) {
            assertThat(Totp.verify(RFC_SECRET, Totp.code(RFC_SECRET, s), now, Long.MIN_VALUE)).hasValue(s);
        }
        assertThat(Totp.verify(RFC_SECRET, Totp.code(RFC_SECRET, step - 2), now, Long.MIN_VALUE)).isEmpty();
        assertThat(Totp.verify(RFC_SECRET, Totp.code(RFC_SECRET, step + 2), now, Long.MIN_VALUE)).isEmpty();
    }

    @Test
    void neverAcceptsAStepTwice() {
        Instant now = Instant.ofEpochSecond(1_800_000_000L);
        long step = Totp.step(now);
        String code = Totp.code(RFC_SECRET, step);
        assertThat(Totp.verify(RFC_SECRET, code, now, step)).isEmpty();
        assertThat(Totp.verify(RFC_SECRET, Totp.code(RFC_SECRET, step - 1), now, step - 1)).isEmpty();
    }

    @Test
    void refusesMalformedInput() {
        Instant now = Instant.ofEpochSecond(1_800_000_000L);
        for (String bad : new String[] {null, "", "12345", "1234567", "abcdef"}) {
            assertThat(Totp.verify(RFC_SECRET, bad, now, Long.MIN_VALUE)).isEmpty();
        }
    }

    @Test
    void otpauthUriIsWhatAuthenticatorAppsExpect() {
        assertThat(Totp.otpauthUri("MasterDB", "jane+x@example.com", "ABC"))
                .isEqualTo("otpauth://totp/MasterDB:jane%2Bx%40example.com?secret=ABC&issuer=MasterDB"
                        + "&algorithm=SHA1&digits=6&period=30");
    }
}
