package ca.nordencapital.masterdb.auth.login;

import ca.nordencapital.masterdb.auth.twofactor.Totp;
import ca.nordencapital.masterdb.auth.user.User;
import ca.nordencapital.masterdb.auth.user.UserRepository;
import ca.nordencapital.masterdb.crypto.SecretCipher;
import ca.nordencapital.testsupport.MutableClock;

import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.HexFormat;

import static org.assertj.core.api.Assertions.assertThat;

/** Enrols test users with a known authenticator secret and signs them in through both steps. */
final class TwoFactorFixture {

    /** Test-only authenticator secret. */
    static final byte[] SECRET = HexFormat.of().parseHex("00112233445566778899aabbccddeeff00112233");

    private final UserRepository users;
    private final SecretCipher cipher;
    private final MutableClock clock;
    private final AuthTestClient client;

    TwoFactorFixture(UserRepository users, SecretCipher cipher, MutableClock clock, AuthTestClient client) {
        this.users = users;
        this.cipher = cipher;
        this.clock = clock;
        this.client = client;
    }

    void enrol(String email) {
        User user = users.findByEmail(email).orElseThrow();
        user.enableTwoFactor(cipher.encrypt(SECRET, "totp:" + user.getId()), clock.instant(),
                Totp.step(clock.instant()) - 10);
        users.save(user);
    }

    /**
     * A code that has not been used yet: the earliest step within the drift
     * window after the last used one; moves the clock 30 s when all three are used.
     */
    String nextCode(String email) {
        long last = users.findByEmail(email).orElseThrow().getTotpLastUsedStep();
        long current = Totp.step(clock.instant());
        long step = Math.max(current - 1, last + 1);
        if (step > current + 1) {
            clock.advance(Duration.ofSeconds(Totp.PERIOD_SECONDS));
            return nextCode(email);
        }
        return Totp.code(SECRET, step);
    }

    /** Password + code; returns the session token. */
    String signIn(String email, String password, String... headers) throws Exception {
        HttpResponse<String> first = client.login(email, password, headers);
        assertThat(first.statusCode()).as(first.body()).isEqualTo(200);
        assertThat(first.body()).contains("\"state\":\"TWO_FACTOR_REQUIRED\"");
        HttpResponse<String> second = client.code("/api/v1/auth/login/2fa", AuthTestClient.preauth(first),
                nextCode(email), headers);
        assertThat(second.statusCode()).as(second.body()).isEqualTo(200);
        return AuthTestClient.token(second);
    }
}
