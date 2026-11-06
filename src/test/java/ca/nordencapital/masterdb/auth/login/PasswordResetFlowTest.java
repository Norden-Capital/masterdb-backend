package ca.nordencapital.masterdb.auth.login;

import ca.nordencapital.masterdb.auth.user.User;
import ca.nordencapital.masterdb.auth.user.UserRepository;
import ca.nordencapital.masterdb.auth.user.UserStatus;
import ca.nordencapital.masterdb.crypto.SecretCipher;
import ca.nordencapital.masterdb.web.security.LoginRateLimiter;
import ca.nordencapital.testsupport.CapturingMailSender;
import ca.nordencapital.testsupport.MutableClock;
import ca.nordencapital.testsupport.TestDatabase;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.annotation.Import;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;

import static ca.nordencapital.masterdb.auth.login.AuthTestClient.stable;
import static org.assertj.core.api.Assertions.assertThat;

/** M1.6: forgot / reset password. */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@Import({MutableClock.Config.class, CapturingMailSender.Config.class})
@ExtendWith(OutputCaptureExtension.class)
class PasswordResetFlowTest {

    static final Instant T0 = Instant.parse("2026-11-06T12:00:07Z");
    static final String PASSWORD = "correct-horse-battery-staple";
    static final String NEW_PASSWORD = "a-brand-new-passphrase-77";
    static final String MEMBER = "jane@example.com";
    static final String DISABLED = "gone@example.com";

    private static String hash;

    @DynamicPropertySource
    static void database(DynamicPropertyRegistry registry) {
        TestDatabase.register(registry);
    }

    @LocalServerPort
    int port;
    @Autowired
    UserRepository users;
    @Autowired
    PasswordEncoder encoder;
    @Autowired
    MutableClock clock;
    @Autowired
    LoginRateLimiter limiter;
    @Autowired
    SecretCipher cipher;
    @Autowired
    CapturingMailSender mail;

    AuthTestClient client;
    TwoFactorFixture fixture;

    @BeforeEach
    void setUp() {
        clock.set(T0);
        limiter.clear();
        mail.clear();
        users.deleteAll();
        if (hash == null) {
            hash = encoder.encode(PASSWORD);
        }
        users.save(AuthFlowTest.activeWith(MEMBER, "Jane Member", hash));
        User gone = AuthFlowTest.activeWith(DISABLED, "Gone User", hash);
        gone.setStatus(UserStatus.DISABLED);
        users.save(gone);
        client = new AuthTestClient(port);
        fixture = new TwoFactorFixture(users, cipher, clock, client);
        fixture.enrol(MEMBER);
    }

    @AfterEach
    void tearDown() {
        users.deleteAll();
        limiter.clear();
    }

    @Test
    void theAnswerNeverSaysWhetherTheEmailExists() throws Exception {
        HttpResponse<String> known = forgot(MEMBER);
        HttpResponse<String> unknown = forgot("nobody@example.com");
        HttpResponse<String> disabled = forgot(DISABLED);
        HttpResponse<String> garbage = forgot("not an email");
        for (HttpResponse<String> r : new HttpResponse[] {known, unknown, disabled, garbage}) {
            assertThat(r.statusCode()).isEqualTo(202);
            assertThat(stable(r.body())).isEqualTo(stable(known.body()));
        }
        assertThat(mail.sent()).hasSize(1);
        assertThat(mail.last().to()).isEqualTo(MEMBER);
        assertThat(mail.last().subject()).isEqualTo("Reset your MasterDB password");
        assertThat(mail.last().text()).contains("/reset-password#", "expires in 30 minutes");
    }

    @Test
    void oneEmailAMinuteAndOnlyTheLatestLinkWorks() throws Exception {
        forgot(MEMBER);
        String first = mail.lastToken();
        forgot(MEMBER);
        assertThat(mail.sent()).hasSize(1);

        clock.advance(Duration.ofMinutes(1));
        forgot(MEMBER);
        assertThat(mail.sent()).hasSize(2);
        String second = mail.lastToken();
        assertThat(check(first).statusCode()).isEqualTo(410);
        HttpResponse<String> ok = check(second);
        assertThat(ok.statusCode()).isEqualTo(200);
        assertThat(ok.body()).contains("\"expiresAt\":\"" + clock.instant().plus(Duration.ofMinutes(30)) + "\"");
    }

    @Test
    void theLinkExpiresAfterThirtyMinutes() throws Exception {
        forgot(MEMBER);
        String token = mail.lastToken();
        clock.advance(Duration.ofMinutes(30));
        HttpResponse<String> late = reset(token, NEW_PASSWORD);
        assertThat(late.statusCode()).isEqualTo(410);
        assertThat(late.body()).contains("\"code\":\"LINK_INVALID\"");
    }

    @Test
    void aResetEndsEverySessionLiftsTheLockAndWorksOnce(CapturedOutput output) throws Exception {
        String session = fixture.signIn(MEMBER, PASSWORD);
        for (int i = 0; i < 5; i++) {
            client.login(MEMBER, "wrong-password");
        }
        assertThat(client.login(MEMBER, PASSWORD).body()).contains("ACCOUNT_LOCKED");

        forgot(MEMBER);
        String token = mail.lastToken();
        assertThat(reset(token, "short").statusCode()).isEqualTo(400);

        assertThat(reset(token, NEW_PASSWORD).statusCode()).isEqualTo(204);
        assertThat(client.me(session).statusCode()).isEqualTo(401);
        assertThat(reset(token, "yet-another-passphrase-1").statusCode()).isEqualTo(410);

        clock.advance(Duration.ofMinutes(2)); // fresh rate-limit window
        assertThat(client.login(MEMBER, PASSWORD).body()).contains("INVALID_CREDENTIALS");
        // The new password still needs the 2FA code: a reset never bypasses it.
        assertThat(client.login(MEMBER, NEW_PASSWORD).body()).isEqualTo("{\"state\":\"TWO_FACTOR_REQUIRED\"}");
        assertThat(fixture.signIn(MEMBER, NEW_PASSWORD)).isNotNull();

        assertThat(output.getAll()).doesNotContain(token).contains("password reset: j***@example.com");
    }

    private HttpResponse<String> forgot(String email) throws Exception {
        return client.send("POST", "/api/v1/auth/password/forgot", null, "{\"email\":\"" + email + "\"}");
    }

    private HttpResponse<String> check(String token) throws Exception {
        return client.send("POST", "/api/v1/auth/password/reset/check", null, "{\"token\":\"" + token + "\"}");
    }

    private HttpResponse<String> reset(String token, String password) throws Exception {
        return client.send("POST", "/api/v1/auth/password/reset", null,
                "{\"token\":\"" + token + "\",\"password\":\"" + password + "\"}");
    }
}
