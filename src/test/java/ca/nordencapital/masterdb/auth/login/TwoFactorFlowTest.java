package ca.nordencapital.masterdb.auth.login;

import ca.nordencapital.masterdb.auth.twofactor.Totp;
import ca.nordencapital.masterdb.auth.user.User;
import ca.nordencapital.masterdb.auth.user.UserRepository;
import ca.nordencapital.masterdb.crypto.SecretCipher;
import ca.nordencapital.masterdb.web.security.LoginRateLimiter;
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
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static ca.nordencapital.masterdb.auth.login.AuthTestClient.preauth;
import static ca.nordencapital.masterdb.auth.login.AuthTestClient.sessionCookies;
import static ca.nordencapital.masterdb.auth.login.AuthTestClient.token;
import static org.assertj.core.api.Assertions.assertThat;

/** M1.3: the second sign-in step, enrolment, recovery codes, replay and lockout. */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@Import(MutableClock.Config.class)
@ExtendWith(OutputCaptureExtension.class)
class TwoFactorFlowTest {

    static final Instant T0 = Instant.parse("2026-11-06T12:00:07Z");
    static final String PASSWORD = "correct-horse-battery-staple";
    static final String NEW = "new@example.com";
    static final String ENROLLED = "jane@example.com";
    static final String LOGIN_2FA = "/api/v1/auth/login/2fa";
    static final String SETUP = "/api/v1/auth/2fa/setup";
    static final String CONFIRM = "/api/v1/auth/2fa/setup/confirm";

    private static String passwordHash;

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
    LoginService loginService;
    @Autowired
    SecretCipher cipher;
    @Autowired
    JdbcTemplate jdbc;

    AuthTestClient client;
    TwoFactorFixture fixture;

    @BeforeEach
    void setUp() {
        clock.set(T0);
        limiter.clear();
        loginService.clearUnknownAccountAttempts();
        users.deleteAll();
        if (passwordHash == null) {
            passwordHash = encoder.encode(PASSWORD);
        }
        users.save(AuthFlowTest.activeWith(NEW, "New Person", passwordHash));
        users.save(AuthFlowTest.activeWith(ENROLLED, "Jane Member", passwordHash));
        client = new AuthTestClient(port);
        fixture = new TwoFactorFixture(users, cipher, clock, client);
        fixture.enrol(ENROLLED);
    }

    @AfterEach
    void tearDown() {
        users.deleteAll();
        limiter.clear();
    }

    // ---- enrolment ---------------------------------------------------------------------

    @Test
    void firstSignInEnrolsAndShowsRecoveryCodesOnce(CapturedOutput output) throws Exception {
        HttpResponse<String> first = client.login(NEW, PASSWORD);
        assertThat(first.statusCode()).isEqualTo(200);
        assertThat(first.body()).isEqualTo("{\"state\":\"TWO_FACTOR_SETUP_REQUIRED\"}");
        String pre = preauth(first);
        // Not signed in yet.
        assertThat(sessionCookies(first)).isEmpty();
        assertThat(client.code(LOGIN_2FA, pre, "123456").body()).contains("LOGIN_CHALLENGE_INVALID");

        HttpResponse<String> setup = client.code(SETUP, pre, null);
        assertThat(setup.statusCode()).isEqualTo(200);
        String secret = field(setup.body(), "secret");
        assertThat(secret).matches("[A-Z2-7]{32}");
        assertThat(field(setup.body(), "otpauthUri")).isEqualTo("otpauth://totp/MasterDB:new%40example.com?secret="
                + secret + "&issuer=MasterDB&algorithm=SHA1&digits=6&period=30");
        byte[] raw = base32Decode(secret);

        HttpResponse<String> wrong = client.code(CONFIRM, pre, "000000".equals(code(raw)) ? "111111" : "000000");
        assertThat(wrong.statusCode()).isEqualTo(401);
        assertThat(wrong.body()).contains("\"code\":\"INVALID_TWO_FACTOR_CODE\"");

        HttpResponse<String> done = client.code(CONFIRM, pre, code(raw));
        assertThat(done.statusCode()).isEqualTo(200);
        assertThat(done.body()).contains("\"state\":\"AUTHENTICATED\"", "\"email\":\"new@example.com\"");
        List<String> codes = recoveryCodes(done.body());
        assertThat(codes).hasSize(10).allMatch(c -> c.matches("[a-z2-9]{5}-[a-z2-9]{5}")).doesNotHaveDuplicates();
        String token = token(done);
        assertThat(client.me(token).statusCode()).isEqualTo(200);

        // At rest: the secret encrypted, the recovery codes as keyed hashes only.
        String stored = jdbc.queryForObject("select totp_secret_enc from users where email = ?", String.class, NEW);
        assertThat(stored).startsWith("v1:").doesNotContain(secret);
        List<String> hashes = jdbc.queryForList("select code_hash from recovery_codes", String.class);
        assertThat(hashes).hasSize(10);
        assertThat(String.join(",", hashes)).doesNotContain(codes.getFirst().replace("-", ""));
        // The challenge is used up.
        assertThat(client.code(CONFIRM, pre, code(raw)).body()).contains("LOGIN_CHALLENGE_INVALID");
        // Never in the logs.
        assertThat(output.getAll()).doesNotContain(secret).doesNotContain(codes.getFirst()).contains("2fa enrolled");

        // Next time: the code is asked for.
        clock.advance(Duration.ofMinutes(1));
        HttpResponse<String> again = client.login(NEW, PASSWORD);
        assertThat(again.body()).isEqualTo("{\"state\":\"TWO_FACTOR_REQUIRED\"}");
        assertThat(client.code(LOGIN_2FA, preauth(again), code(raw)).statusCode()).isEqualTo(200);
    }

    @Test
    void setupIsOnlyForTheSetupStep() throws Exception {
        String pre = preauth(client.login(ENROLLED, PASSWORD));
        assertThat(client.code(SETUP, pre, null).body()).contains("LOGIN_CHALLENGE_INVALID");
        assertThat(client.code(SETUP, null, null).statusCode()).isEqualTo(401);
        assertThat(client.code(LOGIN_2FA, null, "123456").body()).contains("LOGIN_CHALLENGE_INVALID");
    }

    // ---- verification ------------------------------------------------------------------

    @Test
    void aCodeWorksOnceAndNeverAgain() throws Exception {
        String code = Totp.code(TwoFactorFixture.SECRET, Totp.step(clock.instant()));
        HttpResponse<String> ok = client.code(LOGIN_2FA, preauth(client.login(ENROLLED, PASSWORD)), code);
        assertThat(ok.statusCode()).isEqualTo(200);

        HttpResponse<String> replay = client.code(LOGIN_2FA, preauth(client.login(ENROLLED, PASSWORD)), code);
        assertThat(replay.statusCode()).isEqualTo(401);
        assertThat(replay.body()).contains("\"code\":\"INVALID_TWO_FACTOR_CODE\"");
        // An older step within the drift window is refused too: only later steps count.
        String older = Totp.code(TwoFactorFixture.SECRET, Totp.step(clock.instant()) - 1);
        assertThat(client.code(LOGIN_2FA, preauth(client.login(ENROLLED, PASSWORD)), older).statusCode())
                .isEqualTo(401);
    }

    @Test
    void thirtySecondsOfDriftEitherWay() throws Exception {
        long step = Totp.step(clock.instant());
        assertThat(signInWith(Totp.code(TwoFactorFixture.SECRET, step - 1))).isEqualTo(200);
        assertThat(signInWith(Totp.code(TwoFactorFixture.SECRET, step + 1))).isEqualTo(200);
        assertThat(signInWith(Totp.code(TwoFactorFixture.SECRET, step + 2))).isEqualTo(401);
    }

    @Test
    void recoveryCodesWorkOnceEach() throws Exception {
        // Enrol NEW through the API to get real recovery codes.
        String pre = preauth(client.login(NEW, PASSWORD));
        byte[] raw = base32Decode(field(client.code(SETUP, pre, null).body(), "secret"));
        List<String> codes = recoveryCodes(client.code(CONFIRM, pre, code(raw)).body());

        HttpResponse<String> first = client.code(LOGIN_2FA, preauth(client.login(NEW, PASSWORD)),
                codes.get(3).toUpperCase().replace("-", " "));
        assertThat(first.statusCode()).isEqualTo(200);
        HttpResponse<String> again = client.code(LOGIN_2FA, preauth(client.login(NEW, PASSWORD)), codes.get(3));
        assertThat(again.statusCode()).isEqualTo(401);
        assertThat(again.body()).contains("INVALID_TWO_FACTOR_CODE");
        assertThat(jdbc.queryForObject("select count(*) from recovery_codes where used_at is null", Integer.class))
                .isEqualTo(9);
    }

    @Test
    void theChallengeExpiresAfterTenMinutes() throws Exception {
        String pre = preauth(client.login(ENROLLED, PASSWORD));
        clock.advance(Duration.ofMinutes(10));
        HttpResponse<String> late = client.code(LOGIN_2FA, pre, fixture.nextCode(ENROLLED));
        assertThat(late.statusCode()).isEqualTo(401);
        assertThat(late.body()).contains("\"code\":\"LOGIN_CHALLENGE_INVALID\"");
    }

    // ---- lockout and rate limit ------------------------------------------------------------

    @Test
    void wrongCodesCountTowardsTheAccountLock() throws Exception {
        String pre = preauth(client.login(ENROLLED, PASSWORD));
        for (int i = 1; i <= 4; i++) {
            assertThat(client.code(LOGIN_2FA, pre, "000000").statusCode()).as("attempt %d", i).isEqualTo(401);
        }
        HttpResponse<String> fifth = client.code(LOGIN_2FA, pre, "000000");
        assertThat(fifth.statusCode()).isEqualTo(429);
        assertThat(fifth.body()).contains("\"code\":\"ACCOUNT_LOCKED\"");
        // Locked: even the password step answers "locked".
        assertThat(client.login(ENROLLED, PASSWORD).body()).contains("ACCOUNT_LOCKED");
    }

    /** The password alone never resets the count, so it cannot buy unlimited code guesses. */
    @Test
    void aRightPasswordDoesNotResetTheCount() throws Exception {
        for (int i = 0; i < 4; i++) {
            client.login(ENROLLED, "wrong-password");
        }
        String pre = preauth(client.login(ENROLLED, PASSWORD));
        HttpResponse<String> wrong = client.code(LOGIN_2FA, pre, "000000");
        assertThat(wrong.statusCode()).isEqualTo(429);
        assertThat(wrong.body()).contains("ACCOUNT_LOCKED");
    }

    @Test
    void codeAttemptsAreRateLimitedPerAddress() throws Exception {
        for (int i = 0; i < 10; i++) {
            assertThat(client.code(LOGIN_2FA, null, "123456").statusCode()).isEqualTo(401);
        }
        HttpResponse<String> limited = client.code(LOGIN_2FA, null, "123456");
        assertThat(limited.statusCode()).isEqualTo(429);
        assertThat(limited.body()).contains("\"code\":\"RATE_LIMITED\"");
        // Counted apart from passwords: the password step still answers.
        assertThat(client.login(ENROLLED, PASSWORD).statusCode()).isEqualTo(200);
    }

    // ---- helpers --------------------------------------------------------------------

    private int signInWith(String code) throws Exception {
        return client.code(LOGIN_2FA, preauth(client.login(ENROLLED, PASSWORD)), code).statusCode();
    }

    private String code(byte[] secret) {
        return Totp.code(secret, Totp.step(clock.instant()));
    }

    private static String field(String json, String name) {
        Matcher m = Pattern.compile("\"" + name + "\":\"([^\"]*)\"").matcher(json);
        assertThat(m.find()).as(name + " in " + json).isTrue();
        return m.group(1);
    }

    private static List<String> recoveryCodes(String json) {
        Matcher block = Pattern.compile("\"recoveryCodes\":\\[([^]]*)]").matcher(json);
        assertThat(block.find()).isTrue();
        List<String> codes = new ArrayList<>();
        Matcher each = Pattern.compile("\"([^\"]+)\"").matcher(block.group(1));
        while (each.find()) {
            codes.add(each.group(1));
        }
        return codes;
    }

    static byte[] base32Decode(String value) {
        String alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        byte[] out = new byte[value.length() * 5 / 8];
        int buffer = 0;
        int bits = 0;
        int index = 0;
        for (char c : value.toCharArray()) {
            buffer = (buffer << 5) | alphabet.indexOf(c);
            bits += 5;
            if (bits >= 8) {
                out[index++] = (byte) (buffer >> (bits - 8));
                bits -= 8;
            }
        }
        return out;
    }
}
