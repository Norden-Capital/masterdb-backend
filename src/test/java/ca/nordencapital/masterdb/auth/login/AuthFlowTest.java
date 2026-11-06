package ca.nordencapital.masterdb.auth.login;

import ca.nordencapital.masterdb.auth.user.User;
import ca.nordencapital.masterdb.auth.user.UserRepository;
import ca.nordencapital.masterdb.auth.user.UserStatus;
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
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.sql.Timestamp;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;

import static ca.nordencapital.masterdb.auth.login.AuthTestClient.sessionCookies;
import static ca.nordencapital.masterdb.auth.login.AuthTestClient.stable;
import static ca.nordencapital.masterdb.auth.login.AuthTestClient.token;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * Login, session, logout, lockout and rate limit, end to end through real
 * Tomcat (the 401/429 bodies come from the container's /error forward) against
 * the embedded PostgreSQL, with a clock the tests move.
 *
 * <p>The proxy-secret check is off here (as locally), so X-Client-IP must be
 * ignored; ClientIpTrustTest covers the website path with the secret on.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@Import(MutableClock.Config.class)
@ExtendWith(OutputCaptureExtension.class)
class AuthFlowTest {

    static final Instant T0 = Instant.parse("2026-11-06T12:00:00Z");
    /** Test-only passwords. */
    static final String PASSWORD = "correct-horse-battery-staple";
    static final String WRONG = "wrong-password-0123";

    static final String OWNER = "owner@example.com";
    static final String MEMBER = "jane@example.com";
    static final String DISABLED = "gone@example.com";
    static final String INVITED = "new@example.com";

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
    JdbcTemplate jdbc;
    @Autowired
    SecretCipher cipher;

    AuthTestClient client;
    TwoFactorFixture twoFactor;

    @BeforeEach
    void setUp() {
        clock.set(T0);
        limiter.clear();
        loginService.clearUnknownAccountAttempts();
        users.deleteAll();
        if (passwordHash == null) {
            passwordHash = encoder.encode(PASSWORD);
        }
        users.save(User.newOwner(OWNER, "Olivia Owner", passwordHash));
        users.save(active(MEMBER, "Jane Member"));
        User disabled = active(DISABLED, "Gone User");
        disabled.setStatus(UserStatus.DISABLED);
        users.save(disabled);
        users.save(User.newInvited(INVITED, "New User"));
        client = new AuthTestClient(port);
        twoFactor = new TwoFactorFixture(users, cipher, clock, client);
        twoFactor.enrol(OWNER);
        twoFactor.enrol(MEMBER);
        twoFactor.enrol(DISABLED);
    }

    @AfterEach
    void tearDown() {
        users.deleteAll(); // sessions go with them (ON DELETE CASCADE)
        limiter.clear();
    }

    static User active(String email, String name) {
        return activeWith(email, name, passwordHash);
    }

    static User activeWith(String email, String name, String hash) {
        User user = User.newInvited(email, name);
        user.setPasswordHash(hash);
        user.setStatus(UserStatus.ACTIVE);
        return user;
    }

    // ---- login ------------------------------------------------------------------------

    @Test
    void loginSetsAProperCookieAndReturnsTheUser() throws Exception {
        HttpResponse<String> first = client.login(" Owner@Example.COM ", PASSWORD);
        assertThat(first.statusCode()).isEqualTo(200);
        assertThat(first.body()).isEqualTo("{\"state\":\"TWO_FACTOR_REQUIRED\"}");
        assertThat(sessionCookies(first)).isEmpty();
        assertThat(first.headers().allValues("Set-Cookie")).singleElement().satisfies(c -> assertThat(c)
                .startsWith("md_preauth=").contains("HttpOnly", "Secure", "SameSite=Strict", "Path=/api/v1/auth",
                        "Max-Age=600").doesNotContainIgnoringCase("Domain"));

        HttpResponse<String> response = client.code("/api/v1/auth/login/2fa", AuthTestClient.preauth(first),
                twoFactor.nextCode(OWNER));
        assertThat(response.statusCode()).isEqualTo(200);
        String owner = users.findByEmail(OWNER).orElseThrow().getPublicId().toString();
        assertThat(response.body()).contains("\"state\":\"AUTHENTICATED\"", "\"publicId\":\"" + owner + "\"",
                "\"email\":\"owner@example.com\"", "\"fullName\":\"Olivia Owner\"", "\"isOwner\":true")
                .doesNotContain("passwordHash", "\"id\"", "token", "recoveryCodes");

        List<String> cookies = sessionCookies(response);
        assertThat(cookies).hasSize(1);
        String cookie = cookies.getFirst();
        assertThat(cookie).contains("HttpOnly", "Secure", "SameSite=Lax", "Path=/", "Max-Age=604800")
                .doesNotContainIgnoringCase("Domain");
        // The 2FA-step cookie is deleted.
        assertThat(response.headers().allValues("Set-Cookie")).anySatisfy(c ->
                assertThat(c).startsWith("md_preauth=;").contains("Max-Age=0"));
        String token = token(response);
        assertThat(token).hasSize(43).matches("[A-Za-z0-9_-]+");

        // Only the hash is stored, with where the login came from.
        Map<String, Object> row = jdbc.queryForMap("select * from user_sessions");
        assertThat(row.get("token_hash")).isEqualTo(sha256(token));
        assertThat(row.values()).noneMatch(v -> v != null && v.toString().contains(token));
        assertThat(row.get("ip")).isEqualTo("127.0.0.1");
        assertThat(row.get("user_agent")).isEqualTo(AuthTestClient.USER_AGENT);
        assertThat(((Timestamp) row.get("expires_at")).toInstant()).isEqualTo(T0.plus(Duration.ofDays(7)));
        assertThat(row.get("revoked_at")).isNull();

        User stored = users.findByEmail(OWNER).orElseThrow();
        assertThat(stored.getLastLoginAt()).isEqualTo(T0);
        assertThat(stored.getFailedLoginAttempts()).isZero();
    }

    @Test
    void everyFailureLooksTheSame() throws Exception {
        List<HttpResponse<String>> failures = List.of(
                client.login(OWNER, WRONG),          // wrong password
                client.login("nobody@example.com", PASSWORD), // no such account
                client.login(DISABLED, PASSWORD),     // right password, disabled
                client.login(INVITED, PASSWORD));     // invited, has no password yet

        String first = stable(failures.getFirst().body());
        assertThat(first).contains("\"code\":\"INVALID_CREDENTIALS\"", "\"status\":401",
                "\"detail\":\"" + InvalidCredentialsException.DETAIL + "\"");
        for (HttpResponse<String> failure : failures) {
            assertThat(failure.statusCode()).isEqualTo(401);
            assertThat(failure.headers().firstValue("Content-Type")).hasValueSatisfying(
                    ct -> assertThat(ct).startsWith("application/problem+json"));
            assertThat(stable(failure.body())).isEqualTo(first);
            assertThat(sessionCookies(failure)).isEmpty();
        }
        assertThat(jdbc.queryForObject("select count(*) from user_sessions", Integer.class)).isZero();
    }

    @Test
    void badRequestBodyIsValidationFailedWithoutEcho() throws Exception {
        HttpResponse<String> response = client.login(OWNER, "");
        assertThat(response.statusCode()).isEqualTo(400);
        assertThat(response.body()).contains("\"code\":\"VALIDATION_FAILED\"").doesNotContain(OWNER);
    }

    // ---- lockout ------------------------------------------------------------------------

    @Test
    void fiveWrongPasswordsLockTheAccountForFifteenMinutes() throws Exception {
        for (int i = 1; i <= 4; i++) {
            assertThat(client.login(MEMBER, WRONG).statusCode()).as("attempt %d", i).isEqualTo(401);
        }
        HttpResponse<String> fifth = client.login(MEMBER, WRONG);
        assertLocked(fifth, 900);

        // While locked the password is not even checked: right and wrong look the same.
        HttpResponse<String> right = client.login(MEMBER, PASSWORD);
        HttpResponse<String> wrong = client.login(MEMBER, WRONG);
        assertLocked(right, 900);
        assertThat(stable(right.body())).isEqualTo(stable(wrong.body()));
        assertThat(sessionCookies(right)).isEmpty();
        assertThat(users.findByEmail(MEMBER).orElseThrow().getLockedUntil()).isEqualTo(T0.plus(Duration.ofMinutes(15)));

        clock.advance(Duration.ofMinutes(15).minusSeconds(1));
        assertLocked(client.login(MEMBER, PASSWORD), 1);

        clock.advance(Duration.ofSeconds(1));
        twoFactor.signIn(MEMBER, PASSWORD);
        User member = users.findByEmail(MEMBER).orElseThrow();
        assertThat(member.getFailedLoginAttempts()).isZero();
        assertThat(member.getLockedUntil()).isNull();
    }

    @Test
    void aSuccessResetsTheCount() throws Exception {
        for (int i = 0; i < 4; i++) {
            client.login(MEMBER, WRONG);
        }
        twoFactor.signIn(MEMBER, PASSWORD);
        for (int i = 1; i <= 4; i++) {
            assertThat(client.login(MEMBER, WRONG).statusCode()).as("attempt %d", i).isEqualTo(401);
        }
        assertThat(users.findByEmail(MEMBER).orElseThrow().getFailedLoginAttempts()).isEqualTo(4);
    }

    /** Otherwise "locked" would reveal which emails have an account. */
    @Test
    void madeUpEmailsLockExactlyLikeRealOnes() throws Exception {
        HttpResponse<String> real = null;
        HttpResponse<String> fake = null;
        for (int i = 0; i < 5; i++) {
            real = client.login(MEMBER, WRONG);
            fake = client.login("nobody@example.com", WRONG);
        }
        assertLocked(real, 900);
        assertLocked(fake, 900);
        assertThat(stable(fake.body())).isEqualTo(stable(real.body()));

        clock.advance(Duration.ofMinutes(15));
        assertThat(client.login("nobody@example.com", WRONG).statusCode()).isEqualTo(401);
    }

    // ---- rate limit per address ----------------------------------------------------------------

    @Test
    void elevenAttemptsInAMinuteAreRateLimited() throws Exception {
        for (int i = 0; i < 10; i++) {
            HttpResponse<String> response = client.login("x" + i + "@example.com", WRONG);
            assertThat(response.statusCode()).as("attempt %d", i + 1).isEqualTo(401);
        }
        HttpResponse<String> limited = client.login(OWNER, PASSWORD);
        assertThat(limited.statusCode()).isEqualTo(429);
        assertThat(limited.headers().firstValue("Retry-After")).hasValue("60");
        assertThat(limited.headers().firstValue("Content-Type")).hasValueSatisfying(
                ct -> assertThat(ct).startsWith("application/problem+json"));
        assertThat(limited.body()).contains("\"code\":\"RATE_LIMITED\"", "\"status\":429");
        assertThat(sessionCookies(limited)).isEmpty();

        clock.advance(Duration.ofMinutes(1));
        assertThat(client.login(OWNER, PASSWORD).statusCode()).isEqualTo(200);
    }

    @Test
    void fiftyAttemptsAnHourAreRateLimited() throws Exception {
        int sent = 0;
        for (int minute = 0; minute < 5; minute++) {
            for (int i = 0; i < 10; i++) {
                assertThat(client.login("y" + sent++ + "@example.com", WRONG).statusCode()).isEqualTo(401);
            }
            clock.advance(Duration.ofMinutes(1));
        }
        HttpResponse<String> limited = client.login(OWNER, PASSWORD);
        assertThat(limited.statusCode()).isEqualTo(429);
        assertThat(limited.body()).contains("\"code\":\"RATE_LIMITED\"");
        // The hour window started at T0 and it is now T0 + 5 min.
        assertThat(limited.headers().firstValue("Retry-After")).hasValue(String.valueOf(55 * 60));
    }

    /** With no valid proxy secret, a client cannot pick its own address. */
    @Test
    void xClientIpIsIgnoredWithoutAValidProxySecret() throws Exception {
        for (int i = 0; i < 10; i++) {
            client.login("z" + i + "@example.com", WRONG, "X-Client-IP", "203.0.113." + i);
        }
        HttpResponse<String> limited = client.login(OWNER, PASSWORD, "X-Client-IP", "198.51.100.1");
        assertThat(limited.statusCode()).isEqualTo(429);

        limiter.clear();
        twoFactor.signIn(OWNER, PASSWORD, "X-Client-IP", "203.0.113.50");
        assertThat(jdbc.queryForObject("select ip from user_sessions", String.class)).isEqualTo("127.0.0.1");
    }

    // ---- session ------------------------------------------------------------------------

    @Test
    void meNeedsASession() throws Exception {
        HttpResponse<String> anonymous = client.me(null);
        assertThat(anonymous.statusCode()).isEqualTo(401);
        assertThat(anonymous.headers().firstValue("Content-Type")).hasValueSatisfying(
                ct -> assertThat(ct).startsWith("application/problem+json"));
        assertThat(anonymous.body()).contains("\"code\":\"UNAUTHENTICATED\"", "\"instance\":\"/api/v1/auth/me\"");
        assertThat(sessionCookies(anonymous)).isEmpty();

        String token = twoFactor.signIn(MEMBER, PASSWORD);
        HttpResponse<String> me = client.me(token);
        assertThat(me.statusCode()).isEqualTo(200);
        assertThat(me.body()).contains("\"email\":\"jane@example.com\"", "\"fullName\":\"Jane Member\"",
                "\"isOwner\":false");
    }

    @Test
    void anUnknownCookieIs401AndDeleted() throws Exception {
        for (String bad : List.of("not-a-token", "A".repeat(43))) {
            HttpResponse<String> response = client.me(bad);
            assertThat(response.statusCode()).isEqualTo(401);
            assertThat(response.body()).contains("\"code\":\"UNAUTHENTICATED\"");
            assertThat(sessionCookies(response)).singleElement().satisfies(c ->
                    assertThat(c).startsWith("md_session=;").contains("Max-Age=0", "Path=/", "HttpOnly"));
        }
    }

    @Test
    void logoutEndsTheSessionAtOnce() throws Exception {
        String token = twoFactor.signIn(MEMBER, PASSWORD);
        String other = twoFactor.signIn(MEMBER, PASSWORD);

        HttpResponse<String> logout = client.logout(token);
        assertThat(logout.statusCode()).isEqualTo(204);
        assertThat(sessionCookies(logout)).singleElement().satisfies(c ->
                assertThat(c).startsWith("md_session=;").contains("Max-Age=0"));
        assertThat(jdbc.queryForObject("select revoked_at from user_sessions where token_hash = ?", Timestamp.class,
                sha256(token)).toInstant()).isEqualTo(T0);

        assertThat(client.me(token).statusCode()).isEqualTo(401);
        assertThat(client.logout(token).statusCode()).isEqualTo(401);
        // Only that session: the other sign-in still works.
        assertThat(client.me(other).statusCode()).isEqualTo(200);
    }

    @Test
    void anIdleSessionEndsAfterTwelveHours() throws Exception {
        String token = twoFactor.signIn(MEMBER, PASSWORD);

        clock.advance(Duration.ofHours(11));
        assertThat(client.me(token).statusCode()).isEqualTo(200); // use moves last_seen_at
        clock.advance(Duration.ofHours(11));
        assertThat(client.me(token).statusCode()).isEqualTo(200);
        clock.advance(Duration.ofHours(12));
        assertThat(client.me(token).statusCode()).isEqualTo(401);
    }

    @Test
    void aSessionEndsAfterSevenDaysHoweverMuchItIsUsed() throws Exception {
        String token = twoFactor.signIn(MEMBER, PASSWORD);
        List<Integer> statuses = new ArrayList<>();
        for (int i = 1; i <= 16; i++) { // every 11 h: never idle; 15 × 11 h = 165 h < 168 h < 176 h
            clock.advance(Duration.ofHours(11));
            statuses.add(client.me(token).statusCode());
        }
        assertThat(statuses.subList(0, 15)).containsOnly(200);
        assertThat(statuses.get(15)).isEqualTo(401);
    }

    @Test
    void disablingAUserEndsTheirSessionsAtOnce() throws Exception {
        String token = twoFactor.signIn(MEMBER, PASSWORD);
        User member = users.findByEmail(MEMBER).orElseThrow();
        member.setStatus(UserStatus.DISABLED);
        users.save(member);
        assertThat(client.me(token).statusCode()).isEqualTo(401);
    }

    @Test
    void signedInUnknownRouteIs404() throws Exception {
        String token = twoFactor.signIn(MEMBER, PASSWORD);
        HttpResponse<String> response = client.send("GET", "/api/v1/nope", token, null);
        assertThat(response.statusCode()).isEqualTo(404);
        assertThat(response.body()).contains("\"code\":\"NOT_FOUND\"");
    }

    @Test
    void statusStaysOpen() throws Exception {
        assertThat(client.send("GET", "/api/v1/status", null, null).statusCode()).isEqualTo(200);
        assertThat(client.send("GET", "/actuator/health", null, null).statusCode()).isEqualTo(200);
        // Only POST is open on the login path.
        assertThat(client.send("GET", "/api/v1/auth/login", null, null).statusCode()).isEqualTo(401);
    }

    // ---- logs ----------------------------------------------------------------------------

    @Test
    void auditLinesHaveMaskedEmailAndRequestIdButNoSecrets(CapturedOutput output) throws Exception {
        String token = twoFactor.signIn(MEMBER, PASSWORD, "X-Request-Id", "login-ok-1");
        client.login(MEMBER, WRONG, "X-Request-Id", "login-bad-1");
        client.me(token);
        client.logout(token);
        for (int i = 0; i < 5; i++) {
            client.login(OWNER, WRONG);
        }

        assertThat(output.getAll())
                .contains("login succeeded: j***@example.com", "requestId=login-ok-1")
                .contains("login failed (wrong password): j***@example.com", "requestId=login-bad-1")
                .contains("logout: j***@example.com")
                .contains("account locked: o***@example.com")
                .doesNotContain(PASSWORD, WRONG, token, sha256(token), passwordHash,
                        ca.nordencapital.masterdb.auth.twofactor.Totp.base32(TwoFactorFixture.SECRET))
                .doesNotContain(MEMBER, OWNER)
                .doesNotContain("Using generated security password");
    }

    // ---- helpers --------------------------------------------------------------------------

    private static void assertLocked(HttpResponse<String> response, long seconds) {
        assertThat(response.statusCode()).isEqualTo(429);
        assertThat(response.headers().firstValue("Retry-After")).hasValue(String.valueOf(seconds));
        assertThat(response.body()).contains("\"code\":\"ACCOUNT_LOCKED\"", "\"retryAfterSeconds\":" + seconds);
    }

    static String sha256(String value) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                .digest(value.getBytes(StandardCharsets.US_ASCII)));
    }
}
