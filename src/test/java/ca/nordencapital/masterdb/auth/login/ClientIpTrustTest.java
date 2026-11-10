package ca.nordencapital.masterdb.auth.login;

import ca.nordencapital.masterdb.auth.user.User;
import ca.nordencapital.masterdb.auth.user.UserRepository;
import ca.nordencapital.masterdb.crypto.SecretCipher;
import ca.nordencapital.masterdb.web.security.LoginRateLimiter;
import ca.nordencapital.testsupport.MutableClock;
import ca.nordencapital.testsupport.TestDatabase;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import java.net.http.HttpResponse;
import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The website's X-Client-IP is believed when well-formed (no proxy secret since
 * 2026-11-10, see ClientIp), and the login rate limit counts per that address.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@Import(MutableClock.Config.class)
class ClientIpTrustTest {

    static final String EMAIL = "owner@example.com";
    static final String PASSWORD = "correct-horse-battery-staple";

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
    LoginRateLimiter limiter;
    @Autowired
    LoginService loginService;
    @Autowired
    MutableClock clock;
    @Autowired
    JdbcTemplate jdbc;
    @Autowired
    SecretCipher cipher;

    AuthTestClient client;
    TwoFactorFixture twoFactor;

    @BeforeEach
    void setUp() {
        clock.set(Instant.parse("2026-11-06T12:00:00Z"));
        limiter.clear();
        loginService.clearUnknownAccountAttempts();
        users.deleteAll();
        users.save(User.newOwner(EMAIL, "Olivia Owner", encoder.encode(PASSWORD)));
        client = new AuthTestClient(port);
        twoFactor = new TwoFactorFixture(users, cipher, clock, client);
        twoFactor.enrol(EMAIL);
    }

    @AfterEach
    void tearDown() {
        users.deleteAll();
        limiter.clear();
    }

    @Test
    void theWebsitesClientIpIsRecorded() throws Exception {
        String token = twoFactor.signIn(EMAIL, PASSWORD, "X-Client-IP", "203.0.113.7");
        assertThat(jdbc.queryForObject("select ip from user_sessions", String.class)).isEqualTo("203.0.113.7");
        assertThat(jdbc.queryForObject("select ip from login_challenges", String.class)).isEqualTo("203.0.113.7");
        assertThat(client.me(token).statusCode()).isEqualTo(200);
    }

    @Test
    void aMalformedClientIpFallsBackToTheConnection() throws Exception {
        twoFactor.signIn(EMAIL, PASSWORD, "X-Client-IP", "203.0.113.7, 10.0.0.1");
        assertThat(jdbc.queryForObject("select ip from user_sessions", String.class)).isEqualTo("127.0.0.1");
    }

    @Test
    void theRateLimitCountsPerForwardedAddress() throws Exception {
        for (int i = 0; i < 10; i++) {
            client.login("x" + i + "@example.com", "wrong-password", "X-Client-IP", "203.0.113.7");
        }
        HttpResponse<String> limited = client.login(EMAIL, PASSWORD, "X-Client-IP", "203.0.113.7");
        assertThat(limited.statusCode()).isEqualTo(429);
        assertThat(limited.body()).contains("\"code\":\"RATE_LIMITED\"");

        // Another visitor behind the same website server is not affected.
        twoFactor.signIn(EMAIL, PASSWORD, "X-Client-IP", "2001:db8::1");
        assertThat(jdbc.queryForObject("select ip from user_sessions", String.class)).isEqualTo("2001:db8::1");
    }
}
