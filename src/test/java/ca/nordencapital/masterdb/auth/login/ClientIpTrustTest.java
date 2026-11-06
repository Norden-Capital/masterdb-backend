package ca.nordencapital.masterdb.auth.login;

import ca.nordencapital.masterdb.auth.user.User;
import ca.nordencapital.masterdb.auth.user.UserRepository;
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

import static ca.nordencapital.masterdb.auth.login.AuthTestClient.token;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * As in production: the proxy-secret check is on. The website's X-Client-IP is
 * believed only on a request with the right secret, and the login rate limit
 * counts per that address.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
        "app.proxy.required=true",
        "app.proxy.secret=" + ClientIpTrustTest.SECRET,
})
@Import(MutableClock.Config.class)
class ClientIpTrustTest {

    /** A test value only. */
    static final String SECRET = "test-proxy-secret-for-client-ip-0123456789abcdef0123456789abcdef";
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

    AuthTestClient client;

    @BeforeEach
    void setUp() {
        clock.set(Instant.parse("2026-11-06T12:00:00Z"));
        limiter.clear();
        loginService.clearUnknownAccountAttempts();
        users.deleteAll();
        users.save(User.newOwner(EMAIL, "Olivia Owner", encoder.encode(PASSWORD)));
        client = new AuthTestClient(port);
    }

    @AfterEach
    void tearDown() {
        users.deleteAll();
        limiter.clear();
    }

    @Test
    void theWebsitesClientIpIsRecordedWithTheSecret() throws Exception {
        HttpResponse<String> response = client.login(EMAIL, PASSWORD,
                "X-Proxy-Secret", SECRET, "X-Client-IP", "203.0.113.7");
        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(jdbc.queryForObject("select ip from user_sessions", String.class)).isEqualTo("203.0.113.7");

        // The session works through the website (cookie + secret) and not without the secret.
        String token = token(response);
        assertThat(client.send("GET", "/api/v1/auth/me", token, null, "X-Proxy-Secret", SECRET).statusCode())
                .isEqualTo(200);
        HttpResponse<String> direct = client.me(token);
        assertThat(direct.statusCode()).isEqualTo(401);
        assertThat(direct.body()).contains("\"code\":\"PROXY_SECRET_INVALID\"");
    }

    @Test
    void aMalformedClientIpFallsBackToTheConnection() throws Exception {
        client.login(EMAIL, PASSWORD, "X-Proxy-Secret", SECRET, "X-Client-IP", "203.0.113.7, 10.0.0.1");
        assertThat(jdbc.queryForObject("select ip from user_sessions", String.class)).isEqualTo("127.0.0.1");
    }

    @Test
    void aWrongSecretNeverReachesTheLimiterOrLogin() throws Exception {
        HttpResponse<String> response = client.login(EMAIL, PASSWORD,
                "X-Proxy-Secret", "wrong-secret-wrong-secret-wrong-secret", "X-Client-IP", "203.0.113.7");
        assertThat(response.statusCode()).isEqualTo(401);
        assertThat(response.body()).contains("\"code\":\"PROXY_SECRET_INVALID\"");
        assertThat(jdbc.queryForObject("select count(*) from user_sessions", Integer.class)).isZero();
    }

    @Test
    void theRateLimitCountsPerForwardedAddress() throws Exception {
        for (int i = 0; i < 10; i++) {
            client.login("x" + i + "@example.com", "wrong-password", "X-Proxy-Secret", SECRET,
                    "X-Client-IP", "203.0.113.7");
        }
        HttpResponse<String> limited = client.login(EMAIL, PASSWORD, "X-Proxy-Secret", SECRET,
                "X-Client-IP", "203.0.113.7");
        assertThat(limited.statusCode()).isEqualTo(429);
        assertThat(limited.body()).contains("\"code\":\"RATE_LIMITED\"");

        // Another visitor behind the same website server is not affected.
        HttpResponse<String> other = client.login(EMAIL, PASSWORD, "X-Proxy-Secret", SECRET,
                "X-Client-IP", "2001:db8::1");
        assertThat(other.statusCode()).isEqualTo(200);
        assertThat(jdbc.queryForObject("select ip from user_sessions", String.class)).isEqualTo("2001:db8::1");
    }
}
