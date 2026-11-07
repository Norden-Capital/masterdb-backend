package ca.nordencapital.masterdb.auth.login;

import ca.nordencapital.masterdb.auth.permission.Permission;
import ca.nordencapital.masterdb.auth.permission.PermissionService;
import ca.nordencapital.masterdb.auth.user.User;
import ca.nordencapital.masterdb.auth.user.UserRepository;
import ca.nordencapital.masterdb.crypto.SecretCipher;
import ca.nordencapital.masterdb.web.security.LoginRateLimiter;
import ca.nordencapital.testsupport.CapturingMailSender;
import ca.nordencapital.testsupport.MutableClock;
import ca.nordencapital.testsupport.NamecheapStub;
import ca.nordencapital.testsupport.TestDatabase;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
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
import java.util.Arrays;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Shared set-up of the DNS flow tests: an enrolled Owner (signed in) and a
 * member without permissions, a fake Namecheap API (never the real one), and
 * a saved Namecheap account with a fake key.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@Import({MutableClock.Config.class, CapturingMailSender.Config.class})
abstract class DnsFlowTestBase {

    static final Instant T0 = Instant.parse("2026-11-07T09:00:03Z");
    static final String PASSWORD = "correct-horse-battery-staple";
    static final String OWNER = "owner@example.com";
    static final String MEMBER = "jane@example.com";
    static final String KEY = "FAKEKEYtest0000fake1111nope2222";

    private static String hash;

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry registry) {
        TestDatabase.register(registry);
        NamecheapStub.register(registry);
        ca.nordencapital.testsupport.FakeSmtpServer.register(registry);
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
    PermissionService permissions;
    @Autowired
    JdbcTemplate jdbc;

    AuthTestClient client;
    TwoFactorFixture fixture;
    String owner;

    @BeforeEach
    void setUpDns() throws Exception {
        clock.set(T0);
        limiter.clear();
        loginService.clearUnknownAccountAttempts();
        NamecheapStub.reset();
        clean();
        if (hash == null) {
            hash = encoder.encode(PASSWORD);
        }
        users.save(User.newOwner(OWNER, "Olivia Owner", hash));
        users.save(AuthFlowTest.activeWith(MEMBER, "Jane Member", hash));
        client = new AuthTestClient(port);
        fixture = new TwoFactorFixture(users, cipher, clock, client);
        fixture.enrol(OWNER);
        fixture.enrol(MEMBER);
        owner = fixture.signIn(OWNER, PASSWORD);
        HttpResponse<String> saved = client.send("PUT", "/api/v1/dns/namecheap/account", owner,
                "{\"apiUser\":\"testuser\",\"apiKey\":\"" + KEY + "\"}");
        assertThat(saved.statusCode()).isEqualTo(200);
    }

    @AfterEach
    void tearDownDns() {
        clean();
        limiter.clear();
        NamecheapStub.reset();
    }

    private void clean() {
        users.deleteAll();
        jdbc.update("delete from domains");
        jdbc.update("delete from namecheap_account");
        jdbc.update("delete from activity_log");
    }

    /** The member, signed in with exactly these permissions (VIEW implied as usual). */
    String member(String... perms) throws Exception {
        Long id = users.findByEmail(MEMBER).orElseThrow().getId();
        permissions.replace(id, Arrays.stream(perms).map(Permission::parse).collect(Collectors.toSet()), null);
        return fixture.signIn(MEMBER, PASSWORD);
    }

    HttpResponse<String> get(String path) throws Exception {
        return client.send("GET", path, owner, null);
    }

    HttpResponse<String> post(String path, String body) throws Exception {
        return client.send("POST", path, owner, body);
    }

    /** Adds a domain by hand and returns its public id. */
    String addManual(String name) throws Exception {
        HttpResponse<String> res = post("/api/v1/dns/domains", "{\"name\":\"" + name + "\"}");
        assertThat(res.statusCode()).as(res.body()).isEqualTo(201);
        return id(res.body());
    }

    static String id(String body) {
        int i = body.indexOf("\"publicId\":\"") + 12;
        return body.substring(i, body.indexOf('"', i));
    }
}
