package ca.nordencapital.masterdb.auth.login;

import ca.nordencapital.masterdb.auth.permission.Permission;
import ca.nordencapital.masterdb.auth.permission.PermissionService;
import ca.nordencapital.masterdb.auth.user.User;
import ca.nordencapital.masterdb.auth.user.UserRepository;
import ca.nordencapital.masterdb.crypto.SecretCipher;
import ca.nordencapital.masterdb.web.security.LoginRateLimiter;
import ca.nordencapital.testsupport.MutableClock;
import ca.nordencapital.testsupport.PermissionProbeController;
import ca.nordencapital.testsupport.TestDatabase;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.annotation.Import;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import java.net.http.HttpResponse;
import java.time.Instant;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/** M1.4: permission checks on endpoints, the Owner bypass, /me and the catalogue. */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@Import({MutableClock.Config.class, PermissionProbeController.class})
class PermissionFlowTest {

    static final String PASSWORD = "correct-horse-battery-staple";
    static final String OWNER = "owner@example.com";
    static final String MEMBER = "jane@example.com";
    static final String EXPORT = "/api/v1/test-probe/contacts-export";

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
    PermissionService permissions;

    AuthTestClient client;
    TwoFactorFixture fixture;

    @BeforeEach
    void setUp() {
        clock.set(Instant.parse("2026-11-06T12:00:00Z"));
        limiter.clear();
        users.deleteAll();
        if (hash == null) {
            hash = encoder.encode(PASSWORD);
        }
        users.save(User.newOwner(OWNER, "Olivia Owner", hash));
        users.save(AuthFlowTest.activeWith(MEMBER, "Jane Member", hash));
        client = new AuthTestClient(port);
        fixture = new TwoFactorFixture(users, cipher, clock, client);
        fixture.enrol(OWNER);
        fixture.enrol(MEMBER);
    }

    @AfterEach
    void tearDown() {
        users.deleteAll();
        limiter.clear();
    }

    @Test
    void withoutTheGrantItIs403ProblemJson() throws Exception {
        String token = fixture.signIn(MEMBER, PASSWORD);
        HttpResponse<String> response = client.send("GET", EXPORT, token, null);
        assertThat(response.statusCode()).isEqualTo(403);
        assertThat(response.headers().firstValue("Content-Type")).hasValueSatisfying(
                ct -> assertThat(ct).startsWith("application/problem+json"));
        assertThat(response.body()).contains("\"code\":\"FORBIDDEN\"", "\"instance\":\"" + EXPORT + "\"");
        // Signed out it stays 401, never 403.
        assertThat(client.send("GET", EXPORT, null, null).statusCode()).isEqualTo(401);
    }

    @Test
    void aGrantTakesEffectOnTheNextRequestAndShowsInMe() throws Exception {
        String token = fixture.signIn(MEMBER, PASSWORD);
        Long id = users.findByEmail(MEMBER).orElseThrow().getId();
        permissions.replace(id, Set.of(Permission.parse("CONTACTS:EXPORT")), null);

        assertThat(client.send("GET", EXPORT, token, null).statusCode()).isEqualTo(200);
        assertThat(client.send("GET", "/api/v1/test-probe/backups-run", token, null).statusCode()).isEqualTo(403);
        assertThat(client.me(token).body())
                .contains("\"isOwner\":false", "\"permissions\":[\"CONTACTS:VIEW\",\"CONTACTS:EXPORT\"]");

        permissions.replace(id, Set.of(), null);
        assertThat(client.send("GET", EXPORT, token, null).statusCode()).isEqualTo(403);
        assertThat(client.me(token).body()).contains("\"permissions\":[]");
    }

    @Test
    void theOwnerPassesEveryCheckAndSeesEveryPermission() throws Exception {
        String token = fixture.signIn(OWNER, PASSWORD);
        assertThat(client.send("GET", EXPORT, token, null).statusCode()).isEqualTo(200);
        assertThat(client.send("GET", "/api/v1/test-probe/backups-run", token, null).statusCode()).isEqualTo(200);
        String me = client.me(token).body();
        assertThat(me).contains("\"isOwner\":true", "\"USERS:EDIT\"", "\"SETTINGS:EDIT\"", "\"BACKUPS:RUN\"");
        assertThat(me.split("\"[A-Z_]+:[A-Z]+\"", -1).length - 1).isEqualTo(Permission.all().size());
    }

    @Test
    void theCatalogueListsModulesActionsAndTemplates() throws Exception {
        String token = fixture.signIn(MEMBER, PASSWORD);
        HttpResponse<String> response = client.send("GET", "/api/v1/permissions/catalogue", token, null);
        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(response.body()).contains("{\"key\":\"SERVERS\",\"label\":\"Servers\"",
                "{\"key\":\"RUN\",\"label\":\"Run\"}", "\"key\":\"VIEWER\"", "\"key\":\"OPERATOR\"", "\"key\":\"ADMIN\"");
        assertThat(client.send("GET", "/api/v1/permissions/catalogue", null, null).statusCode()).isEqualTo(401);
    }
}
