package ca.nordencapital.masterdb.auth.login;

import ca.nordencapital.masterdb.auth.permission.Permission;
import ca.nordencapital.masterdb.auth.permission.PermissionService;
import ca.nordencapital.masterdb.auth.user.User;
import ca.nordencapital.masterdb.auth.user.UserRepository;
import ca.nordencapital.masterdb.crypto.SecretCipher;
import ca.nordencapital.masterdb.web.security.LoginRateLimiter;
import ca.nordencapital.testsupport.CapturingMailSender;
import ca.nordencapital.testsupport.MutableClock;
import ca.nordencapital.testsupport.TestDatabase;
import org.flywaydb.core.Flyway;
import org.flywaydb.core.api.configuration.FluentConfiguration;
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

import javax.sql.DataSource;
import java.net.http.HttpResponse;
import java.sql.Timestamp;
import java.time.Duration;
import java.time.Instant;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/** M2.4: GET /api/v1/dashboard/summary – real counts only, behind DASHBOARD:VIEW. */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@Import({MutableClock.Config.class, CapturingMailSender.Config.class})
class DashboardFlowTest {

    static final Instant T0 = Instant.parse("2026-11-07T09:00:03Z");
    static final String PASSWORD = "correct-horse-battery-staple";
    static final String OWNER = "owner@example.com";
    static final String MEMBER = "jane@example.com";
    static final String LEAVER = "leaver@example.com";

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
    LoginService loginService;
    @Autowired
    SecretCipher cipher;
    @Autowired
    PermissionService permissions;
    @Autowired
    JdbcTemplate jdbc;
    @Autowired
    DataSource dataSource;

    AuthTestClient client;
    TwoFactorFixture fixture;

    @BeforeEach
    void setUp() {
        clock.set(T0);
        limiter.clear();
        loginService.clearUnknownAccountAttempts();
        users.deleteAll();
        jdbc.update("delete from activity_log");
        if (hash == null) {
            hash = encoder.encode(PASSWORD);
        }
        users.save(User.newOwner(OWNER, "Olivia Owner", hash));
        users.save(AuthFlowTest.activeWith(MEMBER, "Jane Member", hash));
        users.save(AuthFlowTest.activeWith(LEAVER, "Lee Leaver", hash));
        users.save(User.newInvited("new1@example.com", "New One"));
        users.save(User.newInvited("new2@example.com", "New Two"));
        client = new AuthTestClient(port);
        fixture = new TwoFactorFixture(users, cipher, clock, client);
        fixture.enrol(OWNER);
        fixture.enrol(MEMBER);
        fixture.enrol(LEAVER);
    }

    @AfterEach
    void tearDown() {
        users.deleteAll();
        jdbc.update("delete from activity_log");
        limiter.clear();
    }

    @Test
    void theNumbersAreTheDatabasesNumbers() throws Exception {
        // Session that goes idle (12 h limit) before the summary is asked for.
        fixture.signIn(MEMBER, PASSWORD);
        clock.advance(Duration.ofHours(13));
        String owner = fixture.signIn(OWNER, PASSWORD);
        fixture.signIn(MEMBER, PASSWORD);
        client.logout(fixture.signIn(MEMBER, PASSWORD)); // revoked
        fixture.signIn(LEAVER, PASSWORD);
        jdbc.update("update users set status = 'DISABLED' where email = ?", LEAVER); // open row, can't be used
        Instant now = clock.instant();
        jdbc.update("insert into activity_log (occurred_at, action) values (?, 'LOGOUT'), (?, 'LOGOUT'), "
                        + "(?, 'LOGOUT')", Timestamp.from(now.minus(Duration.ofDays(2))),
                Timestamp.from(now.minus(Duration.ofDays(8))), Timestamp.from(now.minus(Duration.ofHours(23))));

        HttpResponse<String> res = client.send("GET", "/api/v1/dashboard/summary", owner, null);
        assertThat(res.statusCode()).isEqualTo(200);
        String body = res.body();

        // By hand: 5 accounts, owner + jane active, leaver disabled, 2 invited.
        // Open: owner + jane's second session (first idle, third logged out, leaver disabled).
        // Activity at T0+13h: 5 sign-ins + 1 logout today, one entry 23 h ago (in 24 h), one 2 days ago (7 days
        // only), one 8 days ago (neither); jane's first sign-in was 13 h ago (in 24 h).
        assertThat(body).contains("\"users\":{\"total\":5,\"active\":2,\"invited\":2,\"disabled\":1}",
                "\"openSessions\":2", "\"generatedAt\":\"2026-11-07T22:00:03Z\"");

        // And the same numbers counted straight from the tables.
        long logins24 = count("select count(*) from activity_log where occurred_at >= ?", now.minus(Duration.ofHours(24)));
        long logins7 = count("select count(*) from activity_log where occurred_at >= ?", now.minus(Duration.ofDays(7)));
        assertThat(logins24).isEqualTo(count("select count(*) from activity_log") - 2);
        assertThat(body).contains("\"activity\":{\"last24Hours\":" + logins24 + ",\"last7Days\":" + logins7 + "}");
        assertThat(logins7).isEqualTo(logins24 + 1);
        assertThat(body).doesNotContain("backup", "contacts", "validation");
    }

    @Test
    void zeroIsShownAsZero() throws Exception {
        String owner = fixture.signIn(OWNER, PASSWORD);
        jdbc.update("delete from users where status = 'INVITED'");
        String body = client.send("GET", "/api/v1/dashboard/summary", owner, null).body();
        assertThat(body).contains("\"invited\":0", "\"disabled\":0", "\"openSessions\":1");
    }

    @Test
    void itNeedsTheDashboardPermission() throws Exception {
        assertThat(client.send("GET", "/api/v1/dashboard/summary", null, null).statusCode()).isEqualTo(401);
        String member = fixture.signIn(MEMBER, PASSWORD);
        HttpResponse<String> denied = client.send("GET", "/api/v1/dashboard/summary", member, null);
        assertThat(denied.statusCode()).isEqualTo(403);
        assertThat(denied.body()).contains("\"code\":\"FORBIDDEN\"").doesNotContain("openSessions");

        Long id = users.findByEmail(MEMBER).orElseThrow().getId();
        permissions.replace(id, Set.of(Permission.parse("DASHBOARD:VIEW")), null);
        assertThat(client.send("GET", "/api/v1/dashboard/summary", member, null).statusCode()).isEqualTo(200);
        assertThat(client.send("GET", "/api/v1/permissions/catalogue", member, null).body())
                .contains("\"key\":\"DASHBOARD\"");
    }

    /** V7 gives everybody who had an account before it DASHBOARD:VIEW (not the Owner, who needs no row); V19 copies CONTACTS grants to LISTS. */
    @Test
    void theMigrationKeepsTheDashboardForExistingAccounts() {
        String schema = "m2_v7_check";
        FluentConfiguration flyway = Flyway.configure().dataSource(dataSource).schemas(schema).defaultSchema(schema)
                .locations("classpath:db/migration").cleanDisabled(false);
        try {
            flyway.target("6").load().migrate();
            jdbc.update("insert into " + schema + ".users (email, full_name, status, is_owner, password_hash) values "
                    + "('o@example.com', 'O', 'ACTIVE', true, 'x'), ('a@example.com', 'A', 'ACTIVE', false, 'x'), "
                    + "('i@example.com', 'I', 'INVITED', false, null)");
            jdbc.update("insert into " + schema + ".user_permissions (user_id, module, action) select id, "
                    + "'CONTACTS', 'VIEW' from " + schema + ".users where email = 'a@example.com'");
            Flyway.configure().dataSource(dataSource).schemas(schema).defaultSchema(schema)
                    .locations("classpath:db/migration").load().migrate();

            assertThat(jdbc.queryForList("select u.email || ' ' || p.module || ':' || p.action from " + schema
                    + ".user_permissions p join " + schema + ".users u on u.id = p.user_id order by 1", String.class))
                    .containsExactly("a@example.com CONTACTS:VIEW", "a@example.com DASHBOARD:VIEW",
                            // V19: a Contacts action gives the same Lists action (Lists used Contacts until then).
                            "a@example.com LISTS:VIEW", "i@example.com DASHBOARD:VIEW");
        } finally {
            flyway.load().clean();
            jdbc.execute("drop schema if exists " + schema + " cascade");
        }
    }

    private long count(String sql, Object... args) {
        Object[] params = new Object[args.length];
        for (int i = 0; i < args.length; i++) {
            params[i] = args[i] instanceof Instant t ? Timestamp.from(t) : args[i];
        }
        Long n = jdbc.queryForObject(sql, Long.class, params);
        return n == null ? 0 : n;
    }
}
