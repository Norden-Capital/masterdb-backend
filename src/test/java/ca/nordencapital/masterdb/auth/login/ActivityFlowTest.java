package ca.nordencapital.masterdb.auth.login;

import ca.nordencapital.masterdb.activity.ActivityQuery;
import ca.nordencapital.masterdb.auth.permission.Permission;
import ca.nordencapital.masterdb.auth.permission.PermissionService;
import ca.nordencapital.masterdb.auth.user.User;
import ca.nordencapital.masterdb.auth.user.UserRepository;
import ca.nordencapital.masterdb.crypto.SecretCipher;
import ca.nordencapital.masterdb.web.security.LoginRateLimiter;
import ca.nordencapital.testsupport.CapturingMailSender;
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
import java.sql.Timestamp;
import java.time.Duration;
import java.time.Instant;
import java.util.Set;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;

/** M1.8: what is recorded, the list with filters, CSV export, permissions and retention. */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@Import({MutableClock.Config.class, CapturingMailSender.Config.class})
class ActivityFlowTest {

    static final Instant T0 = Instant.parse("2026-11-06T12:00:07Z");
    static final String PASSWORD = "correct-horse-battery-staple";
    static final String OWNER = "owner@example.com";
    static final String MEMBER = "jane@example.com";

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
    ActivityQuery activity;
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
        jdbc.update("delete from activity_log");
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
    void sensitiveActionsAreRecordedWithoutSecrets() throws Exception {
        client.login("nobody@example.com", "wrong-password-1", "X-Request-Id", "req-unknown");
        client.login(MEMBER, "wrong-password-2");
        String member = fixture.signIn(MEMBER, PASSWORD);
        client.logout(member);
        String owner = fixture.signIn(OWNER, PASSWORD);
        String jane = users.findByEmail(MEMBER).orElseThrow().getPublicId().toString();
        client.send("PUT", "/api/v1/users/" + jane + "/permissions", owner, "{\"permissions\":[\"CONTACTS:EXPORT\"]}");
        client.send("POST", "/api/v1/users/" + jane + "/disable", owner, null);
        client.send("POST", "/api/v1/users/invites", owner, "{\"email\":\"new@example.com\"}");

        assertThat(actions()).containsExactly("LOGIN_FAILED", "LOGIN_FAILED", "LOGIN_SUCCEEDED", "LOGOUT",
                "LOGIN_SUCCEEDED", "PERMISSIONS_CHANGED", "USER_DISABLED", "USER_INVITED");

        // A made-up email is stored masked; the request id and address are kept.
        assertThat(jdbc.queryForMap("select * from activity_log where request_id = 'req-unknown'"))
                .containsEntry("target_label", "n***@example.com").containsEntry("ip", "127.0.0.1")
                .containsEntry("action", "LOGIN_FAILED");
        assertThat(jdbc.queryForObject("select details::text from activity_log where action = 'PERMISSIONS_CHANGED'",
                String.class)).isEqualTo("{\"added\": [\"CONTACTS:VIEW\", \"CONTACTS:EXPORT\"], \"removed\": []}");
        assertThat(jdbc.queryForObject("select actor_label || '>' || target_label from activity_log "
                + "where action = 'USER_DISABLED'", String.class)).isEqualTo("owner@example.com>jane@example.com");

        String everything = String.join("\n", jdbc.queryForList("select activity_log::text from activity_log",
                String.class));
        assertThat(everything).doesNotContain(PASSWORD, "wrong-password", member, owner,
                AuthFlowTest.sha256(member));
    }

    @Test
    void theListFiltersAndNeedsThePermission() throws Exception {
        client.login("nobody@example.com", "wrong-password-1");
        clock.advance(Duration.ofMinutes(5));
        String member = fixture.signIn(MEMBER, PASSWORD);
        String owner = fixture.signIn(OWNER, PASSWORD);

        HttpResponse<String> all = client.send("GET", "/api/v1/activity", owner, null);
        assertThat(all.statusCode()).isEqualTo(200);
        assertThat(all.body()).contains("\"totalItems\":3", "\"action\":\"LOGIN_SUCCEEDED\"",
                "\"actorLabel\":\"owner@example.com\"", "\"details\":{\"session\":");
        // Newest first by default; oldest first on request.
        assertThat(all.body().indexOf("owner@example.com")).isLessThan(all.body().indexOf("n***@example.com"));
        String asc = client.send("GET", "/api/v1/activity?sort=occurredAt,asc", owner, null).body();
        assertThat(asc.indexOf("n***@example.com")).isLessThan(asc.indexOf("owner@example.com"));

        assertThat(client.send("GET", "/api/v1/activity?action=LOGIN_FAILED", owner, null).body())
                .contains("\"totalItems\":1");
        String jane = users.findByEmail(MEMBER).orElseThrow().getPublicId().toString();
        assertThat(client.send("GET", "/api/v1/activity?user=" + jane, owner, null).body())
                .contains("\"totalItems\":1");
        assertThat(client.send("GET", "/api/v1/activity?q=JANE", owner, null).body()).contains("\"totalItems\":1");
        assertThat(client.send("GET", "/api/v1/activity?to=" + T0.plusSeconds(60), owner, null).body())
                .contains("\"totalItems\":1");
        assertThat(client.send("GET", "/api/v1/activity?from=" + T0.plusSeconds(60), owner, null).body())
                .contains("\"totalItems\":2");
        assertThat(client.send("GET", "/api/v1/activity?action=NOPE", owner, null).statusCode()).isEqualTo(400);

        assertThat(client.send("GET", "/api/v1/activity", member, null).statusCode()).isEqualTo(403);
        grant(MEMBER, "ACTIVITY_LOG:VIEW");
        assertThat(client.send("GET", "/api/v1/activity", member, null).statusCode()).isEqualTo(200);
        assertThat(client.send("GET", "/api/v1/activity/export", member, null).statusCode()).isEqualTo(403);
    }

    @Test
    void theCsvExportIsCompleteSafeAndItselfLogged() throws Exception {
        client.login("nobody@example.com", "wrong-password-1");
        String owner = fixture.signIn(OWNER, PASSWORD);
        HttpResponse<String> csv = client.send("GET", "/api/v1/activity/export?action=LOGIN_FAILED", owner, null);
        assertThat(csv.statusCode()).isEqualTo(200);
        assertThat(csv.headers().firstValue("Content-Type")).hasValueSatisfying(ct -> assertThat(ct)
                .startsWith("text/csv"));
        assertThat(csv.headers().firstValue("Content-Disposition"))
                .hasValue("attachment; filename=\"activity-log-2026-11-06.csv\"");
        String[] lines = csv.body().split("\r\n");
        assertThat(lines[0]).isEqualTo("﻿occurred_at,action,actor,actor_id,target,target_id,ip,user_agent,"
                + "request_id,details");
        assertThat(lines).hasSize(2);
        assertThat(lines[1]).contains("\"LOGIN_FAILED\"", "\"n***@example.com\"", "\"127.0.0.1\"",
                "\"{\"\"reason\"\":\"\"unknown_account\"\"}\"");
        assertThat(actions()).last().isEqualTo("ACTIVITY_EXPORTED");
    }

    @Test
    void entriesOlderThanAYearAreDeleted() {
        jdbc.update("insert into activity_log (occurred_at, action) values (?, 'LOGOUT'), (?, 'LOGOUT')",
                Timestamp.from(T0.minus(Duration.ofDays(366))), Timestamp.from(T0.minus(Duration.ofDays(364))));
        assertThat(activity.prune()).isEqualTo(1);
        assertThat(jdbc.queryForObject("select count(*) from activity_log", Integer.class)).isEqualTo(1);
    }

    private java.util.List<String> actions() {
        return jdbc.queryForList("select action from activity_log order by id", String.class);
    }

    private void grant(String email, String... values) {
        Long id = users.findByEmail(email).orElseThrow().getId();
        permissions.replace(id, Set.of(values).stream().map(Permission::parse).collect(Collectors.toSet()), null);
    }
}
