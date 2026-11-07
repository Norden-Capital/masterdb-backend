package ca.nordencapital.masterdb.auth.login;

import ca.nordencapital.masterdb.auth.permission.Permission;
import ca.nordencapital.masterdb.auth.permission.PermissionService;
import ca.nordencapital.masterdb.auth.twofactor.Totp;
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
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import static ca.nordencapital.masterdb.auth.login.AuthTestClient.preauth;
import static ca.nordencapital.masterdb.auth.login.AuthTestClient.token;
import static org.assertj.core.api.Assertions.assertThat;

/** M1.5: users list, invitations, disable/enable, 2FA reset, permissions, sessions, my account. */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@Import({MutableClock.Config.class, CapturingMailSender.Config.class})
@ExtendWith(OutputCaptureExtension.class)
class UsersFlowTest {

    static final Instant T0 = Instant.parse("2026-11-06T12:00:07Z");
    static final String PASSWORD = "correct-horse-battery-staple";
    static final String NEW_PASSWORD = "another-long-passphrase-42";
    static final String OWNER = "owner@example.com";
    static final String ADMIN = "admin@example.com";
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
    SecretCipher cipher;
    @Autowired
    PermissionService permissions;
    @Autowired
    CapturingMailSender mail;
    @Autowired
    JdbcTemplate jdbc;

    AuthTestClient client;
    TwoFactorFixture fixture;
    String owner;

    @BeforeEach
    void setUp() throws Exception {
        clock.set(T0);
        limiter.clear();
        mail.clear();
        users.deleteAll();
        if (hash == null) {
            hash = encoder.encode(PASSWORD);
        }
        users.save(User.newOwner(OWNER, "Olivia Owner", hash));
        users.save(AuthFlowTest.activeWith(ADMIN, "Adam Admin", hash));
        users.save(AuthFlowTest.activeWith(MEMBER, "Jane Member", hash));
        client = new AuthTestClient(port);
        fixture = new TwoFactorFixture(users, cipher, clock, client);
        for (String e : new String[] {OWNER, ADMIN, MEMBER}) {
            fixture.enrol(e);
        }
        // Adam may manage users and hold contact viewing, nothing else.
        grant(ADMIN, "USERS:VIEW", "USERS:CREATE", "USERS:EDIT", "USERS:DELETE", "CONTACTS:VIEW");
        owner = fixture.signIn(OWNER, PASSWORD);
    }

    @AfterEach
    void tearDown() {
        users.deleteAll();
        limiter.clear();
    }

    // ---- list ----------------------------------------------------------------------------

    @Test
    void listPagesSearchesAndFilters() throws Exception {
        HttpResponse<String> all = get("/api/v1/users?sort=email", owner);
        assertThat(all.statusCode()).isEqualTo(200);
        assertThat(all.body()).contains("\"totalItems\":3", "\"email\":\"admin@example.com\"", "\"isOwner\":true",
                "\"twoFactorEnabled\":true", "\"permissionCount\":5").doesNotContain("passwordHash", "totp");
        assertThat(all.body().indexOf("admin@")).isLessThan(all.body().indexOf("jane@"));

        assertThat(get("/api/v1/users?q=JANE", owner).body()).contains("\"totalItems\":1", "jane@example.com");
        assertThat(get("/api/v1/users?q=member", owner).body()).contains("\"totalItems\":1");
        assertThat(get("/api/v1/users?status=INVITED", owner).body()).contains("\"totalItems\":0");
        assertThat(get("/api/v1/users?size=2&page=1", owner).body()).contains("\"page\":1", "\"totalPages\":2");
        assertThat(get("/api/v1/users?sort=passwordHash", owner).statusCode()).isEqualTo(400);

        String member = fixture.signIn(MEMBER, PASSWORD);
        assertThat(get("/api/v1/users", member).statusCode()).isEqualTo(403);
    }

    // ---- invitations ----------------------------------------------------------------------

    @Test
    void inviteAcceptEnrolAndSignIn(CapturedOutput output) throws Exception {
        HttpResponse<String> invited = post("/api/v1/users/invites", owner,
                "{\"email\":\"New@Example.com\",\"fullName\":\"Nina New\",\"permissions\":[\"CONTACTS:EXPORT\"]}");
        assertThat(invited.statusCode()).isEqualTo(201);
        assertThat(invited.body()).contains("\"email\":\"new@example.com\"", "\"status\":\"INVITED\"",
                "\"inviteExpiresAt\":\"" + T0.plus(Duration.ofHours(72)) + "\"");
        assertThat(mail.last().to()).isEqualTo("new@example.com");
        assertThat(mail.last().subject()).isEqualTo("You are invited to MasterDB");
        assertThat(mail.last().text()).contains("Olivia Owner invited you", "https://db.nordencapital.ca/accept-invite#");
        String token = mail.lastToken();
        assertThat(mail.last().html()).contains("accept-invite#" + token);
        assertThat(output.getAll()).doesNotContain(token);
        assertThat(jdbc.queryForObject("select token_hash from account_tokens", String.class))
                .isEqualTo(AuthFlowTest.sha256(token));

        // Same email again: 409.
        assertThat(post("/api/v1/users/invites", owner, "{\"email\":\"new@example.com\"}").statusCode())
                .isEqualTo(409);
        assertThat(post("/api/v1/users/invites", owner, "{\"email\":\"jane@example.com\"}").statusCode())
                .isEqualTo(409);

        HttpResponse<String> check = anon("/api/v1/invites/check", "{\"token\":\"" + token + "\"}");
        assertThat(check.statusCode()).isEqualTo(200);
        assertThat(check.body()).contains("\"email\":\"new@example.com\"", "\"fullName\":\"Nina New\"");

        HttpResponse<String> weak = anon("/api/v1/invites/accept",
                "{\"token\":\"" + token + "\",\"fullName\":\"Nina New\",\"password\":\"short\"}");
        assertThat(weak.statusCode()).isEqualTo(400);
        assertThat(weak.body()).contains("VALIDATION_FAILED", "\"field\":\"password\"").doesNotContain("short\"");

        HttpResponse<String> accepted = anon("/api/v1/invites/accept",
                "{\"token\":\"" + token + "\",\"fullName\":\"Nina Newton\",\"password\":\"" + NEW_PASSWORD + "\"}");
        assertThat(accepted.statusCode()).isEqualTo(200);
        assertThat(accepted.body()).isEqualTo("{\"state\":\"TWO_FACTOR_SETUP_REQUIRED\"}");
        String pre = preauth(accepted);
        String secret = field(client.code("/api/v1/auth/2fa/setup", pre, null).body(), "secret");
        byte[] raw = TwoFactorFlowTest.base32Decode(secret);
        HttpResponse<String> done = client.code("/api/v1/auth/2fa/setup/confirm", pre,
                Totp.code(raw, Totp.step(clock.instant())));
        assertThat(done.statusCode()).isEqualTo(200);
        assertThat(done.body()).contains("\"fullName\":\"Nina Newton\"",
                "\"permissions\":[\"CONTACTS:VIEW\",\"CONTACTS:EXPORT\"]", "recoveryCodes");

        // The link is used up.
        assertThat(anon("/api/v1/invites/check", "{\"token\":\"" + token + "\"}").statusCode()).isEqualTo(410);
        assertThat(users.findByEmail("new@example.com").orElseThrow().getStatus()).isEqualTo(UserStatus.ACTIVE);
    }

    @Test
    void invitationsExpireAndCanBeResentOrCancelled() throws Exception {
        String id = field(post("/api/v1/users/invites", owner, "{\"email\":\"late@example.com\"}").body(), "publicId");
        String first = mail.lastToken();

        HttpResponse<String> resent = post("/api/v1/users/" + id + "/invite/resend", owner, null);
        assertThat(resent.statusCode()).isEqualTo(200);
        String second = mail.lastToken();
        assertThat(second).isNotEqualTo(first);
        HttpResponse<String> old = anon("/api/v1/invites/check", "{\"token\":\"" + first + "\"}");
        assertThat(old.statusCode()).isEqualTo(410);
        assertThat(old.body()).contains("\"code\":\"LINK_INVALID\"");
        assertThat(anon("/api/v1/invites/check", "{\"token\":\"" + second + "\"}").statusCode()).isEqualTo(200);

        clock.advance(Duration.ofHours(72));
        assertThat(anon("/api/v1/invites/check", "{\"token\":\"" + second + "\"}").statusCode()).isEqualTo(410);
        owner = fixture.signIn(OWNER, PASSWORD); // the old session went idle meanwhile

        assertThat(client.send("DELETE", "/api/v1/users/" + id + "/invite", owner, null).statusCode()).isEqualTo(204);
        assertThat(users.findByEmail("late@example.com")).isEmpty();
    }

    // ---- rules no permission can lift --------------------------------------------------------

    @Test
    void nonOwnersCanOnlyGrantWhatTheyHold() throws Exception {
        String admin = fixture.signIn(ADMIN, PASSWORD);
        HttpResponse<String> tooMuch = post("/api/v1/users/invites", admin,
                "{\"email\":\"x@example.com\",\"permissions\":[\"CONTACTS:EXPORT\"]}");
        assertThat(tooMuch.statusCode()).isEqualTo(403);
        assertThat(tooMuch.body()).contains("FORBIDDEN");
        assertThat(post("/api/v1/users/invites", admin,
                "{\"email\":\"x@example.com\",\"permissions\":[\"CONTACTS:VIEW\"]}").statusCode()).isEqualTo(201);

        String jane = id(MEMBER);
        assertThat(put("/api/v1/users/" + jane + "/permissions", admin, "{\"permissions\":[\"BACKUPS:RUN\"]}")
                .statusCode()).isEqualTo(403);
        HttpResponse<String> ok = put("/api/v1/users/" + jane + "/permissions", admin,
                "{\"permissions\":[\"CONTACTS:VIEW\"]}");
        assertThat(ok.statusCode()).isEqualTo(200);
        assertThat(ok.body()).isEqualTo("{\"permissions\":[\"CONTACTS:VIEW\"]}");
        // Removing something Adam does not hold is refused too.
        grant(MEMBER, "SETTINGS:EDIT");
        assertThat(put("/api/v1/users/" + jane + "/permissions", admin, "{\"permissions\":[]}").statusCode())
                .isEqualTo(403);
        assertThat(put("/api/v1/users/" + jane + "/permissions", admin, "{\"permissions\":[\"NOPE:VIEW\"]}")
                .statusCode()).isEqualTo(400);
    }

    @Test
    void theOwnerAndYourselfAreOffLimits() throws Exception {
        String admin = fixture.signIn(ADMIN, PASSWORD);
        for (String path : new String[] {"/disable", "/2fa/reset"}) {
            assertThat(post("/api/v1/users/" + id(OWNER) + path, admin, null).statusCode()).isEqualTo(403);
            assertThat(post("/api/v1/users/" + id(ADMIN) + path, admin, null).statusCode()).isEqualTo(409);
        }
        assertThat(put("/api/v1/users/" + id(OWNER) + "/permissions", admin, "{\"permissions\":[]}").statusCode())
                .isEqualTo(403);
        assertThat(client.send("DELETE", "/api/v1/users/" + id(OWNER) + "/sessions", admin, null).statusCode())
                .isEqualTo(403);
        assertThat(client.me(owner).statusCode()).isEqualTo(200);
    }

    // ---- disable, enable, 2FA reset, sessions ---------------------------------------------------

    @Test
    void disablingSignsOutAndBlocksLoginUntilEnabled() throws Exception {
        String member = fixture.signIn(MEMBER, PASSWORD);
        HttpResponse<String> disabled = post("/api/v1/users/" + id(MEMBER) + "/disable", owner, null);
        assertThat(disabled.statusCode()).isEqualTo(200);
        assertThat(disabled.body()).contains("\"status\":\"DISABLED\"");
        assertThat(client.me(member).statusCode()).isEqualTo(401);
        assertThat(client.login(MEMBER, PASSWORD).body()).contains("INVALID_CREDENTIALS");

        assertThat(post("/api/v1/users/" + id(MEMBER) + "/enable", owner, null).body())
                .contains("\"status\":\"ACTIVE\"");
        assertThat(fixture.signIn(MEMBER, PASSWORD)).isNotNull();
    }

    @Test
    void aTwoFactorResetMeansEnrollingAgain() throws Exception {
        String member = fixture.signIn(MEMBER, PASSWORD);
        assertThat(post("/api/v1/users/" + id(MEMBER) + "/2fa/reset", owner, null).body())
                .contains("\"twoFactorEnabled\":false");
        assertThat(client.me(member).statusCode()).isEqualTo(401);
        assertThat(client.login(MEMBER, PASSWORD).body()).isEqualTo("{\"state\":\"TWO_FACTOR_SETUP_REQUIRED\"}");
    }

    @Test
    void anAdminCanListAndEndSomeonesSessions() throws Exception {
        String first = fixture.signIn(MEMBER, PASSWORD);
        String second = fixture.signIn(MEMBER, PASSWORD);
        HttpResponse<String> list = get("/api/v1/users/" + id(MEMBER) + "/sessions", owner);
        assertThat(list.body()).contains("\"ip\":\"127.0.0.1\"", "\"userAgent\":\"AuthFlowTest/1.0\"");
        String sessionId = jdbc.queryForObject("select public_id::text from user_sessions where token_hash = ?",
                String.class, AuthFlowTest.sha256(first));
        assertThat(client.send("DELETE", "/api/v1/users/" + id(MEMBER) + "/sessions/" + sessionId, owner, null)
                .statusCode()).isEqualTo(204);
        assertThat(client.me(first).statusCode()).isEqualTo(401);
        assertThat(client.me(second).statusCode()).isEqualTo(200);

        assertThat(client.send("DELETE", "/api/v1/users/" + id(MEMBER) + "/sessions", owner, null).body())
                .isEqualTo("{\"sessionsEnded\":1}");
        assertThat(client.me(second).statusCode()).isEqualTo(401);
    }

    // ---- my account --------------------------------------------------------------------------

    @Test
    void changingMyPasswordChecksTheCurrentOneAndSignsOutTheOthers() throws Exception {
        String here = fixture.signIn(MEMBER, PASSWORD);
        String elsewhere = fixture.signIn(MEMBER, PASSWORD);

        HttpResponse<String> wrong = post("/api/v1/account/password", here,
                "{\"currentPassword\":\"not-my-password\",\"newPassword\":\"" + NEW_PASSWORD + "\"}");
        assertThat(wrong.statusCode()).isEqualTo(400);
        assertThat(wrong.body()).contains("CURRENT_PASSWORD_INCORRECT");
        assertThat(users.findByEmail(MEMBER).orElseThrow().getFailedLoginAttempts()).isEqualTo(1);

        assertThat(post("/api/v1/account/password", here,
                "{\"currentPassword\":\"" + PASSWORD + "\",\"newPassword\":\"" + MEMBER + "\"}").statusCode())
                .isEqualTo(400);

        assertThat(post("/api/v1/account/password", here,
                "{\"currentPassword\":\"" + PASSWORD + "\",\"newPassword\":\"" + NEW_PASSWORD + "\"}").statusCode())
                .isEqualTo(204);
        assertThat(client.me(here).statusCode()).isEqualTo(200);
        assertThat(client.me(elsewhere).statusCode()).isEqualTo(401);
        assertThat(client.login(MEMBER, PASSWORD).statusCode()).isEqualTo(401);
        assertThat(fixture.signIn(MEMBER, NEW_PASSWORD)).isNotNull();
    }

    @Test
    void mySessionsAndLogOutEverywhere() throws Exception {
        String here = fixture.signIn(MEMBER, PASSWORD);
        String elsewhere = fixture.signIn(MEMBER, PASSWORD);
        String third = fixture.signIn(MEMBER, PASSWORD);

        HttpResponse<String> mine = get("/api/v1/account/sessions", here);
        assertThat(mine.body()).contains("\"current\":true", "\"current\":false");
        assertThat(mine.body().split("\"current\":true", -1)).hasSize(2);

        assertThat(post("/api/v1/account/sessions/revoke-others", third, null).body())
                .isEqualTo("{\"sessionsEnded\":2}");
        assertThat(client.me(here).statusCode()).isEqualTo(401);
        assertThat(client.me(elsewhere).statusCode()).isEqualTo(401);
        assertThat(client.me(third).statusCode()).isEqualTo(200);

        HttpResponse<String> everywhere = post("/api/v1/account/logout-everywhere", third, null);
        assertThat(everywhere.body()).isEqualTo("{\"sessionsEnded\":1}");
        assertThat(AuthTestClient.sessionCookies(everywhere)).singleElement()
                .satisfies(c -> assertThat(c).contains("Max-Age=0"));
        assertThat(client.me(third).statusCode()).isEqualTo(401);
    }

    @Test
    void newRecoveryCodesNeedACurrentCode() throws Exception {
        String member = fixture.signIn(MEMBER, PASSWORD);
        assertThat(get("/api/v1/account/2fa", member).body()).contains("\"enabled\":true");
        HttpResponse<String> wrong = post("/api/v1/account/2fa/recovery-codes", member, "{\"code\":\"000000\"}");
        assertThat(wrong.statusCode()).isEqualTo(400);
        assertThat(wrong.body()).contains("INVALID_TWO_FACTOR_CODE");
        HttpResponse<String> ok = post("/api/v1/account/2fa/recovery-codes", member,
                "{\"code\":\"" + fixture.nextCode(MEMBER) + "\"}");
        assertThat(ok.statusCode()).isEqualTo(200);
        assertThat(ok.body().split("\"[a-z2-9]{5}-[a-z2-9]{5}\"", -1)).hasSize(11);
        assertThat(get("/api/v1/account/2fa", member).body()).contains("\"recoveryCodesRemaining\":10");
    }

    // ---- helpers ------------------------------------------------------------------------------

    private void grant(String email, String... values) {
        Long id = users.findByEmail(email).orElseThrow().getId();
        permissions.replace(id, Set.of(values).stream().map(Permission::parse).collect(Collectors.toSet()), null);
    }

    private String id(String email) {
        return users.findByEmail(email).orElseThrow().getPublicId().toString();
    }

    private HttpResponse<String> get(String path, String token) throws Exception {
        return client.send("GET", path, token, null);
    }

    private HttpResponse<String> post(String path, String token, String body) throws Exception {
        return client.send("POST", path, token, body);
    }

    private HttpResponse<String> put(String path, String token, String body) throws Exception {
        return client.send("PUT", path, token, body);
    }

    private HttpResponse<String> anon(String path, String body) throws Exception {
        return client.send("POST", path, null, body);
    }

    static String field(String json, String name) {
        Matcher m = Pattern.compile("\"" + name + "\":\"([^\"]*)\"").matcher(json);
        assertThat(m.find()).as(name + " in " + json).isTrue();
        return m.group(1);
    }
}
