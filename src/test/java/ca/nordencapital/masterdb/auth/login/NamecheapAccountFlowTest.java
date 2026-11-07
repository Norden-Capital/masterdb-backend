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
import java.time.Instant;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/** DNS job 1: the Namecheap account, against a local fake of the Namecheap API (never the real one). */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@Import({MutableClock.Config.class, CapturingMailSender.Config.class})
@ExtendWith(OutputCaptureExtension.class)
class NamecheapAccountFlowTest {

    static final Instant T0 = Instant.parse("2026-11-07T09:00:03Z");
    static final String PASSWORD = "correct-horse-battery-staple";
    static final String OWNER = "owner@example.com";
    static final String MEMBER = "jane@example.com";
    static final String PATH = "/api/v1/dns/namecheap/account";
    /** Fake keys: the shape of a Namecheap key, nothing more. */
    static final String KEY = "FAKEKEYtest0000fake1111nope2222";
    static final String KEY2 = "FAKEKEYtest3333fake4444nope5555";

    private static String hash;

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry registry) {
        TestDatabase.register(registry);
        NamecheapStub.register(registry);
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
    void setUp() throws Exception {
        clock.set(T0);
        limiter.clear();
        loginService.clearUnknownAccountAttempts();
        NamecheapStub.reset();
        users.deleteAll();
        jdbc.update("delete from namecheap_account");
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
        owner = fixture.signIn(OWNER, PASSWORD);
    }

    @AfterEach
    void tearDown() {
        users.deleteAll();
        jdbc.update("delete from namecheap_account");
        jdbc.update("delete from activity_log");
        limiter.clear();
        NamecheapStub.reset();
    }

    HttpResponse<String> save(String token, String apiUser, String username, String apiKey) throws Exception {
        String body = "{\"apiUser\":\"" + apiUser + "\",\"username\":\"" + username + "\""
                + (apiKey == null ? "" : ",\"apiKey\":\"" + apiKey + "\"") + "}";
        return client.send("PUT", PATH, token, body);
    }

    @Test
    void withoutAnAccountThePageSaysSoAndTestIs409() throws Exception {
        HttpResponse<String> get = client.send("GET", PATH, owner, null);
        assertThat(get.statusCode()).isEqualTo(200);
        assertThat(get.body()).contains("\"configured\":false", "\"clientIp\":\"203.0.113.10\"");
        HttpResponse<String> test = client.send("POST", PATH + "/test", owner, null);
        assertThat(test.statusCode()).isEqualTo(409);
        assertThat(test.body()).contains("\"code\":\"NAMECHEAP_NOT_CONFIGURED\"");
        assertThat(NamecheapStub.requests()).isEmpty();
    }

    @Test
    void addViewReplaceAndRemoveWithTheKeyWriteOnly(CapturedOutput output) throws Exception {
        HttpResponse<String> noKey = save(owner, "testuser", "", null);
        assertThat(noKey.statusCode()).isEqualTo(400);
        assertThat(noKey.body()).contains("\"field\":\"apiKey\"", "is required");
        HttpResponse<String> badKey = save(owner, "testuser", "", "short!" + KEY);
        assertThat(badKey.statusCode()).isEqualTo(400);
        assertThat(badKey.body()).doesNotContain(KEY);

        HttpResponse<String> added = save(owner, "testuser", "", KEY);
        assertThat(added.statusCode()).isEqualTo(200);
        assertThat(added.body()).contains("\"configured\":true", "\"apiUser\":\"testuser\"",
                "\"username\":\"testuser\"", "\"apiKeySet\":true").doesNotContain(KEY);
        String stored = jdbc.queryForObject("select api_key_enc from namecheap_account", String.class);
        assertThat(stored).startsWith("v1:").doesNotContain(KEY);
        assertThat(client.send("GET", PATH, owner, null).body()).doesNotContain(KEY).contains("\"apiKeySet\":true");

        // Change the username, keep the key: the next call still sends the first key.
        NamecheapStub.answer("namecheap.domains.getList", "getList-ok");
        assertThat(save(owner, "testuser", "otheruser", "").statusCode()).isEqualTo(200);
        assertThat(client.send("POST", PATH + "/test", owner, null).statusCode()).isEqualTo(200);
        Map<String, String> sent = NamecheapStub.requests().getLast();
        assertThat(sent).containsEntry("ApiKey", KEY).containsEntry("UserName", "otheruser")
                .containsEntry("ApiUser", "testuser").containsEntry("ClientIp", "203.0.113.10")
                .containsEntry("Command", "namecheap.domains.getList");

        // Replace the key: the last test is forgotten and the new key is sent.
        HttpResponse<String> replaced = save(owner, "testuser", "otheruser", KEY2);
        assertThat(replaced.body()).doesNotContain(KEY2).doesNotContain("lastTest");
        client.send("POST", PATH + "/test", owner, null);
        assertThat(NamecheapStub.requests().getLast()).containsEntry("ApiKey", KEY2);

        assertThat(client.send("DELETE", PATH, owner, null).statusCode()).isEqualTo(204);
        assertThat(client.send("GET", PATH, owner, null).body()).contains("\"configured\":false");
        assertThat(client.send("DELETE", PATH, owner, null).statusCode()).isEqualTo(404);

        assertThat(jdbc.queryForList("select action from activity_log order by id", String.class))
                .containsSubsequence("NAMECHEAP_ACCOUNT_SAVED", "NAMECHEAP_ACCOUNT_SAVED",
                        "NAMECHEAP_CONNECTION_TESTED", "NAMECHEAP_ACCOUNT_SAVED", "NAMECHEAP_CONNECTION_TESTED",
                        "NAMECHEAP_ACCOUNT_REMOVED");
        String everything = String.join("\n", jdbc.queryForList("select details::text || coalesce(target_label,'') "
                + "from activity_log", String.class));
        assertThat(everything).doesNotContain(KEY).doesNotContain(KEY2).contains("\"keyReplaced\": true");
        assertThat(output.getAll()).doesNotContain(KEY).doesNotContain(KEY2);
    }

    @Test
    void testConnectionSucceeds() throws Exception {
        save(owner, "testuser", "", KEY);
        NamecheapStub.answer("namecheap.domains.getList", "getList-ok");
        HttpResponse<String> res = client.send("POST", PATH + "/test", owner, null);
        assertThat(res.statusCode()).isEqualTo(200);
        assertThat(res.body()).contains("\"ok\":true", "\"domainCount\":3", "3 domains");
        assertThat(client.send("GET", PATH, owner, null).body())
                .contains("\"lastTest\":{\"at\":\"2026-11-07T09:00:03Z\",\"ok\":true");
    }

    @Test
    void ipNotWhitelistedGivesAClearMessage(CapturedOutput output) throws Exception {
        save(owner, "testuser", "", KEY);
        NamecheapStub.answer("namecheap.domains.getList", "error-ip-not-whitelisted");
        HttpResponse<String> res = client.send("POST", PATH + "/test", owner, null);
        assertThat(res.statusCode()).isEqualTo(200);
        assertThat(res.body()).contains("\"ok\":false", "\"code\":\"NAMECHEAP_IP_NOT_WHITELISTED\"",
                "203.0.113.10", "whitelisted IPs");
        assertThat(client.send("GET", PATH, owner, null).body()).contains("\"ok\":false");
        assertThat(jdbc.queryForObject("select details::text from activity_log where action = "
                + "'NAMECHEAP_CONNECTION_TESTED'", String.class)).contains("NAMECHEAP_IP_NOT_WHITELISTED");
        assertThat(output.getAll()).contains("refused: error 1011150").doesNotContain(KEY);
    }

    @Test
    void invalidKeyGivesAClearMessage() throws Exception {
        save(owner, "testuser", "", KEY);
        NamecheapStub.answer("namecheap.domains.getList", "error-invalid-key");
        HttpResponse<String> res = client.send("POST", PATH + "/test", owner, null);
        assertThat(res.body()).contains("\"ok\":false", "\"code\":\"NAMECHEAP_INVALID_KEY\"", "API access must be ON");
    }

    @Test
    void aKeyQuotedBackByNamecheapIsHidden(CapturedOutput output) throws Exception {
        save(owner, "testuser", "", KEY);
        NamecheapStub.answer("namecheap.domains.getList", "error-echoes-key");
        HttpResponse<String> res = client.send("POST", PATH + "/test", owner, null);
        assertThat(res.body()).contains("\"code\":\"NAMECHEAP_ERROR\"", "[hidden]").doesNotContain(KEY);
        assertThat(client.send("GET", PATH, owner, null).body()).doesNotContain(KEY);
        assertThat(output.getAll()).doesNotContain(KEY);
    }

    @Test
    void permissionsAreCheckedOnEveryCall() throws Exception {
        save(owner, "testuser", "", KEY);
        NamecheapStub.answer("namecheap.domains.getList", "getList-ok");
        String member = fixture.signIn(MEMBER, PASSWORD);
        Long id = users.findByEmail(MEMBER).orElseThrow().getId();

        assertThat(client.send("GET", PATH, null, null).statusCode()).isEqualTo(401);
        for (String[] call : new String[][] {{"GET", PATH}, {"PUT", PATH}, {"DELETE", PATH}, {"POST", PATH + "/test"}}) {
            HttpResponse<String> res = client.send(call[0], call[1], member, call[0].equals("PUT") ? "{}" : null);
            assertThat(res.statusCode()).as(call[0] + " " + call[1]).isEqualTo(403);
            assertThat(res.body()).contains("\"code\":\"FORBIDDEN\"");
        }

        permissions.replace(id, Set.of(Permission.parse("DNS:VIEW")), null);
        assertThat(client.send("GET", PATH, member, null).statusCode()).isEqualTo(200);
        assertThat(save(member, "x", "", KEY2).statusCode()).isEqualTo(403);
        assertThat(client.send("POST", PATH + "/test", member, null).statusCode()).isEqualTo(403);

        permissions.replace(id, Set.of(Permission.parse("DNS:EDIT"), Permission.parse("DNS:RUN")), null);
        assertThat(save(member, "testuser", "", "").statusCode()).isEqualTo(200);
        assertThat(client.send("POST", PATH + "/test", member, null).statusCode()).isEqualTo(200);
        assertThat(client.send("DELETE", PATH, member, null).statusCode()).isEqualTo(403);
        assertThat(NamecheapStub.requests()).hasSize(1);
    }
}
