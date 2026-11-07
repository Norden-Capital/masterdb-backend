package ca.nordencapital.masterdb.auth.login;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;

import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/** Server management job 1: MasterDB's SSH key, servers, connect with trust-on-first-use pinning. */
@ExtendWith(OutputCaptureExtension.class)
class ServerFlowTest extends ServerFlowTestBase {

    @Test
    void thePrivateKeyIsNeverInAResponseOrALogLine(CapturedOutput output) throws Exception {
        List<String> bodies = new ArrayList<>();
        HttpResponse<String> key = get("/api/v1/servers/ssh-key");
        bodies.add(key.body());
        assertThat(key.body()).contains("\"publicKey\":\"ssh-ed25519 AAAA", " masterdb\"", "\"fingerprint\":\"SHA256:",
                "\"installCommand\":\"mkdir -p ~/.ssh");
        // Same key on every call: one key pair for the app.
        assertThat(get("/api/v1/servers/ssh-key").body()).isEqualTo(key.body());

        String id = connectedServer("alpha");
        bodies.add(get("/api/v1/servers/" + id).body());
        bodies.add(get("/api/v1/servers").body());
        bodies.add(post("/api/v1/servers/" + id + "/connect", null).body());
        bodies.add(get("/api/v1/activity?size=100").body());

        String stored = jdbc.queryForObject("select private_key_enc from ssh_identity", String.class);
        assertThat(stored).startsWith("v1:").doesNotContain("PRIVATE KEY");
        String pem = new String(cipher.decrypt(stored, "ssh:identity"), StandardCharsets.UTF_8);
        assertThat(pem).startsWith("-----BEGIN OPENSSH PRIVATE KEY-----");
        // Every base64 line of the private key, and the header, appear nowhere.
        List<String> secretLines = pem.lines().filter(l -> !l.startsWith("-----") && l.length() > 20).toList();
        assertThat(secretLines).isNotEmpty();
        String everything = String.join("\n", bodies) + "\n" + output.getAll();
        assertThat(everything).doesNotContain("PRIVATE KEY", stored);
        for (String line : secretLines) {
            assertThat(everything).doesNotContain(line);
        }
    }

    @Test
    void addListEditDeleteWithValidation() throws Exception {
        HttpResponse<String> bad = post("/api/v1/servers", "{\"name\":\"\",\"ip\":\"999.1.1.1\",\"sshPort\":70000,"
                + "\"sshUser\":\"Root User\"}");
        assertThat(bad.statusCode()).isEqualTo(400);
        assertThat(bad.body()).contains("\"field\":\"name\"", "\"field\":\"ip\"", "\"field\":\"sshPort\"",
                "\"field\":\"sshUser\"", "\"field\":\"expiresOn\"");

        String domain = addManual("mail-one.example");
        HttpResponse<String> created = post("/api/v1/servers", "{\"name\":\"Probe 1\",\"ip\":\"127.0.0.1\","
                + "\"expiresOn\":\"2026-11-15\",\"notes\":\"Contabo S\",\"domainId\":\"" + domain + "\"}");
        assertThat(created.statusCode()).as(created.body()).isEqualTo(201);
        assertThat(created.body()).contains("\"sshPort\":22", "\"sshUser\":\"root\"", "\"daysLeft\":8",
                "\"connectionStatus\":\"NEW\"", "\"domain\":{\"publicId\":\"" + domain + "\",\"name\":\"mail-one.example\"}")
                .doesNotContain("hostKey");
        String id = id(created.body());

        // Same address twice, or the same domain on two servers: 409.
        assertThat(post("/api/v1/servers", "{\"name\":\"Dup\",\"ip\":\"127.0.0.1\",\"expiresOn\":\"2027-01-01\"}")
                .statusCode()).isEqualTo(409);
        HttpResponse<String> twice = post("/api/v1/servers", "{\"name\":\"Other\",\"ip\":\"127.0.0.2\","
                + "\"expiresOn\":\"2027-01-01\",\"domainId\":\"" + domain + "\"}");
        assertThat(twice.statusCode()).isEqualTo(409);
        assertThat(twice.body()).contains("mail-one.example is already linked to another server");

        assertThat(get("/api/v1/servers?q=probe").body()).contains("\"totalItems\":1");
        assertThat(get("/api/v1/servers?expiry=DAYS_14").body()).contains("\"totalItems\":1");
        assertThat(get("/api/v1/servers?expiry=EXPIRED").body()).contains("\"totalItems\":0");
        assertThat(get("/api/v1/servers?connection=CONNECTED").body()).contains("\"totalItems\":0");
        assertThat(get("/api/v1/servers?sort=nope").statusCode()).isEqualTo(400);

        HttpResponse<String> edited = client.send("PUT", "/api/v1/servers/" + id, owner, "{\"name\":\"Probe 1b\","
                + "\"ip\":\"127.0.0.1\",\"sshPort\":2200,\"sshUser\":\"deploy\",\"expiresOn\":\"2027-06-01\"}");
        assertThat(edited.statusCode()).as(edited.body()).isEqualTo(200);
        assertThat(edited.body()).contains("\"name\":\"Probe 1b\"", "\"sshPort\":2200", "\"sshUser\":\"deploy\"")
                .doesNotContain("\"domain\"");

        assertThat(client.send("DELETE", "/api/v1/servers/" + id, owner, null).statusCode()).isEqualTo(204);
        assertThat(get("/api/v1/servers/" + id).statusCode()).isEqualTo(404);
        assertThat(jdbc.queryForList("select action from activity_log where action like 'SERVER_%' order by id",
                String.class)).containsExactly("SERVER_ADDED", "SERVER_UPDATED", "SERVER_DELETED");
    }

    @Test
    void firstUseShowsTheFingerprintWithoutLoggingInThenTrustPins() throws Exception {
        String id = addServer("alpha");
        HttpResponse<String> first = post("/api/v1/servers/" + id + "/connect", null);
        assertThat(first.statusCode()).isEqualTo(200);
        assertThat(first.body()).contains("\"outcome\":\"KEY_PENDING\"", "\"connectionStatus\":\"KEY_PENDING\"",
                "\"presentedKey\":{\"type\":\"ssh-ed25519\",\"fingerprint\":\"" + SSH.fingerprint() + "\"")
                .doesNotContain("\"hostKey\"");
        // Only looked at the key: no login attempt, no command.
        assertThat(SSH.logins()).isEmpty();
        assertThat(SSH.exchanges()).isEmpty();

        HttpResponse<String> wrong = post("/api/v1/servers/" + id + "/host-key/trust",
                "{\"fingerprint\":\"SHA256:notTheOneThatWasShown\"}");
        assertThat(wrong.statusCode()).isEqualTo(409);

        HttpResponse<String> trusted = post("/api/v1/servers/" + id + "/host-key/trust",
                "{\"fingerprint\":\"" + SSH.fingerprint() + "\"}");
        assertThat(trusted.statusCode()).as(trusted.body()).isEqualTo(200);
        assertThat(trusted.body()).contains("\"outcome\":\"CONNECTED\"", "\"os\":\"Ubuntu 24.04.1 LTS\"",
                "\"privileged\":true", "\"hostKey\":{\"type\":\"ssh-ed25519\",\"fingerprint\":\"" + SSH.fingerprint())
                .doesNotContain("presentedKey");
        assertThat(SSH.exchanges()).hasSize(1);

        // Trusted once: later connects never ask again.
        String again = post("/api/v1/servers/" + id + "/connect", null).body();
        assertThat(again).contains("\"outcome\":\"CONNECTED\"").doesNotContain("presentedKey");
        assertThat(post("/api/v1/servers/" + id + "/host-key/trust", "{\"fingerprint\":\"" + SSH.fingerprint()
                + "\"}").statusCode()).isEqualTo(409);
        assertThat(jdbc.queryForObject("select count(*) from activity_log where action = 'SERVER_HOST_KEY_TRUSTED'",
                Integer.class)).isEqualTo(1);
    }

    @Test
    void aChangedHostKeyBlocksTheServerUntilTheOwnerAcceptsIt() throws Exception {
        String id = connectedServer("alpha");
        String member = member("SERVERS:EDIT", "SERVERS:RUN", "SERVERS:CREATE");
        String newPrint = SSH.newHostKey();
        int before = SSH.exchanges().size();

        HttpResponse<String> changed = client.send("POST", "/api/v1/servers/" + id + "/connect", member, null);
        assertThat(changed.statusCode()).isEqualTo(200);
        assertThat(changed.body()).contains("\"outcome\":\"KEY_CHANGED\"", "\"connectionStatus\":\"KEY_CHANGED\"",
                "\"presentedKey\":{\"type\":\"ssh-ed25519\",\"fingerprint\":\"" + newPrint + "\"",
                "blocked");
        // Nothing was sent to the impostor.
        assertThat(SSH.exchanges()).hasSize(before);
        assertThat(jdbc.queryForObject("select details::text from activity_log where action = "
                + "'SERVER_HOST_KEY_CHANGED'", String.class)).contains(newPrint);

        // Still blocked on the next try, and first-use trust can't be used to get round it.
        assertThat(client.send("POST", "/api/v1/servers/" + id + "/connect", member, null).body())
                .contains("\"outcome\":\"KEY_CHANGED\"");
        assertThat(client.send("POST", "/api/v1/servers/" + id + "/host-key/trust", member,
                "{\"fingerprint\":\"" + newPrint + "\"}").statusCode()).isEqualTo(409);
        // Only the Owner may accept it, whatever the member's permissions.
        HttpResponse<String> refused = client.send("POST", "/api/v1/servers/" + id + "/host-key/replace", member,
                "{\"fingerprint\":\"" + newPrint + "\"}");
        assertThat(refused.statusCode()).isEqualTo(403);
        assertThat(SSH.exchanges()).hasSize(before);

        HttpResponse<String> accepted = post("/api/v1/servers/" + id + "/host-key/replace",
                "{\"fingerprint\":\"" + newPrint + "\"}");
        assertThat(accepted.statusCode()).as(accepted.body()).isEqualTo(200);
        assertThat(accepted.body()).contains("\"outcome\":\"CONNECTED\"", "\"fingerprint\":\"" + newPrint + "\"");
        assertThat(jdbc.queryForObject("select details::text from activity_log where action = "
                + "'SERVER_HOST_KEY_REPLACED'", String.class)).contains(newPrint, "previous");
    }

    @Test
    void aKeyThatIsNotAuthorizedSaysWhatToDo() throws Exception {
        SSH.reset();
        SSH.on("MASTERDB_LOGIN_TEST", 0, "MASTERDB_UID=0\n");
        String id = addServer("alpha", "deploy");
        post("/api/v1/servers/" + id + "/connect", null);
        String body = post("/api/v1/servers/" + id + "/host-key/trust", "{\"fingerprint\":\"" + SSH.fingerprint()
                + "\"}").body();
        assertThat(body).contains("\"outcome\":\"AUTH_FAILED\"", "refused MasterDB's SSH key for user deploy",
                "authorized_keys");
        assertThat(SSH.logins()).contains("deploy");

        SSH.authorize(publicKey);
        SSH.on("MASTERDB_LOGIN_TEST", 0, "MASTERDB_UID=1000\nMASTERDB_SUDO=no\n");
        assertThat(post("/api/v1/servers/" + id + "/connect", null).body()).contains("\"outcome\":\"CONNECTED\"",
                "\"privileged\":false", "no passwordless sudo");
    }

    @Test
    void anUnreachableServerSaysSo() throws Exception {
        HttpResponse<String> created = post("/api/v1/servers", "{\"name\":\"gone\",\"ip\":\"127.0.0.1\",\"sshPort\":1,"
                + "\"expiresOn\":\"2027-01-01\"}");
        String id = id(created.body());
        assertThat(post("/api/v1/servers/" + id + "/connect", null).body()).contains("\"outcome\":\"UNREACHABLE\"",
                "\"connectionStatus\":\"UNREACHABLE\"");
    }

    @Test
    void withoutThePermissionEverythingIs403() throws Exception {
        String id = addServer("alpha");
        String none = member("DNS:VIEW");
        assertThat(client.send("GET", "/api/v1/servers", none, null).statusCode()).isEqualTo(403);
        assertThat(client.send("GET", "/api/v1/servers/ssh-key", none, null).statusCode()).isEqualTo(403);
        assertThat(client.send("GET", "/api/v1/servers/" + id, none, null).statusCode()).isEqualTo(403);
        assertThat(client.send("POST", "/api/v1/servers", none, "{}").statusCode()).isEqualTo(403);
        assertThat(client.send("POST", "/api/v1/servers/" + id + "/connect", none, null).statusCode()).isEqualTo(403);

        String viewer = member("SERVERS:VIEW");
        assertThat(client.send("GET", "/api/v1/servers", viewer, null).statusCode()).isEqualTo(200);
        assertThat(client.send("PUT", "/api/v1/servers/" + id, viewer, "{}").statusCode()).isEqualTo(403);
        assertThat(client.send("DELETE", "/api/v1/servers/" + id, viewer, null).statusCode()).isEqualTo(403);
        assertThat(client.send("POST", "/api/v1/servers/" + id + "/connect", viewer, null).statusCode())
                .isEqualTo(403);
        assertThat(client.send("POST", "/api/v1/servers/" + id + "/host-key/trust", viewer,
                "{\"fingerprint\":\"x\"}").statusCode()).isEqualTo(403);
        assertThat(SSH.logins()).isEmpty();
    }
}
