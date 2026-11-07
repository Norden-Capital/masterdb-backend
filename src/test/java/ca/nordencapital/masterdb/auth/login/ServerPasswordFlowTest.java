package ca.nordencapital.masterdb.auth.login;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;

import java.net.http.HttpResponse;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The root password, typed once, lets MasterDB add its own key (like the old
 * app's password login), but only to a server whose host key is trusted, and
 * the password is never stored or logged.
 */
@ExtendWith(OutputCaptureExtension.class)
class ServerPasswordFlowTest extends ServerFlowTestBase {

    static final String ROOT_PASSWORD = "Contabo-Root-Pass-42";

    @BeforeEach
    void serverWithoutOurKey() {
        SSH.reset();
        SSH.on("MASTERDB_LOGIN_TEST", 0, "MASTERDB_LOGIN_TEST\nID=almalinux\nVERSION_ID=\"9.4\"\n"
                + "PRETTY_NAME=\"AlmaLinux 9.4\"\nMASTERDB_UID=0\n");
        SSH.password(ROOT_PASSWORD);
        // Running the install command "on the server" really authorizes the key.
        SSH.on("authorized_keys", 0, "MASTERDB_KEY_ADDED\n");
        SSH.whenRun("authorized_keys", () -> SSH.authorize(publicKey));
    }

    @Test
    void trustWithThePasswordAddsTheKeyOnceAndNeverKeepsIt(CapturedOutput output) throws Exception {
        String id = addServer("alma");
        post("/api/v1/servers/" + id + "/connect", null);
        // Nothing was sent to the server before its key is trusted, password included.
        assertThat(SSH.logins()).isEmpty();

        HttpResponse<String> res = post("/api/v1/servers/" + id + "/host-key/trust",
                "{\"fingerprint\":\"" + SSH.fingerprint() + "\",\"password\":\"" + ROOT_PASSWORD + "\"}");
        assertThat(res.statusCode()).as(res.body()).isEqualTo(200);
        assertThat(res.body()).contains("\"outcome\":\"CONNECTED\"", "\"os\":\"AlmaLinux 9.4\"")
                .doesNotContain(ROOT_PASSWORD);
        assertThat(SSH.exchanges()).anyMatch(e -> e.command().contains(publicKey) && e.command().contains("restorecon"));
        assertThat(SSH.exchanges()).noneMatch(e -> e.command().contains(ROOT_PASSWORD) || e.stdin().contains(ROOT_PASSWORD));

        // From now on the key is used: no password needed.
        SSH.password(null);
        assertThat(post("/api/v1/servers/" + id + "/connect", null).body()).contains("\"outcome\":\"CONNECTED\"");

        String everything = output.getAll() + String.join("|", jdbc.queryForList("select row_to_json(s)::text from "
                + "servers s", String.class)) + String.join("|", jdbc.queryForList("select details::text from "
                + "activity_log", String.class));
        assertThat(everything).doesNotContain(ROOT_PASSWORD);
        assertThat(jdbc.queryForObject("select details::text from activity_log where action = 'SERVER_KEY_INSTALLED'",
                String.class)).contains("password, used once");
    }

    @Test
    void aWrongPasswordSaysSoAndALaterRetryWorks() throws Exception {
        String id = addServer("alma");
        post("/api/v1/servers/" + id + "/connect", null);
        String wrong = post("/api/v1/servers/" + id + "/host-key/trust", "{\"fingerprint\":\"" + SSH.fingerprint()
                + "\",\"password\":\"not-it\"}").body();
        assertThat(wrong).contains("\"outcome\":\"AUTH_FAILED\"", "refused the password for user root");

        HttpResponse<String> retry = post("/api/v1/servers/" + id + "/install-key",
                "{\"password\":\"" + ROOT_PASSWORD + "\"}");
        assertThat(retry.statusCode()).as(retry.body()).isEqualTo(200);
        assertThat(retry.body()).contains("\"outcome\":\"CONNECTED\"");
    }

    @Test
    void thePasswordIsOnlySentToATrustedServer() throws Exception {
        String id = addServer("alma");
        HttpResponse<String> early = post("/api/v1/servers/" + id + "/install-key",
                "{\"password\":\"" + ROOT_PASSWORD + "\"}");
        assertThat(early.statusCode()).isEqualTo(409);
        assertThat(early.body()).contains("SERVER_NOT_READY").doesNotContain(ROOT_PASSWORD);

        post("/api/v1/servers/" + id + "/connect", null);
        post("/api/v1/servers/" + id + "/host-key/trust", "{\"fingerprint\":\"" + SSH.fingerprint() + "\"}");
        // Another machine answers at that address now: blocked, the password goes nowhere.
        SSH.newHostKey();
        int before = SSH.logins().size();
        String body = post("/api/v1/servers/" + id + "/install-key", "{\"password\":\"" + ROOT_PASSWORD + "\"}").body();
        assertThat(body).contains("\"outcome\":\"KEY_CHANGED\"");
        assertThat(SSH.logins()).hasSize(before);

        String viewer = member("SERVERS:VIEW", "SERVERS:RUN");
        assertThat(client.send("POST", "/api/v1/servers/" + id + "/install-key", viewer,
                "{\"password\":\"x\"}").statusCode()).isEqualTo(403);
    }
}
