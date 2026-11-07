package ca.nordencapital.masterdb.auth.login;

import ca.nordencapital.testsupport.FakeDnsLookup;
import ca.nordencapital.testsupport.FakeDnsblLookup;
import ca.nordencapital.testsupport.FakeSshServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.context.annotation.Import;

import java.net.http.HttpResponse;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Shared set-up of the Server management flow tests: everything from the DNS
 * tests (Owner, member, fake Namecheap) plus an embedded fake SSH server on
 * 127.0.0.1 that has MasterDB's public key authorized. No test reaches a real
 * server.
 */
@Import({FakeDnsLookup.Config.class, FakeDnsblLookup.Config.class})
abstract class ServerFlowTestBase extends DnsFlowTestBase {

    static final FakeSshServer SSH = new FakeSshServer(0);

    String publicKey;

    @BeforeEach
    void setUpServers() throws Exception {
        jdbc.update("delete from servers");
        SSH.reset();
        HttpResponse<String> key = get("/api/v1/servers/ssh-key");
        assertThat(key.statusCode()).as(key.body()).isEqualTo(200);
        publicKey = field(key.body(), "publicKey");
        SSH.authorize(publicKey);
        SSH.on("MASTERDB_LOGIN_TEST", 0, """
                MASTERDB_LOGIN_TEST
                ID=ubuntu
                VERSION_ID="24.04"
                PRETTY_NAME="Ubuntu 24.04.1 LTS"
                MASTERDB_UID=0
                """);
    }

    @AfterEach
    void tearDownServers() {
        jdbc.update("delete from servers");
    }

    /** Adds the fake server (127.0.0.1:its port) and returns its public id. */
    String addServer(String name) throws Exception {
        return addServer(name, "root");
    }

    String addServer(String name, String user) throws Exception {
        HttpResponse<String> res = post("/api/v1/servers", "{\"name\":\"" + name + "\",\"ip\":\"127.0.0.1\","
                + "\"sshPort\":" + SSH.port() + ",\"sshUser\":\"" + user + "\",\"expiresOn\":\"2027-03-01\"}");
        assertThat(res.statusCode()).as(res.body()).isEqualTo(201);
        return id(res.body());
    }

    /** Adds the fake server, connects, trusts its key: ready for SSH work. */
    String connectedServer(String name) throws Exception {
        String id = addServer(name);
        String pending = post("/api/v1/servers/" + id + "/connect", null).body();
        assertThat(pending).contains("\"outcome\":\"KEY_PENDING\"");
        HttpResponse<String> trusted = post("/api/v1/servers/" + id + "/host-key/trust",
                "{\"fingerprint\":\"" + SSH.fingerprint() + "\"}");
        assertThat(trusted.body()).as(trusted.body()).contains("\"outcome\":\"CONNECTED\"");
        return id;
    }

    static String field(String body, String name) {
        int i = body.indexOf("\"" + name + "\":\"") + name.length() + 4;
        return body.substring(i, body.indexOf('"', i));
    }
}
