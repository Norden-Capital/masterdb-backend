package ca.nordencapital.masterdb.auth.login;

import ca.nordencapital.masterdb.servers.health.ServerHealthService;
import ca.nordencapital.testsupport.FakeDnsLookup;
import ca.nordencapital.testsupport.FakeDnsblLookup;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.net.http.HttpResponse;

import static org.assertj.core.api.Assertions.assertThat;

/** Server management job 2: health over SSH (fake server) and from the backend (fake DNS and blocklists). */
class ServerHealthFlowTest extends ServerFlowTestBase {

    @Autowired
    FakeDnsLookup dns;
    @Autowired
    FakeDnsblLookup dnsbl;
    @Autowired
    ServerHealthService health;

    String domain;

    @BeforeEach
    void freshDns() throws Exception {
        dns.clear();
        dnsbl.clear();
        domain = addManual("probe.example");
        SSH.on("MASTERDB_PORT25_CHECK", 0, "MASTERDB_PORT25_CHECK\nMASTERDB_PORT25_OK gmail-smtp-in.l.google.com\n");
        dns.ptr("127.0.0.1", "mail.probe.example");
    }

    String linkedServer() throws Exception {
        String id = connectedServer("alpha");
        HttpResponse<String> linked = client.send("PUT", "/api/v1/servers/" + id, owner, "{\"name\":\"alpha\","
                + "\"ip\":\"127.0.0.1\",\"sshPort\":" + SSH.port() + ",\"expiresOn\":\"2027-03-01\",\"domainId\":\""
                + domain + "\"}");
        assertThat(linked.statusCode()).as(linked.body()).isEqualTo(200);
        return id;
    }

    @Test
    void allGoodIsGreenWithTheReasonPerCheck() throws Exception {
        String id = linkedServer();
        assertThat(get("/api/v1/servers/" + id + "/health").body()).contains("\"checks\":[]");

        HttpResponse<String> res = post("/api/v1/servers/" + id + "/health/check", null);
        assertThat(res.statusCode()).as(res.body()).isEqualTo(200);
        assertThat(res.body()).contains("\"status\":\"OK\"", "\"checkedAt\":\"2026-11-07T09:00:03Z\"",
                "{\"check\":\"SSH\",\"status\":\"OK\",\"detail\":\"MasterDB's key logs in as root",
                "{\"check\":\"PORT25\",\"status\":\"OK\",\"detail\":\"Outbound port 25 is open: "
                        + "gmail-smtp-in.l.google.com answered",
                "{\"check\":\"PTR\",\"status\":\"OK\",\"detail\":\"Reverse DNS of 127.0.0.1 is mail.probe.example.\"",
                "{\"check\":\"DNSBL\",\"status\":\"OK\",\"detail\":\"Not listed on 6 blocklists",
                "{\"check\":\"EXPIRY\",\"status\":\"OK\"");
        // Port 25 is tried from the VPS itself, over SSH, never from the backend.
        assertThat(SSH.exchanges()).anyMatch(e -> e.has("/dev/tcp/$h/25") && e.command().equals("bash -s"));
        assertThat(dnsbl.asked()).contains("1.0.0.127.zen.spamhaus.org");
        assertThat(get("/api/v1/servers/" + id).body()).contains("\"healthStatus\":\"OK\"");
        assertThat(get("/api/v1/servers?health=OK").body()).contains("\"totalItems\":1");
        assertThat(jdbc.queryForObject("select details::text from activity_log where action = 'SERVER_HEALTH_CHECKED'",
                String.class)).contains("\"status\": \"OK\"");
    }

    @Test
    void problemsTurnRedWithTheReason() throws Exception {
        String id = linkedServer();
        SSH.on("MASTERDB_PORT25_CHECK", 0, "MASTERDB_PORT25_CHECK\nMASTERDB_PORT25_FAIL gmail-smtp-in.l.google.com\n"
                + "MASTERDB_PORT25_FAIL mta5.am0.yahoodns.net\nMASTERDB_PORT25_FAIL "
                + "outlook-com.olc.protection.outlook.com\nMASTERDB_PORT25_BLOCKED\n");
        dns.ptr("127.0.0.1", "vmi123.contaboserver.net");
        dnsbl.answer("1.0.0.127.b.barracudacentral.org", "127.0.0.2");

        String body = post("/api/v1/servers/" + id + "/health/check", null).body();
        assertThat(body).contains("\"status\":\"PROBLEM\"",
                "\"check\":\"PORT25\",\"status\":\"PROBLEM\",\"detail\":\"Outbound port 25 looks blocked",
                "Reverse DNS of 127.0.0.1 is vmi123.contaboserver.net, not mail.probe.example. Set it at the VPS provider.",
                "\"check\":\"DNSBL\",\"status\":\"PROBLEM\",\"detail\":\"Listed on Barracuda (listed [127.0.0.2]).\"");
        assertThat(get("/api/v1/servers?health=PROBLEM").body()).contains("\"totalItems\":1");
    }

    @Test
    void aSpamhausRefusalIsNotCountedAsClean() throws Exception {
        String id = linkedServer();
        dnsbl.answer("1.0.0.127.zen.spamhaus.org", "127.255.255.254");
        String body = post("/api/v1/servers/" + id + "/health/check", null).body();
        assertThat(body).contains("\"status\":\"ERROR\"", "\"check\":\"DNSBL\",\"status\":\"ERROR\"",
                "Not listed on 5 of 6 lists; couldn't check Spamhaus ZEN (refused the query")
                .doesNotContain("Not listed on 6 blocklists");
    }

    @Test
    void anExpiringPlanWarnsAndAnUnconnectedServerIsRed() throws Exception {
        HttpResponse<String> created = post("/api/v1/servers", "{\"name\":\"soon\",\"ip\":\"127.0.0.1\",\"sshPort\":"
                + SSH.port() + ",\"expiresOn\":\"2026-11-17\"}");
        String id = id(created.body());
        String body = post("/api/v1/servers/" + id + "/health/check", null).body();
        assertThat(body).contains("\"check\":\"SSH\",\"status\":\"PROBLEM\",\"detail\":\"Not connected yet",
                "\"check\":\"PORT25\",\"status\":\"NOT_CHECKED\"",
                "\"check\":\"PTR\",\"status\":\"NOT_CHECKED\",\"detail\":\"Link a domain",
                "\"check\":\"EXPIRY\",\"status\":\"WARNING\",\"detail\":\"The VPS plan ends in 10 days (2026-11-17).\"");
        assertThat(SSH.logins()).isEmpty();

        // Once connected and with no other problem, the expiry warning is the overall result.
        post("/api/v1/servers/" + id + "/connect", null);
        post("/api/v1/servers/" + id + "/host-key/trust", "{\"fingerprint\":\"" + SSH.fingerprint() + "\"}");
        assertThat(post("/api/v1/servers/" + id + "/health/check", null).body()).startsWith("{\"serverId\"")
                .contains("\"status\":\"WARNING\"");
    }

    @Test
    void theDailyRunChecksEveryServer() throws Exception {
        linkedServer();
        assertThat(post("/api/v1/servers", "{\"name\":\"beta\",\"ip\":\"127.0.0.1\",\"sshPort\":1,"
                + "\"expiresOn\":\"2027-03-01\"}").statusCode()).isEqualTo(201);
        health.checkAllDaily();
        assertThat(jdbc.queryForList("select health_status from servers order by name", String.class))
                .containsExactly("OK", "PROBLEM");
        assertThat(jdbc.queryForObject("select details::text from activity_log where action = 'SERVER_HEALTH_CHECKED'",
                String.class)).contains("\"servers\": 2", "\"ok\": 1", "\"problem\": 1");
    }

    @Test
    void permissionsAreChecked() throws Exception {
        String id = addServer("alpha");
        String none = member("DNS:VIEW");
        assertThat(client.send("GET", "/api/v1/servers/" + id + "/health", none, null).statusCode()).isEqualTo(403);
        String viewer = member("SERVERS:VIEW");
        assertThat(client.send("GET", "/api/v1/servers/" + id + "/health", viewer, null).statusCode()).isEqualTo(200);
        assertThat(client.send("POST", "/api/v1/servers/" + id + "/health/check", viewer, null).statusCode())
                .isEqualTo(403);
    }
}
