package ca.nordencapital.masterdb.auth.login;

import ca.nordencapital.testsupport.FakeDnsLookup;
import ca.nordencapital.testsupport.NamecheapStub;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.net.http.HttpResponse;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Server management job 3: a server linked to a domain gives the domain its
 * mail IP (managed records and DNS health), turns on the DNS module's PTR
 * check, and carries the probe identity (HELO host, MAIL FROM).
 */
class ServerLinkFlowTest extends ServerFlowTestBase {

    @Autowired
    FakeDnsLookup dns;

    String domain;
    String server;

    @BeforeEach
    void namecheapDomainAndServer() throws Exception {
        dns.clear();
        NamecheapStub.answer("namecheap.domains.getList", "getList-ok");
        NamecheapStub.answer("namecheap.domains.dns.getHosts", "getHosts-ok");
        assertThat(post("/api/v1/dns/domains/import", "{\"names\":[\"example-one.com\"]}").statusCode()).isEqualTo(200);
        domain = id(get("/api/v1/dns/domains?q=example-one").body());
        server = addServer("alpha");
    }

    HttpResponse<String> link(String domainId) throws Exception {
        return client.send("PUT", "/api/v1/servers/" + server, owner, "{\"name\":\"alpha\",\"ip\":\"127.0.0.1\","
                + "\"sshPort\":" + SSH.port() + ",\"expiresOn\":\"2027-03-01\""
                + (domainId == null ? "" : ",\"domainId\":\"" + domainId + "\"") + "}");
    }

    @Test
    void linkingGivesTheDomainItsMailIpAndTheServerItsIdentity() throws Exception {
        client.send("PUT", "/api/v1/dns/domains/" + domain + "/dns-settings", owner, "{\"mailIp\":\"198.51.100.9\"}");
        assertThat(get("/api/v1/dns/domains/" + domain + "/dns-settings").body())
                .contains("\"mailIp\":\"198.51.100.9\"").doesNotContain("mailServer");

        HttpResponse<String> linked = link(domain);
        assertThat(linked.statusCode()).as(linked.body()).isEqualTo(200);
        assertThat(linked.body()).contains("\"heloHost\":\"mail.example-one.com\"",
                "\"mailFrom\":\"postmaster@example-one.com\"");
        assertThat(get("/api/v1/dns/domains/" + domain + "/dns-settings").body()).contains("\"mailIp\":\"127.0.0.1\"",
                "\"mailServer\":{\"publicId\":\"" + server + "\",\"name\":\"alpha\",\"ip\":\"127.0.0.1\"}");

        // The IP is no longer typed: a typed one is ignored while the server is linked.
        HttpResponse<String> typed = client.send("PUT", "/api/v1/dns/domains/" + domain + "/dns-settings", owner,
                "{\"mailIp\":\"203.0.113.77\",\"dmarcPolicy\":\"reject\"}");
        assertThat(typed.statusCode()).isEqualTo(200);
        assertThat(typed.body()).contains("\"mailIp\":\"127.0.0.1\"", "\"dmarcPolicy\":\"reject\"");

        // The managed records are built from the server's IP.
        String preview = get("/api/v1/dns/domains/" + domain + "/records/preview").body();
        assertThat(preview).contains("{\"change\":\"ADD\",\"managed\":true,\"record\":{\"name\":\"@\",\"type\":\"A\","
                + "\"address\":\"127.0.0.1\"", "v=spf1 ip4:127.0.0.1 -all").doesNotContain("203.0.113.77");
        assertThat(NamecheapStub.requests("namecheap.domains.dns.setHosts")).isEmpty();

        // Unlinked: the domain is back to the IP that was typed before.
        assertThat(link(null).body()).doesNotContain("heloHost", "mailFrom");
        assertThat(get("/api/v1/dns/domains/" + domain + "/dns-settings").body())
                .contains("\"mailIp\":\"198.51.100.9\"").doesNotContain("mailServer");
    }

    @Test
    void theDnsModulesPtrCheckRunsForALinkedDomain() throws Exception {
        String before = post("/api/v1/dns/domains/" + domain + "/health/check", null).body();
        assertThat(before).contains("{\"record\":\"PTR\",\"status\":\"NOT_CHECKED\",\"detail\":\"Checked once servers are linked");

        link(domain);
        dns.ptr("127.0.0.1", "vmi1.contaboserver.net");
        String wrong = post("/api/v1/dns/domains/" + domain + "/health/check", null).body();
        assertThat(wrong).contains("{\"record\":\"PTR\",\"status\":\"PROBLEM\",\"detail\":\"Reverse DNS of 127.0.0.1 "
                + "is vmi1.contaboserver.net, not mail.example-one.com.");
        dns.ptr("127.0.0.1", "mail.example-one.com");
        assertThat(post("/api/v1/dns/domains/" + domain + "/health/check", null).body())
                .contains("{\"record\":\"PTR\",\"status\":\"OK\"");
    }

    @Test
    void theProbeIdentityStaysOnTheLinkedDomain() throws Exception {
        assertThat(client.send("PUT", "/api/v1/servers/" + server + "/identity", owner,
                "{\"heloHost\":\"mail.example-one.com\",\"mailFrom\":\"a@example-one.com\"}").statusCode())
                .isEqualTo(409);
        link(domain);

        HttpResponse<String> bad = client.send("PUT", "/api/v1/servers/" + server + "/identity", owner,
                "{\"heloHost\":\"mail.other.example\",\"mailFrom\":\"bounce@other.example\"}");
        assertThat(bad.statusCode()).isEqualTo(400);
        assertThat(bad.body()).contains("\"field\":\"heloHost\"", "\"field\":\"mailFrom\"");

        HttpResponse<String> ok = client.send("PUT", "/api/v1/servers/" + server + "/identity", owner,
                "{\"heloHost\":\" Probe1.Example-One.com \",\"mailFrom\":\"verify@example-one.com\"}");
        assertThat(ok.statusCode()).as(ok.body()).isEqualTo(200);
        assertThat(ok.body()).contains("\"heloHost\":\"probe1.example-one.com\"",
                "\"mailFrom\":\"verify@example-one.com\"");
        assertThat(jdbc.queryForObject("select details::text from activity_log where action = "
                + "'SERVER_IDENTITY_CHANGED'", String.class)).contains("probe1.example-one.com");

        // The PTR now has to match the new HELO host, in both health checks.
        dns.ptr("127.0.0.1", "mail.example-one.com");
        assertThat(post("/api/v1/dns/domains/" + domain + "/health/check", null).body())
                .contains("is mail.example-one.com, not probe1.example-one.com");

        String viewer = member("SERVERS:VIEW");
        assertThat(client.send("PUT", "/api/v1/servers/" + server + "/identity", viewer,
                "{\"heloHost\":\"mail.example-one.com\",\"mailFrom\":\"a@example-one.com\"}").statusCode())
                .isEqualTo(403);
    }
}
