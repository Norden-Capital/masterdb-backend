package ca.nordencapital.masterdb.auth.login;

import ca.nordencapital.masterdb.dns.health.DnsHealthService;
import ca.nordencapital.testsupport.FakeDnsLookup;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Import;

import java.net.http.HttpResponse;

import static org.assertj.core.api.Assertions.assertThat;

/** DNS job 4: health of every domain (manual too) via a fake public DNS; re-check, daily run, filter. */
@Import(FakeDnsLookup.Config.class)
class DnsHealthFlowTest extends DnsFlowTestBase {

    static final String KEY_B64 = DnsRecordFlowTest.KEY_B64;

    @Autowired
    FakeDnsLookup dns;
    @Autowired
    DnsHealthService health;

    @BeforeEach
    void freshDns() {
        dns.clear();
    }

    @Test
    void aManualDomainIsCheckedAndStored() throws Exception {
        String id = addManual("good.example");
        assertThat(get("/api/v1/dns/domains/" + id + "/health").body()).contains("\"records\":[]").doesNotContain("status");
        client.send("PUT", "/api/v1/dns/domains/" + id + "/dns-settings", owner,
                "{\"mailIp\":\"203.0.113.10\",\"dkimPublicKey\":\"" + KEY_B64 + "\"}");
        dns.healthy("good.example", KEY_B64);

        HttpResponse<String> res = post("/api/v1/dns/domains/" + id + "/health/check", null);
        assertThat(res.statusCode()).as(res.body()).isEqualTo(200);
        assertThat(res.body()).contains("\"status\":\"OK\"", "\"checkedAt\":\"2026-11-07T09:00:03Z\"",
                "{\"record\":\"A\",\"status\":\"OK\",\"detail\":\"Root A record: 203.0.113.10.\"",
                "{\"record\":\"PTR\",\"status\":\"NOT_CHECKED\"");
        assertThat(get("/api/v1/dns/domains/" + id + "/health").body()).contains("\"status\":\"OK\"",
                "\"record\":\"DKIM\",\"status\":\"OK\"");
        assertThat(get("/api/v1/dns/domains/" + id).body()).contains("\"healthStatus\":\"OK\"");
        assertThat(jdbc.queryForObject("select details::text from activity_log where action = 'DNS_HEALTH_CHECKED'",
                String.class)).contains("\"status\": \"OK\"");

        // Public DNS changes: the next check turns red with the reason.
        dns.txt("good.example", "v=spf1 include:other.example -all");
        String body = post("/api/v1/dns/domains/" + id + "/health/check", null).body();
        assertThat(body).contains("\"status\":\"PROBLEM\"", "SPF does not include ip4:203.0.113.10.");
        assertThat(jdbc.queryForObject("select count(*) from domain_health_checks", Integer.class)).isEqualTo(7);
    }

    @Test
    void theDailyRunChecksEveryDomainAndFeedsTheFilter() throws Exception {
        String good = addManual("good.example");
        addManual("empty.example");
        addManual("slow.example");
        client.send("PUT", "/api/v1/dns/domains/" + good + "/dns-settings", owner,
                "{\"mailIp\":\"203.0.113.10\",\"dkimPublicKey\":\"" + KEY_B64 + "\"}");
        dns.healthy("good.example", KEY_B64).healthy("slow.example", KEY_B64).fail("_dmarc.slow.example");
        addManual("never.example");

        health.checkAllDaily();

        assertThat(jdbc.queryForList("select name || ' ' || health_status from domains order by name", String.class))
                .containsExactly("empty.example PROBLEM", "good.example OK", "never.example PROBLEM",
                        "slow.example ERROR");
        assertThat(get("/api/v1/dns/domains?health=PROBLEM").body()).contains("empty.example", "never.example")
                .doesNotContain("good.example");
        assertThat(get("/api/v1/dns/domains?health=ERROR").body()).contains("slow.example");
        String sorted = get("/api/v1/dns/domains?sort=healthStatus").body();
        assertThat(sorted.indexOf("empty.example")).isLessThan(sorted.indexOf("slow.example"));
        assertThat(sorted.indexOf("slow.example")).isLessThan(sorted.indexOf("good.example"));
        assertThat(jdbc.queryForObject("select details::text from activity_log where action = 'DNS_HEALTH_CHECKED'",
                String.class)).contains("\"domains\": 4", "\"problems\": 2", "\"errors\": 1");
        // Deleting a domain takes its results with it.
        client.send("DELETE", "/api/v1/dns/domains/" + good, owner, null);
        assertThat(jdbc.queryForObject("select count(*) from domain_health_checks", Integer.class)).isEqualTo(21);
    }

    @Test
    void permissionsGateHealth() throws Exception {
        String id = addManual("good.example");
        String viewer = member("DNS:VIEW");
        assertThat(client.send("GET", "/api/v1/dns/domains/" + id + "/health", viewer, null).statusCode()).isEqualTo(200);
        assertThat(client.send("POST", "/api/v1/dns/domains/" + id + "/health/check", viewer, null).statusCode())
                .isEqualTo(403);
        assertThat(client.send("POST", "/api/v1/dns/domains/" + id + "/health/check", member("DNS:RUN"), null)
                .statusCode()).isEqualTo(200);
        assertThat(client.send("GET", "/api/v1/dns/domains/" + id + "/health", member(), null).statusCode())
                .isEqualTo(403);
    }
}
