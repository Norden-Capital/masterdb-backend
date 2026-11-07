package ca.nordencapital.masterdb.auth.login;

import ca.nordencapital.testsupport.NamecheapStub;
import org.junit.jupiter.api.Test;

import java.net.http.HttpResponse;

import static org.assertj.core.api.Assertions.assertThat;

/** DNS job 2: domains by hand and from Namecheap, the list with filters, delete, permissions. */
class DomainFlowTest extends DnsFlowTestBase {

    static final String DOMAINS = "/api/v1/dns/domains";

    @Test
    void addByHandNormalisesAndChecksTheSyntax() throws Exception {
        HttpResponse<String> ok = post(DOMAINS, "{\"name\":\"  Example.COM. \"}");
        assertThat(ok.statusCode()).isEqualTo(201);
        assertThat(ok.body()).contains("\"name\":\"example.com\"", "\"source\":\"MANUAL\"");
        assertThat(post(DOMAINS, "{\"name\":\"bücher.de\"}").body()).contains("\"name\":\"xn--bcher-kva.de\"");

        for (String bad : new String[] {"http://example.org/", "nodot", "-bad.com", "a..com", "x@y.com", "", "ex ample.com"}) {
            HttpResponse<String> res = post(DOMAINS, "{\"name\":\"" + bad + "\"}");
            assertThat(res.statusCode()).as(bad).isEqualTo(400);
            assertThat(res.body()).contains("\"field\":\"name\"");
        }
        HttpResponse<String> dup = post(DOMAINS, "{\"name\":\"EXAMPLE.com\"}");
        assertThat(dup.statusCode()).isEqualTo(409);
        assertThat(dup.body()).contains("example.com is already in MasterDB");
        assertThat(jdbc.queryForList("select action from activity_log where action like 'DOMAIN%'", String.class))
                .containsExactly("DOMAIN_ADDED", "DOMAIN_ADDED");
    }

    @Test
    void fetchListsTheAccountAndMarksWhatIsAlreadyThere() throws Exception {
        NamecheapStub.answer("namecheap.domains.getList", "getList-ok");
        addManual("example-one.com");
        HttpResponse<String> res = get("/api/v1/dns/namecheap/domains");
        assertThat(res.statusCode()).isEqualTo(200);
        assertThat(res.body()).contains(
                "{\"name\":\"example-one.com\",\"expiresAt\":\"2027-02-15\",\"expired\":false,\"autoRenew\":true,"
                        + "\"locked\":false,\"usesNamecheapDns\":true,\"alreadyAdded\":true}",
                "{\"name\":\"example-two.net\",\"expiresAt\":\"2026-06-01\",\"expired\":true",
                "\"name\":\"example-three.org\"");
        assertThat(res.body()).contains("\"alreadyAdded\":false");
        // Nothing saved by looking.
        assertThat(jdbc.queryForObject("select count(*) from domains", Integer.class)).isEqualTo(1);
    }

    @Test
    void importAddsOnlyTheSelectedNamesAndRefusesOthers() throws Exception {
        NamecheapStub.answer("namecheap.domains.getList", "getList-ok");
        String manual = addManual("example-one.com");

        HttpResponse<String> notThere = post(DOMAINS + "/import", "{\"names\":[\"example-two.net\",\"stranger.com\"]}");
        assertThat(notThere.statusCode()).isEqualTo(400);
        assertThat(notThere.body()).contains("stranger.com");
        assertThat(jdbc.queryForObject("select count(*) from domains", Integer.class)).isEqualTo(1);
        assertThat(post(DOMAINS + "/import", "{\"names\":[]}").statusCode()).isEqualTo(400);

        HttpResponse<String> res = post(DOMAINS + "/import", "{\"names\":[\"Example-Two.NET\",\"example-one.com\"]}");
        assertThat(res.statusCode()).isEqualTo(200);
        assertThat(res.body()).contains("\"added\":[\"example-two.net\"]", "\"updated\":[\"example-one.com\"]");
        assertThat(jdbc.queryForList("select name from domains order by name", String.class))
                .containsExactly("example-one.com", "example-two.net"); // example-three.org not selected
        assertThat(get(DOMAINS + "/" + manual).body()).contains("\"source\":\"NAMECHEAP\"",
                "\"expiresAt\":\"2027-02-15\"", "\"autoRenew\":true", "\"namecheapSyncedAt\":\"2026-11-07T09:00:03Z\"");
        String details = jdbc.queryForObject("select details::text from activity_log where action = 'DOMAINS_IMPORTED'",
                String.class);
        assertThat(details).contains("\"addedCount\": 1", "\"updatedCount\": 1", "example-two.net");
    }

    @Test
    void namecheapErrorsReachTheCallerAndWithoutAccountIt409s() throws Exception {
        NamecheapStub.answer("namecheap.domains.getList", "error-ip-not-whitelisted");
        HttpResponse<String> res = get("/api/v1/dns/namecheap/domains");
        assertThat(res.statusCode()).isEqualTo(424);
        assertThat(res.body()).contains("\"code\":\"NAMECHEAP_IP_NOT_WHITELISTED\"", "203.0.113.10");
        jdbc.update("delete from namecheap_account");
        assertThat(get("/api/v1/dns/namecheap/domains").body()).contains("NAMECHEAP_NOT_CONFIGURED");
    }

    @Test
    void listSearchesFiltersAndSorts() throws Exception {
        NamecheapStub.answer("namecheap.domains.getList", "getList-ok");
        post(DOMAINS + "/import", "{\"names\":[\"example-one.com\",\"example-two.net\",\"example-three.org\"]}");
        addManual("manual-site.ca");

        assertThat(names(DOMAINS + "?sort=name")).isEqualTo(
                "example-one.com,example-three.org,example-two.net,manual-site.ca");
        assertThat(names(DOMAINS + "?q=TWO")).isEqualTo("example-two.net");
        assertThat(names(DOMAINS + "?source=MANUAL")).isEqualTo("manual-site.ca");
        // Today is 2026-11-07: example-two expired, example-three expires on 11-20, example-one in 2027.
        assertThat(names(DOMAINS + "?expiry=EXPIRED")).isEqualTo("example-two.net");
        assertThat(names(DOMAINS + "?expiry=DAYS_30")).isEqualTo("example-three.org");
        assertThat(names(DOMAINS + "?expiry=DAYS_90")).isEqualTo("example-three.org");
        assertThat(names(DOMAINS + "?expiry=UNKNOWN")).isEqualTo("manual-site.ca");
        assertThat(names(DOMAINS + "?sort=expiresAt,desc")).isEqualTo(
                "example-one.com,example-three.org,example-two.net,manual-site.ca");
        assertThat(names(DOMAINS + "?health=UNCHECKED&size=2&page=1")).isEqualTo("example-two.net,manual-site.ca");
        assertThat(get(DOMAINS + "?size=2").body()).contains("\"totalItems\":4", "\"totalPages\":2");
        assertThat(get(DOMAINS + "?sort=nope").statusCode()).isEqualTo(400);
        assertThat(get(DOMAINS + "?expiry=SOON").statusCode()).isEqualTo(400);
        assertThat(names(DOMAINS + "?q=%25")).isEmpty();
    }

    @Test
    void deleteRemovesTheDomainAndIsLogged() throws Exception {
        String id = addManual("gone.example");
        assertThat(client.send("DELETE", DOMAINS + "/" + id, owner, null).statusCode()).isEqualTo(204);
        assertThat(get(DOMAINS + "/" + id).statusCode()).isEqualTo(404);
        assertThat(client.send("DELETE", DOMAINS + "/" + id, owner, null).statusCode()).isEqualTo(404);
        assertThat(jdbc.queryForObject("select target_label from activity_log where action = 'DOMAIN_DELETED'",
                String.class)).isEqualTo("gone.example");
    }

    @Test
    void permissionsGateEveryCall() throws Exception {
        NamecheapStub.answer("namecheap.domains.getList", "getList-ok");
        String id = addManual("example.com");
        String none = member();
        assertThat(client.send("GET", DOMAINS, none, null).statusCode()).isEqualTo(403);
        assertThat(client.send("GET", DOMAINS + "/" + id, none, null).statusCode()).isEqualTo(403);

        String viewer = member("DNS:VIEW");
        assertThat(client.send("GET", DOMAINS, viewer, null).statusCode()).isEqualTo(200);
        assertThat(client.send("POST", DOMAINS, viewer, "{\"name\":\"x.com\"}").statusCode()).isEqualTo(403);
        assertThat(client.send("GET", "/api/v1/dns/namecheap/domains", viewer, null).statusCode()).isEqualTo(403);
        assertThat(client.send("POST", DOMAINS + "/import", viewer, "{\"names\":[\"example-one.com\"]}").statusCode())
                .isEqualTo(403);
        assertThat(client.send("DELETE", DOMAINS + "/" + id, viewer, null).statusCode()).isEqualTo(403);

        String creator = member("DNS:CREATE");
        assertThat(client.send("POST", DOMAINS, creator, "{\"name\":\"x.com\"}").statusCode()).isEqualTo(201);
        assertThat(client.send("DELETE", DOMAINS + "/" + id, creator, null).statusCode()).isEqualTo(403);
        assertThat(client.send("DELETE", DOMAINS + "/" + id, member("DNS:DELETE"), null).statusCode()).isEqualTo(204);
    }

    private String names(String path) throws Exception {
        HttpResponse<String> res = get(path);
        assertThat(res.statusCode()).as(res.body()).isEqualTo(200);
        return String.join(",", java.util.regex.Pattern.compile("\"name\":\"([^\"]+)\"").matcher(res.body())
                .results().map(m -> m.group(1)).toList());
    }
}
