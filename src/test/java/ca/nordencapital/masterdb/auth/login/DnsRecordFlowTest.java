package ca.nordencapital.masterdb.auth.login;

import ca.nordencapital.testsupport.NamecheapStub;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.net.http.HttpResponse;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * DNS job 3: preview, write and restore the managed records against a fake
 * Namecheap whose zone really changes on setHosts, so "read back" is real.
 */
class DnsRecordFlowTest extends DnsFlowTestBase {

    static final String KEY_B64 = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAfakefakefakefakefakefakefake0123456789";

    /** The fake zone at Namecheap: getHosts XML; starts as the fixture, setHosts rewrites it. */
    final AtomicReference<String> zone = new AtomicReference<>();
    String domainId;
    String base;

    @BeforeEach
    void zoneAndDomain() throws Exception {
        zone.set(NamecheapStub.fixture("getHosts-ok"));
        NamecheapStub.answer("namecheap.domains.getList", "getList-ok");
        NamecheapStub.answer("namecheap.domains.dns.getHosts", p -> zone.get());
        NamecheapStub.answer("namecheap.domains.dns.setHosts", p -> {
            zone.set(render(p));
            return NamecheapStub.fixture("setHosts-ok");
        });
        assertThat(post("/api/v1/dns/domains/import", "{\"names\":[\"example-one.com\"]}").statusCode()).isEqualTo(200);
        domainId = id(get("/api/v1/dns/domains?q=example-one").body());
        base = "/api/v1/dns/domains/" + domainId;
    }

    HttpResponse<String> settings(String token, String json) throws Exception {
        return client.send("PUT", base + "/dns-settings", token, json);
    }

    void configure() throws Exception {
        HttpResponse<String> res = settings(owner, "{\"mailIp\":\"203.0.113.10\",\"dkimPublicKey\":\"v=DKIM1; k=rsa; p="
                + KEY_B64 + "\",\"dmarcPolicy\":\"reject\"}");
        assertThat(res.statusCode()).as(res.body()).isEqualTo(200);
    }

    @Test
    void settingsAreSavedAndChecked() throws Exception {
        assertThat(get(base + "/dns-settings").body()).contains("\"dkimSelector\":\"mail\"",
                "\"dmarcPolicy\":\"quarantine\"").doesNotContain("mailIp");
        HttpResponse<String> bad = settings(owner, "{\"mailIp\":\"1.2.3\",\"dmarcPolicy\":\"maybe\"}");
        assertThat(bad.statusCode()).isEqualTo(400);
        assertThat(bad.body()).contains("\"field\":\"mailIp\"", "\"field\":\"dmarcPolicy\"");
        configure();
        assertThat(get(base + "/dns-settings").body()).contains("\"mailIp\":\"203.0.113.10\"",
                "\"dkimPublicKey\":\"" + KEY_B64 + "\"", "\"dmarcPolicy\":\"reject\"");
        assertThat(jdbc.queryForObject("select details::text from activity_log where action = 'DNS_SETTINGS_CHANGED'",
                String.class)).contains("\"dkimKey\": true", "203.0.113.10");
    }

    @Test
    void previewShowsBeforeAfterAndWritesNothing() throws Exception {
        configure();
        HttpResponse<String> res = get(base + "/records/preview");
        assertThat(res.statusCode()).as(res.body()).isEqualTo(200);
        String body = res.body();
        assertThat(body).contains("\"domain\":\"example-one.com\"", "\"emailType\":\"MX\"", "\"token\":\"",
                "{\"change\":\"REMOVE\",\"managed\":true,\"record\":{\"name\":\"@\",\"type\":\"URL\"",
                "{\"change\":\"KEEP\",\"managed\":false,\"record\":{\"name\":\"www\",\"type\":\"CNAME\"",
                "{\"change\":\"ADD\",\"managed\":true,\"record\":{\"name\":\"@\",\"type\":\"A\",\"address\":\"203.0.113.10\"");
        assertThat(NamecheapStub.requests("namecheap.domains.dns.setHosts")).isEmpty();
        assertThat(jdbc.queryForObject("select count(*) from dns_snapshots", Integer.class)).isZero();
    }

    @Test
    void applyKeepsUnmanagedRecordsSnapshotsTheOldOnesAndVerifies() throws Exception {
        configure();
        String token = token(get(base + "/records/preview").body());
        HttpResponse<String> res = post(base + "/records/apply", "{\"token\":\"" + token + "\"}");
        assertThat(res.statusCode()).as(res.body()).isEqualTo(200);
        assertThat(res.body()).contains("\"verified\":true", "\"missing\":[]", "\"snapshotId\":\"");

        Map<String, String> sent = NamecheapStub.requests("namecheap.domains.dns.setHosts").getFirst();
        assertThat(sent).containsEntry("SLD", "example-one").containsEntry("TLD", "com").containsEntry("EmailType", "MX")
                .containsEntry("ApiKey", KEY);
        List<String> written = records(sent);
        // Every record MasterDB doesn't manage is sent back unchanged (TTL included).
        assertThat(written).contains("www CNAME parkingpage.namecheap.com. 1800",
                "@ TXT site-verification=FAKE-not-a-real-token 1799", "shop CNAME shops.example.net. 300",
                "s1._domainkey TXT v=DKIM1; k=rsa; p=FAKEOTHERSELECTORKEY 1800");
        // Ours replace the old managed ones.
        assertThat(written).contains("@ A 203.0.113.10 1800", "mail A 203.0.113.10 1800",
                "webmail A 203.0.113.10 1800", "@ MX/10 mail.example-one.com. 1800",
                "@ TXT v=spf1 ip4:203.0.113.10 -all 1800", "mail._domainkey TXT v=DKIM1; k=rsa; p=" + KEY_B64 + " 1800",
                "_dmarc TXT v=DMARC1; p=reject 1800");
        assertThat(written).noneMatch(r -> r.contains("old-mail") || r.startsWith("@ URL") || r.contains("p=none"));
        assertThat(written).hasSize(4 + 7);

        // The previous set is saved, with Namecheap's email type, and can be read back.
        assertThat(jdbc.queryForObject("select reason || ' ' || email_type || ' ' || record_count from dns_snapshots",
                String.class)).isEqualTo("BEFORE_SETUP MX 8");
        String snapshots = get(base + "/snapshots").body();
        assertThat(snapshots).contains("\"reason\":\"BEFORE_SETUP\"", "\"recordCount\":8", "\"actorLabel\":\"" + OWNER + "\"");
        String snapId = id(snapshots);
        assertThat(get(base + "/snapshots/" + snapId).body()).contains("old-mail.example.net.", "http://www.example-one.com/");
        assertThat(jdbc.queryForObject("select details::text from activity_log where action = 'DNS_RECORDS_WRITTEN'",
                String.class)).contains("\"added\": 7", "\"removed\": 4", "\"verified\": true", snapId);

        // A second preview now has nothing left to do.
        assertThat(get(base + "/records/preview").body()).doesNotContain("\"change\":\"ADD\"", "\"change\":\"REMOVE\"");
    }

    @Test
    void aChangeAtNamecheapAfterThePreviewStopsTheWrite() throws Exception {
        configure();
        String token = token(get(base + "/records/preview").body());
        zone.set(zone.get().replace("TTL=\"300\"", "TTL=\"600\""));
        HttpResponse<String> res = post(base + "/records/apply", "{\"token\":\"" + token + "\"}");
        assertThat(res.statusCode()).isEqualTo(409);
        assertThat(res.body()).contains("\"code\":\"DNS_CHANGED_SINCE_PREVIEW\"");
        assertThat(NamecheapStub.requests("namecheap.domains.dns.setHosts")).isEmpty();
        assertThat(jdbc.queryForObject("select count(*) from dns_snapshots", Integer.class)).isZero();
        // Settings changed after the preview: the old token is refused too.
        String fresh = token(get(base + "/records/preview").body());
        settings(owner, "{\"mailIp\":\"203.0.113.99\"}");
        assertThat(post(base + "/records/apply", "{\"token\":\"" + fresh + "\"}").statusCode()).isEqualTo(409);
    }

    @Test
    void restorePutsBackTheSnapshotAndSnapshotsFirst() throws Exception {
        configure();
        post(base + "/records/apply", "{\"token\":\"" + token(get(base + "/records/preview").body()) + "\"}");
        String snapId = id(get(base + "/snapshots").body());

        HttpResponse<String> preview = get(base + "/snapshots/" + snapId + "/restore-preview");
        assertThat(preview.statusCode()).isEqualTo(200);
        assertThat(preview.body()).contains("{\"change\":\"ADD\",\"managed\":true,\"record\":{\"name\":\"@\",\"type\":\"URL\"");
        HttpResponse<String> res = post(base + "/snapshots/" + snapId + "/restore",
                "{\"token\":\"" + token(preview.body()) + "\"}");
        assertThat(res.statusCode()).as(res.body()).isEqualTo(200);
        assertThat(res.body()).contains("\"verified\":true");

        Map<String, String> sent = NamecheapStub.requests("namecheap.domains.dns.setHosts").getLast();
        assertThat(records(sent)).containsExactly("@ URL http://www.example-one.com/ 1800",
                "www CNAME parkingpage.namecheap.com. 1800", "@ TXT site-verification=FAKE-not-a-real-token 1799",
                "shop CNAME shops.example.net. 300", "@ TXT v=spf1 include:old-mail.example.net -all 1800",
                "@ MX/20 old-mail.example.net. 1800", "_dmarc TXT v=DMARC1; p=none 1800",
                "s1._domainkey TXT v=DKIM1; k=rsa; p=FAKEOTHERSELECTORKEY 1800");
        assertThat(jdbc.queryForList("select reason from dns_snapshots order by id", String.class))
                .containsExactly("BEFORE_SETUP", "BEFORE_RESTORE");
        assertThat(jdbc.queryForObject("select count(*) from activity_log where action = 'DNS_RECORDS_RESTORED'",
                Integer.class)).isOne();
    }

    @Test
    void unsafeWritesAreRefused() throws Exception {
        // No mail IP yet.
        assertThat(get(base + "/records/preview").body()).contains("DNS_WRITE_REFUSED", "mail server IP");
        configure();
        // DNS hosted elsewhere.
        NamecheapStub.answer("namecheap.domains.dns.getHosts", "getHosts-foreign-dns");
        assertThat(get(base + "/records/preview").body()).contains("DNS_WRITE_REFUSED", "does not use Namecheap DNS");
        // A record type setHosts can't send back.
        NamecheapStub.answer("namecheap.domains.dns.getHosts", "getHosts-unsupported-type");
        HttpResponse<String> srv = get(base + "/records/preview");
        assertThat(srv.statusCode()).isEqualTo(409);
        assertThat(srv.body()).contains("SRV record");
        // A manual domain.
        String manual = addManual("manual-only.example");
        HttpResponse<String> res = get("/api/v1/dns/domains/" + manual + "/records/preview");
        assertThat(res.statusCode()).isEqualTo(409);
        assertThat(res.body()).contains("Import this domain from Namecheap first");
        // Namecheap refusing the IP is passed on.
        NamecheapStub.answer("namecheap.domains.dns.getHosts", "error-ip-not-whitelisted");
        assertThat(get(base + "/records/preview").body()).contains("NAMECHEAP_IP_NOT_WHITELISTED");
        assertThat(NamecheapStub.requests("namecheap.domains.dns.setHosts")).isEmpty();
    }

    @Test
    void permissionsGateRecords() throws Exception {
        configure();
        String viewer = member("DNS:VIEW");
        assertThat(client.send("GET", base + "/dns-settings", viewer, null).statusCode()).isEqualTo(200);
        assertThat(client.send("GET", base + "/snapshots", viewer, null).statusCode()).isEqualTo(200);
        assertThat(client.send("PUT", base + "/dns-settings", viewer, "{}").statusCode()).isEqualTo(403);
        assertThat(client.send("GET", base + "/records/preview", viewer, null).statusCode()).isEqualTo(403);
        assertThat(client.send("POST", base + "/records/apply", viewer, "{\"token\":\"x\"}").statusCode()).isEqualTo(403);
        String none = member();
        assertThat(client.send("GET", base + "/dns-settings", none, null).statusCode()).isEqualTo(403);
        String editor = member("DNS:EDIT");
        assertThat(client.send("GET", base + "/records/preview", editor, null).statusCode()).isEqualTo(200);
    }

    // ---- helpers ------------------------------------------------------------------

    static String token(String planJson) {
        Matcher m = Pattern.compile("\"token\":\"([^\"]+)\"").matcher(planJson);
        assertThat(m.find()).isTrue();
        return m.group(1);
    }

    /** setHosts form fields as "name TYPE[/pref] address ttl" lines. */
    static List<String> records(Map<String, String> p) {
        List<String> out = new ArrayList<>();
        for (int n = 1; p.containsKey("HostName" + n); n++) {
            String type = p.get("RecordType" + n);
            out.add(p.get("HostName" + n) + " " + type + (type.equals("MX") ? "/" + p.get("MXPref" + n) : "") + " "
                    + p.get("Address" + n) + " " + p.get("TTL" + n));
        }
        return out;
    }

    /** What getHosts answers after a setHosts with these fields. */
    static String render(Map<String, String> p) {
        StringBuilder hosts = new StringBuilder();
        for (int n = 1; p.containsKey("HostName" + n); n++) {
            hosts.append("<host HostId=\"").append(n).append("\" Name=\"").append(xml(p.get("HostName" + n)))
                    .append("\" Type=\"").append(xml(p.get("RecordType" + n))).append("\" Address=\"")
                    .append(xml(p.get("Address" + n))).append("\" MXPref=\"").append(p.getOrDefault("MXPref" + n, "10"))
                    .append("\" TTL=\"").append(p.get("TTL" + n)).append("\" IsActive=\"true\" />\n");
        }
        return "<?xml version=\"1.0\" encoding=\"utf-8\"?><ApiResponse Status=\"OK\" "
                + "xmlns=\"http://api.namecheap.com/xml.response\"><Errors /><CommandResponse "
                + "Type=\"namecheap.domains.dns.getHosts\"><DomainDNSGetHostsResult Domain=\"example-one.com\" EmailType=\""
                + p.get("EmailType") + "\" IsUsingOurDNS=\"true\">" + hosts + "</DomainDNSGetHostsResult>"
                + "</CommandResponse></ApiResponse>";
    }

    static String xml(String v) {
        return v.replace("&", "&amp;").replace("\"", "&quot;").replace("<", "&lt;");
    }
}
