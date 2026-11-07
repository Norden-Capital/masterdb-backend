package ca.nordencapital.masterdb.dns.health;

import ca.nordencapital.masterdb.dns.health.DnsLookup.Mx;
import ca.nordencapital.masterdb.dns.health.HealthChecks.Result;
import ca.nordencapital.masterdb.dns.health.HealthChecks.Status;
import ca.nordencapital.masterdb.dns.records.DnsSettings;
import ca.nordencapital.testsupport.FakeDnsLookup;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

/** DNS health rules against a fake DNS. */
class HealthChecksTest {

    static final String D = "example.com";
    static final String KEY = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAfakefakefakefakefakefakefake0123456789";
    static final DnsSettings SET = new DnsSettings("203.0.113.10", "mail", KEY, "quarantine", null, null, Instant.EPOCH);
    static final DnsSettings NONE = new DnsSettings(null, "mail", null, "quarantine", null, null, null);

    final FakeDnsLookup dns = new FakeDnsLookup();
    final HealthChecks checks = new HealthChecks(dns);

    List<Result> run(DnsSettings s) {
        return checks.all(D, s, s.updatedAt() != null, Optional.empty());
    }

    static String line(Result r) {
        return r.record() + " " + r.status();
    }

    @Test
    void aFullySetUpDomainIsGreen() {
        dns.healthy(D, KEY);
        List<Result> r = run(SET);
        assertThat(r).extracting(HealthChecksTest::line).containsExactly("A OK", "MX OK", "SPF OK", "DKIM OK",
                "DMARC OK", "BIMI NOT_CHECKED", "PTR NOT_CHECKED");
        assertThat(HealthChecks.overall(r)).isEqualTo(Status.OK);
        assertThat(r.get(5).detail()).isEqualTo("Not set up (optional).");
        assertThat(r.get(6).detail()).contains("servers are linked");
    }

    @Test
    void anEmptyDomainHasAReasonPerRecord() {
        List<Result> r = run(NONE);
        assertThat(r).extracting(HealthChecksTest::line).containsExactly("A PROBLEM", "MX PROBLEM", "SPF PROBLEM",
                "DKIM NOT_CHECKED", "DMARC PROBLEM", "BIMI NOT_CHECKED", "PTR NOT_CHECKED");
        assertThat(r).extracting(Result::detail).contains("No A record at the root of example.com.",
                "No MX record at the root.", "No SPF record (TXT v=spf1) at the root.",
                "No DKIM selector known. Set one under Managed records.", "No DMARC record at _dmarc.example.com.");
        assertThat(HealthChecks.overall(r)).isEqualTo(Status.PROBLEM);
    }

    @Test
    void wrongValuesAreNamed() {
        dns.healthy(D, "OTHERKEY0000").a(D, "198.51.100.7")
                .mx(D, new Mx(10, "mx.elsewhere.net"))
                .mx(D + "." + D, new Mx(10, "mail." + D))
                .txt("_dmarc." + D, "v=DMARC1; p=none");
        List<Result> r = run(SET);
        assertThat(r.get(0).detail()).isEqualTo("The root A record is 198.51.100.7, not the mail server IP 203.0.113.10.");
        assertThat(r.get(1).detail()).contains("MX points to 10 mx.elsewhere.net, not mail.example.com.",
                "published at example.com.example.com");
        assertThat(r.get(3).detail()).contains("is not the saved one");
        assertThat(r.get(4).detail()).isEqualTo("DMARC policy is none, not quarantine.");
    }

    @Test
    void spfRules() {
        dns.healthy(D, KEY).txt(D, "v=spf1 ip4:203.0.113.10 -all", "v=spf1 include:x.net ~all");
        assertThat(run(SET).get(2).detail()).startsWith("2 SPF records");
        dns.txt(D, "v=spf1 ip4:203.0.113.10 +all");
        assertThat(run(SET).get(2).detail()).contains("+all");
        dns.txt(D, "v=spf1 include:x.net -all");
        assertThat(run(SET).get(2).detail()).isEqualTo("SPF does not include ip4:203.0.113.10.");
        dns.txt(D, "v=spf1 ip4:203.0.113.10/32 ~all");
        assertThat(run(SET).get(2).status()).isEqualTo(Status.OK);
        // Without a mail IP any single well-formed SPF passes.
        dns.txt(D, "v=spf1 include:x.net -all");
        assertThat(run(NONE).get(2).status()).isEqualTo(Status.OK);
    }

    @Test
    void dkimAndBimiDetails() {
        dns.healthy(D, KEY).txt("mail._domainkey." + D, "v=DKIM1; k=rsa; p=");
        assertThat(run(SET).get(3).detail()).contains("empty key");
        dns.txt("mail._domainkey." + D, new String[0]);
        assertThat(run(SET).get(3).detail()).isEqualTo("No DKIM record at mail._domainkey.example.com.");
        DnsSettings bimi = new DnsSettings("203.0.113.10", "mail", KEY, "quarantine", "https://example.com/l.svg", null,
                Instant.EPOCH);
        assertThat(run(bimi).get(5).status()).isEqualTo(Status.PROBLEM);
        dns.txt("default._bimi." + D, "v=BIMI1; l=https://example.com/l.svg; a=");
        assertThat(run(bimi).get(5).status()).isEqualTo(Status.OK);
        dns.txt("default._bimi." + D, "v=BIMI1; l=http://example.com/l.svg");
        assertThat(run(NONE).get(5).detail()).contains("no https logo");
    }

    @Test
    void aFailedLookupIsAnErrorNotAProblem() {
        dns.healthy(D, KEY).fail("_dmarc." + D);
        List<Result> r = run(SET);
        assertThat(line(r.get(4))).isEqualTo("DMARC ERROR");
        assertThat(r.get(4).detail()).contains("failed (timeout)");
        assertThat(HealthChecks.overall(r)).isEqualTo(Status.ERROR);
    }

    @Test
    void ptrIsCheckedOnceAServerIsLinked() {
        dns.healthy(D, KEY).ptr("203.0.113.10", "vps123.provider.example");
        Optional<PtrExpectations.Expected> linked = Optional.of(new PtrExpectations.Expected("203.0.113.10", "mail." + D));
        Result r = checks.all(D, SET, true, linked).get(6);
        assertThat(r.status()).isEqualTo(Status.PROBLEM);
        assertThat(r.detail()).contains("is vps123.provider.example, not mail.example.com");
        dns.ptr("203.0.113.10", "mail." + D);
        assertThat(checks.all(D, SET, true, linked).get(6).status()).isEqualTo(Status.OK);
        assertThat(new PtrExpectations().forDomain(1, D)).isEmpty();
    }

    @Test
    void txtPartsAreJoined() {
        assertThat(JndiDnsLookup.joinTxt("\"v=DKIM1; k=rsa; \" \"p=MIIB\\\"x\"")).isEqualTo("v=DKIM1; k=rsa; p=MIIB\"x");
        assertThat(JndiDnsLookup.joinTxt("v=spf1 -all")).isEqualTo("v=spf1 -all");
    }
}
