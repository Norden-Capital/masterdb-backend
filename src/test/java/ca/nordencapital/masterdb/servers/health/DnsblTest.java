package ca.nordencapital.masterdb.servers.health;

import ca.nordencapital.masterdb.servers.health.Dnsbl.Outcome;
import ca.nordencapital.masterdb.servers.health.Dnsbl.Zone;
import ca.nordencapital.testsupport.FakeDnsblLookup;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/** Blocklist answers are read with their return codes; refusals are never "not listed". */
class DnsblTest {

    static final Zone ZEN = Dnsbl.ZONES.getFirst();
    static final Zone BARRACUDA = Dnsbl.ZONES.get(1);

    @Test
    void noAnswerIsClean() {
        assertThat(Dnsbl.read(ZEN, List.of()).outcome()).isEqualTo(Outcome.CLEAN);
    }

    @Test
    void spamhausCodesAreNamed() {
        assertThat(Dnsbl.read(ZEN, List.of("127.0.0.2")).text()).isEqualTo("SBL (spam source) [127.0.0.2]");
        assertThat(Dnsbl.read(ZEN, List.of("127.0.0.4", "127.0.0.11")))
                .satisfies(a -> {
                    assertThat(a.outcome()).isEqualTo(Outcome.LISTED);
                    assertThat(a.text()).contains("XBL (exploited / botnet) [127.0.0.4]",
                            "PBL (Spamhaus says: should not send mail directly) [127.0.0.11]");
                });
        assertThat(Dnsbl.read(ZEN, List.of("127.0.0.42")).text()).isEqualTo("listed [127.0.0.42]");
    }

    @Test
    void spamhausRefusalsAreUnknownNotClean() {
        for (String code : List.of("127.255.255.252", "127.255.255.254", "127.255.255.255")) {
            assertThat(Dnsbl.read(ZEN, List.of(code)).outcome()).as(code).isEqualTo(Outcome.UNKNOWN);
        }
        assertThat(Dnsbl.read(ZEN, List.of("127.255.255.254")).text()).contains("public or shared resolvers");
        assertThat(Dnsbl.read(ZEN, List.of("127.255.255.255")).text()).contains("too many queries");
    }

    @Test
    void answersOutsideTheBlocklistRangeAreUnknown() {
        assertThat(Dnsbl.read(BARRACUDA, List.of("198.51.100.7")).outcome()).isEqualTo(Outcome.UNKNOWN);
        assertThat(Dnsbl.read(BARRACUDA, List.of("127.0.0.1")).outcome()).isEqualTo(Outcome.UNKNOWN);
        assertThat(Dnsbl.read(BARRACUDA, List.of("127.0.0.2")).outcome()).isEqualTo(Outcome.LISTED);
    }

    @Test
    void everyListIsAskedWithTheReversedIp() {
        FakeDnsblLookup dns = new FakeDnsblLookup();
        dns.fail("4.3.2.1.bl.spamcop.net");
        List<Dnsbl.Answer> answers = Dnsbl.check(dns, "1.2.3.4");
        assertThat(dns.asked()).hasSize(Dnsbl.ZONES.size()).allMatch(n -> n.startsWith("4.3.2.1."))
                .contains("4.3.2.1.zen.spamhaus.org", "4.3.2.1.b.barracudacentral.org");
        assertThat(answers.get(2).outcome()).isEqualTo(Outcome.UNKNOWN);
    }
}
