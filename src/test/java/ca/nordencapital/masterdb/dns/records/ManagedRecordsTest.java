package ca.nordencapital.masterdb.dns.records;

import ca.nordencapital.masterdb.dns.HostRecord;
import ca.nordencapital.masterdb.dns.records.ManagedRecords.Change;
import ca.nordencapital.masterdb.dns.records.ManagedRecords.Merge;
import ca.nordencapital.masterdb.web.error.BadRequestException;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** The merge before setHosts: unmanaged records always survive. */
class ManagedRecordsTest {

    static final String KEY = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAfakefakefakefakefakefakefake0123456789";
    static final DnsSettings FULL = new DnsSettings("203.0.113.10", "mail", KEY, "quarantine",
            "https://example.com/logo.svg", "https://example.com/vmc.pem", null);
    static final DnsSettings NO_DKIM = new DnsSettings("203.0.113.10", "mail", null, "reject", null, null, null);

    @Test
    void desiredRecordsAreTheOldAppsDefaults() {
        assertThat(ManagedRecords.desired("example.com", FULL)).extracting(r -> r.name() + " " + r.type() + " "
                + (r.type().equals("MX") ? r.mxPref() + " " : "") + r.address() + " " + r.ttl()).containsExactly(
                "@ A 203.0.113.10 1800",
                "mail A 203.0.113.10 1800",
                "webmail A 203.0.113.10 1800",
                "@ MX 10 mail.example.com. 1800",
                "@ TXT v=spf1 ip4:203.0.113.10 -all 1800",
                "mail._domainkey TXT v=DKIM1; k=rsa; p=" + KEY + " 1800",
                "_dmarc TXT v=DMARC1; p=quarantine 1800",
                "default._bimi TXT v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem 1800");
        assertThat(ManagedRecords.desired("example.com", NO_DKIM)).extracting(HostRecord::name)
                .doesNotContain("mail._domainkey", "default._bimi");
    }

    @Test
    void mergeKeepsEveryRecordItDoesNotManage() {
        List<HostRecord> current = List.of(
                HostRecord.of("@", "URL", "http://www.example.com/"),
                HostRecord.of("www", "CNAME", "parkingpage.namecheap.com."),
                HostRecord.of("@", "TXT", "site-verification=abc"),
                new HostRecord("shop", "CNAME", "shops.example.net.", "", "300", "", ""),
                HostRecord.of("@", "TXT", "v=spf1 include:old.example.net -all"),
                HostRecord.mx("@", "old.example.net.", "20"),
                HostRecord.of("_dmarc", "TXT", "v=DMARC1; p=none"),
                HostRecord.of("mail._domainkey", "TXT", "v=DKIM1; k=rsa; p=OLDKEY"),
                HostRecord.of("@", "AAAA", "2001:db8::1"),
                HostRecord.mx("sub", "mx.example.net.", "10"),
                new HostRecord("@", "CAA", "letsencrypt.org", "", "1800", "0", "issue"),
                HostRecord.of("mail", "A", "203.0.113.10"));

        Merge merge = ManagedRecords.merge(current, ManagedRecords.desired("example.com", NO_DKIM), NO_DKIM);

        // Unmanaged: kept, unchanged, including TTL and CAA flag/tag.
        assertThat(merge.after()).contains(current.get(1), current.get(2), current.get(3), current.get(7),
                current.get(8), current.get(9), current.get(10));
        // Managed and different: gone.
        assertThat(merge.after()).doesNotContain(current.get(0), current.get(4), current.get(5), current.get(6));
        assertThat(merge.changes()).filteredOn(c -> c.change() == Change.REMOVE).extracting(c -> c.record())
                .containsExactly(current.get(0), current.get(4), current.get(5), current.get(6));
        // Same as desired: unchanged, not re-added.
        assertThat(merge.changes()).filteredOn(c -> c.record().equals(current.get(11)))
                .singleElement().satisfies(c -> assertThat(c.change()).isEqualTo(Change.KEEP));
        assertThat(merge.changes()).filteredOn(c -> c.change() == Change.ADD).extracting(c -> c.record().name())
                .containsExactly("@", "webmail", "@", "@", "_dmarc");
        // Without a key of ours, a DKIM record set up elsewhere stays.
        assertThat(merge.after()).contains(current.get(7));
        // With one, ours replaces it.
        Merge withKey = ManagedRecords.merge(current, ManagedRecords.desired("example.com", FULL), FULL);
        assertThat(withKey.after()).doesNotContain(current.get(7));
        assertThat(withKey.after()).contains(current.get(1), current.get(2), current.get(3), current.get(8));
    }

    @Test
    void restoreGoesBackToExactlyTheSnapshot() {
        List<HostRecord> now = List.of(HostRecord.of("@", "A", "203.0.113.10"), HostRecord.of("www", "CNAME", "x."));
        List<HostRecord> then = List.of(HostRecord.of("@", "URL", "http://x/"), HostRecord.of("www", "CNAME", "x."));
        Merge m = ManagedRecords.replaceWith(now, then);
        assertThat(m.after()).isEqualTo(then);
        assertThat(m.changes()).extracting(c -> c.change() + " " + c.record().type())
                .containsExactly("REMOVE A", "KEEP CNAME", "ADD URL");
    }

    @Test
    void recordsCompareLikeDns() {
        assertThat(HostRecord.of("@", "CNAME", "Mail.Example.com.").sameAs(HostRecord.of("@", "cname", "mail.example.com")))
                .isTrue();
        assertThat(HostRecord.mx("@", "a.", "10").sameAs(HostRecord.mx("@", "a.", "20"))).isFalse();
        assertThat(HostRecord.of("@", "TXT", "V=spf1").sameAs(HostRecord.of("@", "TXT", "v=spf1"))).isFalse();
        assertThat(new HostRecord("@", "A", "1.2.3.4", "", "abc", "", "").ttl()).isEqualTo("1800");
    }

    @Test
    void settingsAreChecked() {
        DnsSettings ok = DnsRecordService.validate(new DnsSettings(" 203.0.113.10 ", "", "\"v=DKIM1; k=rsa; p="
                + KEY.substring(0, 40) + " " + KEY.substring(40) + "\"", "", "", "", null));
        assertThat(ok).extracting(DnsSettings::mailIp, DnsSettings::dkimSelector, DnsSettings::dkimPublicKey,
                DnsSettings::dmarcPolicy, DnsSettings::bimiLogoUrl).containsExactly("203.0.113.10", "mail", KEY,
                "quarantine", null);
        assertThatThrownBy(() -> DnsRecordService.validate(new DnsSettings("300.1.1.1", "bad selector!", "%%%",
                "always", "http://x.com/l.svg", "ftp://x.com/c.pem", null)))
                .isInstanceOfSatisfying(BadRequestException.class, e -> assertThat(e.getErrors())
                        .extracting(v -> v.field()).containsExactly("mailIp", "dkimSelector", "dkimPublicKey",
                                "dmarcPolicy", "bimiLogoUrl", "bimiCertificateUrl"));
        assertThatThrownBy(() -> DnsRecordService.validate(new DnsSettings(null, "mail", null, "none", null,
                "https://x.com/c.pem", null))).isInstanceOf(BadRequestException.class);
    }
}
