package ca.nordencapital.masterdb.dns.records;

import ca.nordencapital.masterdb.dns.HostRecord;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Which records MasterDB writes and which existing ones it replaces, ported
 * from the old app's NamecheapDns ({@code desired} / {@code managed}).
 * Everything else at Namecheap is kept as it is: setHosts replaces the whole
 * set, so the "after" list is always the unmanaged records plus ours.
 *
 * <p>Pure logic, no I/O, so the merge is unit-tested on its own.
 */
public final class ManagedRecords {

    /** Record types setHosts accepts, so they can be sent back unchanged (old app's SUPPORTED). */
    public static final Set<String> SUPPORTED = Set.of("A", "AAAA", "ALIAS", "CAA", "CNAME", "MX", "MXE", "NS",
            "TXT", "URL", "URL301", "FRAME");
    /** Types that answer for a host name (an A at @ replaces a URL redirect or a CNAME there). */
    static final Set<String> ADDRESS_TYPES = Set.of("A", "CNAME", "ALIAS", "URL", "URL301", "FRAME");

    private ManagedRecords() {
    }

    /** What the managed records should say. {@code mailIp} must be set. */
    public static List<HostRecord> desired(String domain, DnsSettings s) {
        String ip = s.mailIp();
        List<HostRecord> out = new ArrayList<>();
        out.add(HostRecord.of("@", "A", ip));
        out.add(HostRecord.of("mail", "A", ip));
        out.add(HostRecord.of("webmail", "A", ip));
        out.add(HostRecord.mx("@", "mail." + domain + ".", "10"));
        out.add(HostRecord.of("@", "TXT", "v=spf1 ip4:" + ip + " -all"));
        if (s.dkimPublicKey() != null) {
            out.add(HostRecord.of(s.dkimSelector() + "._domainkey", "TXT", "v=DKIM1; k=rsa; p=" + s.dkimPublicKey()));
        }
        out.add(HostRecord.of("_dmarc", "TXT", "v=DMARC1; p=" + s.dmarcPolicy()));
        if (s.bimiLogoUrl() != null) {
            out.add(HostRecord.of("default._bimi", "TXT", "v=BIMI1; l=" + s.bimiLogoUrl() + "; a="
                    + (s.bimiCertificateUrl() == null ? "" : s.bimiCertificateUrl())));
        }
        return out;
    }

    /**
     * True when the existing record is one of ours, to be replaced by the
     * desired set. DKIM and BIMI records are only ours when we write one
     * (otherwise a key set up elsewhere is kept).
     */
    public static boolean managed(HostRecord r, DnsSettings s) {
        String name = r.name().toLowerCase(Locale.ROOT);
        String type = r.type();
        if (name.equals("@")) {
            if (ADDRESS_TYPES.contains(type) || type.equals("MX") || type.equals("MXE")) {
                return true;
            }
            if (type.equals("TXT") && r.address().trim().toLowerCase(Locale.ROOT).startsWith("v=spf1")) {
                return true;
            }
        }
        if ((name.equals("mail") || name.equals("webmail")) && ADDRESS_TYPES.contains(type)) {
            return true;
        }
        if (name.equals("_dmarc") && type.equals("TXT")) {
            return true;
        }
        if (s.dkimPublicKey() != null && name.equals(s.dkimSelector() + "._domainkey") && type.equals("TXT")) {
            return true;
        }
        return s.bimiLogoUrl() != null && name.equals("default._bimi") && type.equals("TXT");
    }

    public enum Change { ADD, REMOVE, KEEP }

    /** {@code managed}: the record is one MasterDB manages (a KEEP of it means "unchanged"). */
    public record RecordChange(Change change, boolean managed, HostRecord record) {
    }

    public record Merge(List<RecordChange> changes, List<HostRecord> after) {
    }

    /** Setup: keep every unmanaged record, replace the managed ones by {@code desired}. */
    public static Merge merge(List<HostRecord> current, List<HostRecord> desired, DnsSettings s) {
        List<RecordChange> changes = new ArrayList<>();
        List<HostRecord> after = new ArrayList<>();
        List<HostRecord> currentManaged = new ArrayList<>();
        for (HostRecord r : current) {
            if (!managed(r, s)) {
                changes.add(new RecordChange(Change.KEEP, false, r));
                after.add(r);
            } else {
                currentManaged.add(r);
                boolean stays = desired.stream().anyMatch(d -> d.sameAs(r));
                changes.add(new RecordChange(stays ? Change.KEEP : Change.REMOVE, true, r));
            }
        }
        for (HostRecord d : desired) {
            if (currentManaged.stream().noneMatch(d::sameAs)) {
                changes.add(new RecordChange(Change.ADD, true, d));
            }
            after.add(d);
        }
        return new Merge(changes, after);
    }

    /** Restore: the target set exactly. */
    public static Merge replaceWith(List<HostRecord> current, List<HostRecord> target) {
        List<RecordChange> changes = new ArrayList<>();
        for (HostRecord r : current) {
            changes.add(new RecordChange(target.stream().anyMatch(t -> t.sameAs(r)) ? Change.KEEP : Change.REMOVE,
                    true, r));
        }
        for (HostRecord t : target) {
            if (current.stream().noneMatch(t::sameAs)) {
                changes.add(new RecordChange(Change.ADD, true, t));
            }
        }
        return new Merge(changes, List.copyOf(target));
    }

    /** Records of {@code expected} that {@code actual} lacks (checked after a write). */
    public static List<HostRecord> missing(List<HostRecord> expected, List<HostRecord> actual) {
        return expected.stream().filter(e -> actual.stream().noneMatch(e::sameAs)).toList();
    }
}
