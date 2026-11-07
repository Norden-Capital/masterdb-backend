package ca.nordencapital.masterdb.dns.health;

import ca.nordencapital.masterdb.dns.health.DnsLookup.LookupFailed;
import ca.nordencapital.masterdb.dns.health.DnsLookup.Mx;
import ca.nordencapital.masterdb.dns.records.DnsSettings;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.function.Supplier;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The DNS health rules (DNS job 4), over public DNS. What is "expected"
 * comes from the domain's managed-record settings when they are set (mail
 * IP, DKIM selector and key, DMARC policy, BIMI); without them a record only
 * has to exist and be well-formed. The MX "published at domain.domain"
 * hint is the old app's DnsHealth check.
 */
public final class HealthChecks {

    public enum Status { OK, PROBLEM, ERROR, NOT_CHECKED }

    public record Result(String record, Status status, String detail, String expected, String found) {
    }

    private static final Pattern DMARC_POLICY = Pattern.compile("(?i)(?:^|;)\\s*p\\s*=\\s*([a-z]+)");
    private static final Pattern DKIM_KEY = Pattern.compile("(?i)(?:^|;)\\s*p\\s*=\\s*([^;]*)");
    private static final Pattern BIMI_LOGO = Pattern.compile("(?i)(?:^|;)\\s*l\\s*=\\s*([^;]*)");

    private final DnsLookup dns;

    public HealthChecks(DnsLookup dns) {
        this.dns = dns;
    }

    /**
     * @param settingsSaved true once someone saved the managed-record settings: only then is the
     *                      DKIM selector "known" and the DMARC policy an expectation
     */
    public List<Result> all(String domain, DnsSettings s, boolean settingsSaved, Optional<PtrExpectations.Expected> ptr) {
        List<Result> out = new ArrayList<>();
        out.add(safe("A", () -> a(domain, s)));
        out.add(safe("MX", () -> mx(domain, s)));
        out.add(safe("SPF", () -> spf(domain, s)));
        out.add(safe("DKIM", () -> dkim(domain, s, settingsSaved)));
        out.add(safe("DMARC", () -> dmarc(domain, s, settingsSaved)));
        out.add(safe("BIMI", () -> bimi(domain, s)));
        out.add(safe("PTR", () -> ptr(ptr)));
        return out;
    }

    /** PROBLEM if any record has one, else ERROR if a lookup failed, else OK. */
    public static Status overall(List<Result> results) {
        if (results.stream().anyMatch(r -> r.status() == Status.PROBLEM)) {
            return Status.PROBLEM;
        }
        return results.stream().anyMatch(r -> r.status() == Status.ERROR) ? Status.ERROR : Status.OK;
    }

    Result a(String domain, DnsSettings s) {
        List<String> found = dns.a(domain);
        String expected = s.mailIp();
        if (found.isEmpty()) {
            return problem("A", "No A record at the root of " + domain + ".", expected, null);
        }
        if (expected != null && !found.contains(expected)) {
            return problem("A", "The root A record is " + String.join(", ", found) + ", not the mail server IP "
                    + expected + ".", expected, String.join(", ", found));
        }
        return ok("A", "Root A record: " + String.join(", ", found) + ".", expected, String.join(", ", found));
    }

    Result mx(String domain, DnsSettings s) {
        List<Mx> found = dns.mx(domain);
        String expected = s.mailIp() == null ? null : "mail." + domain;
        String list = found.stream().map(m -> m.preference() + " " + m.host()).reduce((x, y) -> x + ", " + y).orElse(null);
        if (found.isEmpty() || (expected != null && found.stream().noneMatch(m -> m.host().equalsIgnoreCase(expected)))) {
            String misplaced = "";
            if (expected != null && misplaced(domain, expected)) {
                misplaced = " An MX was published at " + domain + "." + domain
                        + " instead: in Namecheap the host must be @, not the domain name.";
            }
            return problem("MX", (found.isEmpty() ? "No MX record at the root." : "MX points to " + list
                    + ", not " + expected + ".") + misplaced, expected, list);
        }
        return ok("MX", "MX: " + list + ".", expected, list);
    }

    private boolean misplaced(String domain, String expected) {
        try {
            return dns.mx(domain + "." + domain).stream().anyMatch(m -> m.host().equalsIgnoreCase(expected));
        } catch (LookupFailed e) {
            return false;
        }
    }

    Result spf(String domain, DnsSettings s) {
        List<String> spf = dns.txt(domain).stream().filter(t -> t.trim().toLowerCase(Locale.ROOT).matches("v=spf1(\\s.*)?"))
                .toList();
        String expected = s.mailIp() == null ? null : "ip4:" + s.mailIp();
        if (spf.isEmpty()) {
            return problem("SPF", "No SPF record (TXT v=spf1) at the root.", expected, null);
        }
        String found = String.join(" | ", spf);
        if (spf.size() > 1) {
            return problem("SPF", spf.size() + " SPF records: only one is allowed, receivers treat this as an error.",
                    expected, found);
        }
        String record = " " + spf.getFirst().toLowerCase(Locale.ROOT) + " ";
        if (record.contains(" +all ") || record.contains(" all ")) {
            return problem("SPF", "SPF ends in +all: it lets any server send as this domain.", expected, found);
        }
        if (expected != null && !record.contains(" " + expected + " ") && !record.contains(" " + expected + "/32 ")) {
            return problem("SPF", "SPF does not include " + expected + ".", expected, found);
        }
        return ok("SPF", "One SPF record" + (expected == null ? "." : " including " + expected + "."), expected, found);
    }

    Result dkim(String domain, DnsSettings s, boolean settingsSaved) {
        if (!settingsSaved && s.dkimPublicKey() == null) {
            return new Result("DKIM", Status.NOT_CHECKED, "No DKIM selector known. Set one under Managed records.",
                    null, null);
        }
        String host = s.dkimSelector() + "._domainkey." + domain;
        List<String> found = dns.txt(host).stream().filter(t -> t.toLowerCase(Locale.ROOT).contains("p=")).toList();
        String expected = s.dkimPublicKey() == null ? null : "p=" + s.dkimPublicKey();
        if (found.isEmpty()) {
            return problem("DKIM", "No DKIM record at " + host + ".", expected, null);
        }
        String record = found.getFirst();
        Matcher m = DKIM_KEY.matcher(record);
        String key = m.find() ? m.group(1).replaceAll("\\s", "") : "";
        if (key.isEmpty()) {
            return problem("DKIM", "The DKIM record at " + host + " has an empty key (revoked).", expected, cut(record));
        }
        if (s.dkimPublicKey() != null && !key.equals(s.dkimPublicKey())) {
            return problem("DKIM", "The published DKIM key at " + host + " is not the saved one.", cut(expected),
                    cut(record));
        }
        return ok("DKIM", "DKIM key published at " + host + ".", cut(expected), cut(record));
    }

    Result dmarc(String domain, DnsSettings s, boolean settingsSaved) {
        List<String> found = dns.txt("_dmarc." + domain).stream()
                .filter(t -> t.trim().toUpperCase(Locale.ROOT).startsWith("V=DMARC1")).toList();
        String expected = settingsSaved ? "p=" + s.dmarcPolicy() : null;
        if (found.isEmpty()) {
            return problem("DMARC", "No DMARC record at _dmarc." + domain + ".", expected, null);
        }
        if (found.size() > 1) {
            return problem("DMARC", found.size() + " DMARC records: receivers ignore them all.", expected,
                    String.join(" | ", found));
        }
        Matcher m = DMARC_POLICY.matcher(found.getFirst());
        String policy = m.find() ? m.group(1).toLowerCase(Locale.ROOT) : "";
        if (!List.of("none", "quarantine", "reject").contains(policy)) {
            return problem("DMARC", "The DMARC record has no valid p= policy.", expected, found.getFirst());
        }
        if (settingsSaved && !policy.equals(s.dmarcPolicy())) {
            return problem("DMARC", "DMARC policy is " + policy + ", not " + s.dmarcPolicy() + ".", expected,
                    found.getFirst());
        }
        return ok("DMARC", "DMARC policy " + policy + (policy.equals("none") ? " (monitoring only)." : "."), expected,
                found.getFirst());
    }

    Result bimi(String domain, DnsSettings s) {
        List<String> found = dns.txt("default._bimi." + domain).stream()
                .filter(t -> t.trim().toUpperCase(Locale.ROOT).startsWith("V=BIMI1")).toList();
        String expected = s.bimiLogoUrl() == null ? null : "l=" + s.bimiLogoUrl();
        if (found.isEmpty()) {
            return s.bimiLogoUrl() == null
                    ? new Result("BIMI", Status.NOT_CHECKED, "Not set up (optional).", null, null)
                    : problem("BIMI", "No BIMI record at default._bimi." + domain + ".", expected, null);
        }
        Matcher m = BIMI_LOGO.matcher(found.getFirst());
        String logo = m.find() ? m.group(1).trim() : "";
        if (!logo.toLowerCase(Locale.ROOT).startsWith("https://")) {
            return problem("BIMI", "The BIMI record has no https logo (l=).", expected, found.getFirst());
        }
        if (s.bimiLogoUrl() != null && !logo.equals(s.bimiLogoUrl())) {
            return problem("BIMI", "The BIMI logo is " + logo + ", not the saved one.", expected, found.getFirst());
        }
        return ok("BIMI", "BIMI logo published.", expected, found.getFirst());
    }

    Result ptr(Optional<PtrExpectations.Expected> expectation) {
        if (expectation.isEmpty()) {
            return new Result("PTR", Status.NOT_CHECKED,
                    "Checked once servers are linked to domains (Server management).", null, null);
        }
        PtrExpectations.Expected e = expectation.get();
        List<String> found = dns.ptr(e.ip());
        String list = found.isEmpty() ? null : String.join(", ", found);
        if (found.stream().noneMatch(h -> h.equalsIgnoreCase(e.host()))) {
            return problem("PTR", "Reverse DNS of " + e.ip() + " is " + (list == null ? "not set" : list) + ", not "
                    + e.host() + ". Set it at the VPS provider.", e.host(), list);
        }
        return ok("PTR", "Reverse DNS of " + e.ip() + " is " + e.host() + ".", e.host(), list);
    }

    private static Result safe(String record, Supplier<Result> check) {
        try {
            return check.get();
        } catch (LookupFailed e) {
            return new Result(record, Status.ERROR, e.getMessage() + ". Try again later.", null, null);
        }
    }

    private static Result ok(String record, String detail, String expected, String found) {
        return new Result(record, Status.OK, detail, expected, found);
    }

    private static Result problem(String record, String detail, String expected, String found) {
        return new Result(record, Status.PROBLEM, detail, expected, found);
    }

    private static String cut(String v) {
        return v == null || v.length() <= 300 ? v : v.substring(0, 300) + "…";
    }
}
