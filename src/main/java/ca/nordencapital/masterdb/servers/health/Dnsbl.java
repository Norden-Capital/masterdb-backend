package ca.nordencapital.masterdb.servers.health;

import ca.nordencapital.masterdb.dns.health.DnsLookup.LookupFailed;
import ca.nordencapital.masterdb.servers.Ipv4;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Blocklists (DNSBL) and how to read their answers. A query is
 * {@code <reversed IP>.<zone>}: no answer (NXDOMAIN) means not listed; an
 * answer in 127.0.0.0/24 means listed (the last number says why). Spamhaus
 * answers 127.255.255.252/254/255 when it REFUSES the query (typo, public or
 * shared resolver, too many queries): that says nothing about the IP, so it is
 * "couldn't check", never "not listed". Any other answer (outside 127/8,
 * often a resolver that rewrites NXDOMAIN) is also "couldn't check".
 */
public final class Dnsbl {

    public record Zone(String zone, String label, Map<Integer, String> reasons) {
    }

    public enum Outcome { CLEAN, LISTED, UNKNOWN }

    public record Answer(Zone zone, Outcome outcome, String text) {
    }

    /** Spamhaus ZEN return codes (spamhaus.org/faq: "DNSBL return codes"). */
    static final Map<Integer, String> ZEN = Map.of(
            2, "SBL (spam source)",
            3, "SBL CSS (snowshoe spam)",
            4, "XBL (exploited / botnet)",
            5, "XBL",
            6, "XBL",
            7, "XBL",
            9, "SBL DROP (hijacked network)",
            10, "PBL (ISP says: should not send mail directly)",
            11, "PBL (Spamhaus says: should not send mail directly)");

    public static final List<Zone> ZONES = List.of(
            new Zone("zen.spamhaus.org", "Spamhaus ZEN", ZEN),
            new Zone("b.barracudacentral.org", "Barracuda", Map.of(2, "listed")),
            new Zone("bl.spamcop.net", "SpamCop", Map.of(2, "listed")),
            new Zone("psbl.surriel.com", "PSBL", Map.of(2, "listed")),
            new Zone("dnsbl-1.uceprotect.net", "UCEPROTECT level 1", Map.of(2, "listed")),
            new Zone("bl.mailspike.net", "Mailspike", Map.of(2, "listed")));

    /** What 127.255.255.x means when a blocklist (Spamhaus) refuses to answer. */
    static final Map<Integer, String> REFUSED = Map.of(
            252, "refused: typo in the query",
            254, "refused the query: it doesn't answer public or shared resolvers (set APP_DNSBL_RESOLVERS, or use "
                    + "a Spamhaus Data Query Service key later)",
            255, "refused: too many queries from this resolver");

    private Dnsbl() {
    }

    public static List<Answer> check(DnsblLookup dns, String ip) {
        String reversed = Ipv4.reversed(ip);
        List<Answer> out = new ArrayList<>();
        for (Zone z : ZONES) {
            out.add(ask(dns, reversed, z));
        }
        return out;
    }

    static Answer ask(DnsblLookup dns, String reversed, Zone z) {
        List<String> found;
        try {
            found = dns.a(reversed + "." + z.zone());
        } catch (LookupFailed e) {
            return new Answer(z, Outcome.UNKNOWN, "lookup failed (timeout or server error)");
        }
        return read(z, found);
    }

    /** One blocklist's answer, read with its return codes. */
    static Answer read(Zone z, List<String> found) {
        if (found.isEmpty()) {
            return new Answer(z, Outcome.CLEAN, "not listed");
        }
        List<String> reasons = new ArrayList<>();
        String unknown = null;
        for (String a : found) {
            String ip = a.trim();
            if (ip.startsWith("127.255.255.")) {
                int last = lastOctet(ip);
                unknown = REFUSED.getOrDefault(last, "refused the query (" + ip + ")");
            } else if (ip.startsWith("127.0.0.") && lastOctet(ip) >= 2) {
                int last = lastOctet(ip);
                reasons.add(z.reasons().getOrDefault(last, "listed") + " [" + ip + "]");
            } else {
                unknown = "unexpected answer " + ip + " (the resolver may rewrite missing names)";
            }
        }
        if (!reasons.isEmpty()) {
            return new Answer(z, Outcome.LISTED, String.join(", ", reasons));
        }
        return new Answer(z, Outcome.UNKNOWN, unknown == null ? "unreadable answer" : unknown);
    }

    private static int lastOctet(String ip) {
        try {
            return Integer.parseInt(ip.substring(ip.lastIndexOf('.') + 1));
        } catch (NumberFormatException e) {
            return -1;
        }
    }
}
