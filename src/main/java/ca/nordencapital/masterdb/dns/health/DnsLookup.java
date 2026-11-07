package ca.nordencapital.masterdb.dns.health;

import java.util.List;

/**
 * Public DNS lookups for the health checks. A name that does not exist, or
 * has no record of that type, gives an empty list; anything else that goes
 * wrong (timeout, SERVFAIL) throws {@link LookupFailed}. Tests replace the
 * bean with a fake: no test touches real DNS.
 */
public interface DnsLookup {

    List<String> a(String name);

    List<Mx> mx(String name);

    /** Each TXT record as one string (multi-part records joined, quotes removed). */
    List<String> txt(String name);

    /** Reverse DNS of an IPv4 address: host names, without the trailing dot. */
    List<String> ptr(String ipv4);

    record Mx(int preference, String host) {
    }

    class LookupFailed extends RuntimeException {
        public LookupFailed(String message) {
            super(message);
        }
    }
}
