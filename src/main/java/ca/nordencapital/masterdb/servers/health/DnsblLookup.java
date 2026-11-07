package ca.nordencapital.masterdb.servers.health;

import ca.nordencapital.masterdb.dns.health.DnsLookup.LookupFailed;

import java.util.List;

/**
 * A-record lookups for blocklists (DNSBL). Separate from the DNS health
 * lookups because blocklists must be asked through a resolver they accept
 * ({@code app.servers.dnsbl-resolvers}). No such name = empty list;
 * timeouts and server failures throw {@link LookupFailed}. Tests use a fake.
 */
public interface DnsblLookup {

    List<String> a(String name);
}
