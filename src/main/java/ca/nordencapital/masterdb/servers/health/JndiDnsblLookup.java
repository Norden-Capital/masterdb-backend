package ca.nordencapital.masterdb.servers.health;

import ca.nordencapital.masterdb.dns.health.JndiDnsLookup;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.List;

/** {@link DnsblLookup} through JNDI, asking {@code app.servers.dnsbl-resolvers} (empty = the system resolver). */
@Component
public class JndiDnsblLookup implements DnsblLookup {

    private final JndiDnsLookup dns;

    public JndiDnsblLookup(@Value("${app.servers.dnsbl-resolvers:}") String resolvers,
            @Value("${app.dns.timeout:3s}") Duration timeout) {
        this.dns = new JndiDnsLookup(resolvers, timeout);
    }

    @Override
    public List<String> a(String name) {
        return dns.a(name);
    }
}
