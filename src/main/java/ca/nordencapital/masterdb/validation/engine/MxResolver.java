package ca.nordencapital.masterdb.validation.engine;

import ca.nordencapital.masterdb.dns.health.DnsLookup;
import ca.nordencapital.masterdb.dns.health.DnsLookup.LookupFailed;
import ca.nordencapital.masterdb.servers.Ipv4;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The mail servers of a domain, in MX preference order, each with one public
 * IPv4 address (probes leave from the VPS's IPv4). No MX = the domain itself
 * (RFC 5321 implicit MX); a "null MX" ({@code MX 0 .}) = the domain accepts no
 * mail. Answers are kept 15 minutes (2 minutes when a lookup failed).
 */
@Component
public class MxResolver {

    /** At most this many mail servers are tried for one address. */
    static final int MAX_HOSTS = 5;
    private static final Duration TTL = Duration.ofMinutes(15);
    private static final Duration FAILED_TTL = Duration.ofMinutes(2);

    private final DnsLookup dns;
    private final Clock clock;
    private final boolean allowPrivate;
    private final Map<String, Cached> cache = new LinkedHashMap<>(256, .75f, true) {
        @Override
        protected boolean removeEldestEntry(Map.Entry<String, Cached> eldest) {
            return size() > 4096;
        }
    };

    public MxResolver(DnsLookup dns, Clock clock,
            @Value("${app.validation.allow-private-mx:false}") boolean allowPrivate) {
        this.dns = dns;
        this.clock = clock;
        this.allowPrivate = allowPrivate;
    }

    /** One mail server: its name, and its address or why it has none. */
    public record Host(String name, String ip, String problem) {
        public boolean ready() {
            return ip != null;
        }
    }

    /**
     * {@code nullMx}: the domain says it takes no mail. {@code problem}: the
     * lookup itself failed or found nothing (hosts empty).
     */
    public record Destinations(List<Host> hosts, boolean nullMx, String problem) {
        /** The first mail server's name (or the domain): what pacing and the results show. */
        public String primary(String domain) {
            return hosts.isEmpty() ? domain : hosts.getFirst().name();
        }
    }

    private record Cached(Destinations value, Instant at, boolean failed) {
    }

    /** Drops every remembered answer (tests). */
    public void forget() {
        synchronized (cache) {
            cache.clear();
        }
    }

    public Destinations resolve(String domain) {
        Instant now = clock.instant();
        synchronized (cache) {
            Cached c = cache.get(domain);
            if (c != null && c.at().plus(c.failed() ? FAILED_TTL : TTL).isAfter(now)) {
                return c.value();
            }
        }
        Destinations fresh = lookup(domain);
        boolean failed = fresh.problem() != null || fresh.hosts().stream().anyMatch(h -> !h.ready());
        synchronized (cache) {
            cache.put(domain, new Cached(fresh, now, failed));
        }
        return fresh;
    }

    private Destinations lookup(String domain) {
        List<DnsLookup.Mx> mx;
        try {
            mx = new ArrayList<>(dns.mx(domain));
        } catch (LookupFailed e) {
            return new Destinations(List.of(), false, "The domain's mail servers couldn't be looked up (DNS "
                    + "didn't answer in time).");
        }
        if (mx.stream().anyMatch(m -> m.host() == null || m.host().isBlank() || m.host().equals("."))) {
            return new Destinations(List.of(), true, null);
        }
        if (mx.isEmpty()) {
            mx.add(new DnsLookup.Mx(0, domain));
        }
        mx.sort(Comparator.comparingInt(DnsLookup.Mx::preference));
        List<Host> hosts = new ArrayList<>();
        for (DnsLookup.Mx m : mx) {
            if (hosts.size() >= MAX_HOSTS) {
                break;
            }
            if (hosts.stream().anyMatch(h -> h.name().equals(m.host()))) {
                continue;
            }
            try {
                String ip = dns.a(m.host()).stream().map(String::trim).filter(this::usable).findFirst().orElse(null);
                hosts.add(new Host(m.host(), ip, ip == null ? "no public IPv4 address" : null));
            } catch (LookupFailed e) {
                hosts.add(new Host(m.host(), null, "its address couldn't be looked up"));
            }
        }
        if (hosts.stream().noneMatch(Host::ready)) {
            String why = mx.size() == 1 && mx.getFirst().host().equals(domain)
                    ? "The domain has no mail server in DNS (no MX record, and no address of its own)."
                    : "None of the domain's mail servers has a public address.";
            return new Destinations(hosts, false, why);
        }
        return new Destinations(hosts, false, null);
    }

    private boolean usable(String ip) {
        return Ipv4.valid(ip) && (allowPrivate || Ipv4.isPublic(ip));
    }
}
