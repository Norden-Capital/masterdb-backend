package ca.nordencapital.testsupport;

import ca.nordencapital.masterdb.dns.health.DnsLookup;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/** Public DNS for tests: answers only what a test put in, never asks the network. */
public class FakeDnsLookup implements DnsLookup {

    private final Map<String, List<String>> a = new ConcurrentHashMap<>();
    private final Map<String, List<Mx>> mx = new ConcurrentHashMap<>();
    private final Map<String, List<String>> txt = new ConcurrentHashMap<>();
    private final Map<String, List<String>> ptr = new ConcurrentHashMap<>();
    private final Set<String> failing = ConcurrentHashMap.newKeySet();

    @TestConfiguration
    public static class Config {
        @Bean
        @Primary
        FakeDnsLookup fakeDnsLookup() {
            return new FakeDnsLookup();
        }
    }

    public void clear() {
        a.clear();
        mx.clear();
        txt.clear();
        ptr.clear();
        failing.clear();
    }

    public FakeDnsLookup a(String name, String... ips) {
        a.put(name, List.of(ips));
        return this;
    }

    public FakeDnsLookup mx(String name, Mx... records) {
        mx.put(name, List.of(records));
        return this;
    }

    public FakeDnsLookup txt(String name, String... records) {
        txt.put(name, List.of(records));
        return this;
    }

    public FakeDnsLookup ptr(String ip, String... hosts) {
        ptr.put(ip, List.of(hosts));
        return this;
    }

    /** Any lookup of this name fails (timeout). */
    public FakeDnsLookup fail(String name) {
        failing.add(name);
        return this;
    }

    /** A domain with every record the managed settings write, for 203.0.113.10 / selector mail. */
    public FakeDnsLookup healthy(String domain, String dkimKey) {
        return a(domain, "203.0.113.10")
                .mx(domain, new Mx(10, "mail." + domain))
                .txt(domain, "site-verification=abc", "v=spf1 ip4:203.0.113.10 -all")
                .txt("mail._domainkey." + domain, "v=DKIM1; k=rsa; p=" + dkimKey)
                .txt("_dmarc." + domain, "v=DMARC1; p=quarantine; rua=mailto:dmarc@" + domain);
    }

    private <T> List<T> get(Map<String, List<T>> map, String name) {
        if (failing.contains(name)) {
            throw new LookupFailed("DNS lookup of " + name + " failed (timeout)");
        }
        return map.getOrDefault(name, List.of());
    }

    @Override
    public List<String> a(String name) {
        return get(a, name);
    }

    @Override
    public List<Mx> mx(String name) {
        return get(mx, name);
    }

    @Override
    public List<String> txt(String name) {
        return get(txt, name);
    }

    @Override
    public List<String> ptr(String ipv4) {
        return get(ptr, ipv4);
    }
}
