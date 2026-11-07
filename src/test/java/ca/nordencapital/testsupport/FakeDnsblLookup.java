package ca.nordencapital.testsupport;

import ca.nordencapital.masterdb.dns.health.DnsLookup.LookupFailed;
import ca.nordencapital.masterdb.servers.health.DnsblLookup;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

/** Blocklists for tests: answers only what a test put in (default: not listed), never asks the network. */
public class FakeDnsblLookup implements DnsblLookup {

    private final Map<String, List<String>> answers = new ConcurrentHashMap<>();
    private final Set<String> failing = ConcurrentHashMap.newKeySet();
    private final List<String> asked = new CopyOnWriteArrayList<>();

    @TestConfiguration
    public static class Config {
        @Bean
        @Primary
        FakeDnsblLookup fakeDnsblLookup() {
            return new FakeDnsblLookup();
        }
    }

    public void clear() {
        answers.clear();
        failing.clear();
        asked.clear();
    }

    /** {@code name} is the full query, e.g. "10.113.0.203.zen.spamhaus.org". */
    public FakeDnsblLookup answer(String name, String... ips) {
        answers.put(name, List.of(ips));
        return this;
    }

    public FakeDnsblLookup fail(String name) {
        failing.add(name);
        return this;
    }

    public List<String> asked() {
        return List.copyOf(asked);
    }

    @Override
    public List<String> a(String name) {
        asked.add(name);
        if (failing.contains(name)) {
            throw new LookupFailed("DNS lookup of A " + name + " failed (timeout)");
        }
        return answers.getOrDefault(name, List.of());
    }
}
