package ca.nordencapital.masterdb.dns.health;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.naming.NameNotFoundException;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.InitialDirContext;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Hashtable;
import java.util.List;
import java.util.Locale;
import java.util.stream.Collectors;

/**
 * {@link DnsLookup} through the JDK's DNS provider (JNDI, as the old app's
 * SmtpValidator did), asking the configured public resolvers
 * ({@code app.dns.resolvers}, Cloudflare and Google by default) so the
 * answer is what the internet sees, not a local cache.
 */
@Component
public class JndiDnsLookup implements DnsLookup {

    private final String providerUrl;
    private final String timeoutMs;

    public JndiDnsLookup(@Value("${app.dns.resolvers:1.1.1.1,8.8.8.8}") String resolvers,
            @Value("${app.dns.timeout:3s}") Duration timeout) {
        this.providerUrl = Arrays.stream(resolvers.split(","))
                .map(String::trim).filter(s -> !s.isEmpty()).map(s -> "dns://" + s)
                .collect(Collectors.joining(" "));
        this.timeoutMs = Long.toString(Math.max(500, timeout.toMillis()));
    }

    @Override
    public List<String> a(String name) {
        return values(name, "A").stream().map(String::trim).toList();
    }

    @Override
    public List<Mx> mx(String name) {
        List<Mx> out = new ArrayList<>();
        for (String v : values(name, "MX")) {
            String[] parts = v.trim().split("\\s+");
            if (parts.length == 2) {
                try {
                    out.add(new Mx(Integer.parseInt(parts[0]), host(parts[1])));
                } catch (NumberFormatException ignored) {
                    // not an MX answer
                }
            }
        }
        return out;
    }

    @Override
    public List<String> txt(String name) {
        return values(name, "TXT").stream().map(JndiDnsLookup::joinTxt).toList();
    }

    @Override
    public List<String> ptr(String ipv4) {
        String[] o = ipv4.split("\\.");
        String name = o[3] + "." + o[2] + "." + o[1] + "." + o[0] + ".in-addr.arpa";
        return values(name, "PTR").stream().map(JndiDnsLookup::host).toList();
    }

    /** {@code "v=DKIM1; k=rsa; " "p=MII..."} becomes {@code v=DKIM1; k=rsa; p=MII...}. */
    static String joinTxt(String raw) {
        String v = raw.trim();
        if (!v.startsWith("\"")) {
            return v;
        }
        StringBuilder out = new StringBuilder();
        boolean in = false;
        for (int i = 0; i < v.length(); i++) {
            char c = v.charAt(i);
            if (c == '\\' && in && i + 1 < v.length()) {
                out.append(v.charAt(++i));
            } else if (c == '"') {
                in = !in;
            } else if (in) {
                out.append(c);
            }
        }
        return out.toString();
    }

    private static String host(String v) {
        String h = v.trim().toLowerCase(Locale.ROOT);
        return h.endsWith(".") ? h.substring(0, h.length() - 1) : h;
    }

    private List<String> values(String name, String type) {
        Hashtable<String, String> env = new Hashtable<>();
        env.put("java.naming.factory.initial", "com.sun.jndi.dns.DnsContextFactory");
        if (!providerUrl.isEmpty()) {
            // Empty = the system's own resolvers (used for DNSBL lookups, see servers/health).
            env.put("java.naming.provider.url", providerUrl);
        }
        env.put("com.sun.jndi.dns.timeout.initial", timeoutMs);
        env.put("com.sun.jndi.dns.timeout.retries", "2");
        InitialDirContext ctx = null;
        try {
            ctx = new InitialDirContext(env);
            Attributes attrs = ctx.getAttributes(name, new String[] {type});
            Attribute attr = attrs.get(type);
            List<String> out = new ArrayList<>();
            if (attr != null) {
                NamingEnumeration<?> e = attr.getAll();
                while (e.hasMore()) {
                    out.add(String.valueOf(e.next()));
                }
            }
            return out;
        } catch (NameNotFoundException e) {
            return List.of();
        } catch (NamingException e) {
            throw new LookupFailed("DNS lookup of " + type + " " + name + " failed ("
                    + e.getClass().getSimpleName() + ")");
        } finally {
            if (ctx != null) {
                try {
                    ctx.close();
                } catch (NamingException ignored) {
                    // nothing to do
                }
            }
        }
    }
}
