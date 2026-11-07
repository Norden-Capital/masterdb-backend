package ca.nordencapital.masterdb.dns.namecheap;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;
import java.util.regex.Pattern;

/**
 * Namecheap API settings ({@code app.namecheap.*} in application.yml).
 *
 * @param baseUrl  the XML API endpoint (production by default; tests point it at a local stub)
 * @param clientIp sent as {@code ClientIp} on every call: the server's public IPv4, the one whitelisted
 *                 in Namecheap (147.93.4.107 in production)
 * @param timeout  per call
 */
@ConfigurationProperties("app.namecheap")
public record NamecheapProperties(String baseUrl, String clientIp, Duration timeout) {

    static final Pattern IPV4 = Pattern.compile(
            "((25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)\\.){3}(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)");

    public NamecheapProperties {
        if (baseUrl == null || !baseUrl.startsWith("http")) {
            throw new IllegalArgumentException("app.namecheap.base-url must be an http(s) URL");
        }
        if (clientIp == null || !IPV4.matcher(clientIp.trim()).matches()) {
            throw new IllegalArgumentException("app.namecheap.client-ip must be an IPv4 address");
        }
        clientIp = clientIp.trim();
        if (timeout == null || timeout.isNegative() || timeout.isZero()) {
            timeout = Duration.ofSeconds(60);
        }
    }

    public static boolean isIpv4(String value) {
        return value != null && IPV4.matcher(value).matches();
    }
}
