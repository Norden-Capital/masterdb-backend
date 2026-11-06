package ca.nordencapital.masterdb.web.security;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Component;

import java.util.regex.Pattern;

/**
 * The address a request really came from, for the login rate limit, the
 * session list and the audit log.
 *
 * <p>Browsers never reach this server: the website's server (Vercel) forwards
 * their calls, so {@code getRemoteAddr()} is one of Vercel's addresses for
 * everybody. The website therefore sends the visitor's address in
 * {@value #HEADER}. That header is believed <b>only</b> when the same request
 * carried the right {@code X-Proxy-Secret} ({@link ProxySecretFilter} marks the
 * request); anybody can send the header itself. Otherwise the connection's
 * address is used: on the server that is what Caddy saw (Caddy overwrites any
 * {@code X-Forwarded-For} sent from outside, and Tomcat accepts the header only
 * from the local proxy, {@code server.forward-headers-strategy: native}). A raw
 * {@code X-Forwarded-For} is never read here.
 */
@Component
public class ClientIp {

    public static final String HEADER = "X-Client-IP";

    /** An IPv4 or IPv6 address (hex digits, dots, colons) and nothing else: no spaces, no lists. */
    private static final Pattern ADDRESS = Pattern.compile("[0-9A-Fa-f:.]{2,45}");

    public String resolve(HttpServletRequest request) {
        if (ProxySecretFilter.isVerified(request)) {
            String forwarded = request.getHeader(HEADER);
            if (forwarded != null && ADDRESS.matcher(forwarded.trim()).matches()) {
                return forwarded.trim();
            }
        }
        return request.getRemoteAddr();
    }
}
