package ca.nordencapital.masterdb.web.security;

import ca.nordencapital.masterdb.web.error.ErrorCode;
import ca.nordencapital.masterdb.web.error.ProblemDetails;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

/**
 * Only the MasterDB website may call this API.
 *
 * <p>The browser never talks to this server. It calls {@code /api/...} on the
 * website (Vercel), whose server forwards the request here and adds
 * {@code X-Proxy-Secret}, a value only the two servers know ({@code PROXY_SECRET},
 * a GitHub secret here and a Vercel environment variable there). A request
 * without the right value gets 401 {@code PROXY_SECRET_INVALID}; the answer is
 * the same whether the header was missing or wrong.
 *
 * <p>Every path is checked except {@code /actuator/health}, which the deploy
 * polls from the server itself. That covers {@code /api/**} and leaves nothing
 * else reachable by accident. The path is the container's decoded and normalised
 * one, so {@code /%61pi/...} cannot slip past.
 *
 * <p><b>Fail closed.</b> With no secret configured the application refuses to
 * start, unless {@code app.proxy.required=false}: set only by the {@code local}
 * profile (application-local.yml) and the tests. There, with no secret, the
 * check is off; with one, it is enforced as in production.
 *
 * <p>The header's value is never logged. The comparison is constant-time.
 *
 * <p>Runs after RequestIdFilter, RequestLoggingFilter and CORS, so every
 * rejection is logged with its request id and preflights are answered first.
 */
@Component
@Order(ProxySecretFilter.ORDER)
public class ProxySecretFilter extends OncePerRequestFilter {

    public static final String HEADER = "X-Proxy-Secret";
    static final int ORDER = Ordered.HIGHEST_PRECEDENCE + 3;
    /** 64 hex characters are generated; anything under 32 is a mistake (a placeholder, a truncated paste). */
    static final int MIN_LENGTH = 32;
    static final String DETAIL = "This API only answers requests from the MasterDB website.";

    private static final Logger log = LoggerFactory.getLogger(ProxySecretFilter.class);

    private final byte[] secret;

    public ProxySecretFilter(@Value("${app.proxy.secret:}") String secret,
            @Value("${app.proxy.required:true}") boolean required) {
        String value = secret == null ? "" : secret.trim();
        if (required && value.length() < MIN_LENGTH) {
            // Never put the value in the message: only say what is wrong with it.
            throw new IllegalStateException(value.isEmpty()
                    ? "PROXY_SECRET is not set. The API refuses to start without it (see ProxySecretFilter)."
                    : "PROXY_SECRET is shorter than " + MIN_LENGTH + " characters (see ProxySecretFilter).");
        }
        if (value.isEmpty()) {
            log.warn("PROXY_SECRET is not set: the proxy-secret check is OFF (allowed only in local/test).");
        }
        this.secret = value.getBytes(StandardCharsets.UTF_8);
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        if (secret.length == 0) {
            return true;
        }
        String path = request.getServletPath() + (request.getPathInfo() != null ? request.getPathInfo() : "");
        return path.equals("/actuator/health") || path.startsWith("/actuator/health/");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        if (matches(request.getHeader(HEADER))) {
            chain.doFilter(request, response);
            return;
        }
        // The error dispatch to /error (ProblemErrorController) writes the
        // problem+json body with these, the request id and the path.
        request.setAttribute(ProblemDetails.CODE_ATTRIBUTE, ErrorCode.PROXY_SECRET_INVALID);
        request.setAttribute(ProblemDetails.DETAIL_ATTRIBUTE, DETAIL);
        response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
    }

    private boolean matches(String sent) {
        // isEqual does not stop at the first differing byte. Its running time
        // reveals the length at most, never how much of the value was right.
        return sent != null && MessageDigest.isEqual(secret, sent.getBytes(StandardCharsets.UTF_8));
    }
}
