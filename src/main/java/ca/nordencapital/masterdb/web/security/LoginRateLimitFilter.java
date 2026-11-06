package ca.nordencapital.masterdb.web.security;

import ca.nordencapital.masterdb.web.error.ErrorCode;
import ca.nordencapital.masterdb.web.error.ProblemDetails;
import ca.nordencapital.masterdb.web.request.RequestIdFilter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.OptionalLong;

/**
 * Applies {@link LoginRateLimiter} to the sign-in steps (password: {@code POST
 * /api/v1/auth/login}; codes: {@code /login/2fa}, {@code /2fa/setup/confirm}),
 * per client address and step, before
 * the body is read or a password hashed. Over the limit: 429
 * {@code RATE_LIMITED} problem+json with {@code Retry-After} (seconds).
 *
 * <p>Runs right after ProxySecretFilter, so the address comes from
 * {@link ClientIp} with the request already marked as coming from the website
 * (or not), and before Spring Security. Registered by SecurityConfig (not a
 * {@code @Component}, so web-slice tests do not pull it in).
 */
public class LoginRateLimitFilter extends OncePerRequestFilter {

    static final int ORDER = Ordered.HIGHEST_PRECEDENCE + 4;
    static final String LOGIN_PATH = "/api/v1/auth/login";
    static final String DETAIL = "Too many sign-in attempts from your network. Try again later.";

    private static final Logger log = LoggerFactory.getLogger(LoginRateLimitFilter.class);

    private final LoginRateLimiter limiter;
    private final ClientIp clientIp;

    public LoginRateLimitFilter(LoginRateLimiter limiter, ClientIp clientIp) {
        this.limiter = limiter;
        this.clientIp = clientIp;
    }

    /** Rate-limited POST paths and their bucket: passwords and codes are counted separately. */
    static final java.util.Map<String, String> BUCKETS = java.util.Map.of(
            LOGIN_PATH, "login",
            "/api/v1/auth/login/2fa", "code",
            "/api/v1/auth/2fa/setup/confirm", "code");

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !"POST".equals(request.getMethod()) || !BUCKETS.containsKey(path(request));
    }

    private static String path(HttpServletRequest request) {
        return request.getServletPath() + (request.getPathInfo() != null ? request.getPathInfo() : "");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        String address = clientIp.resolve(request);
        OptionalLong retryAfter = limiter.tryAcquire(BUCKETS.get(path(request)) + "|" + address);
        if (retryAfter.isEmpty()) {
            chain.doFilter(request, response);
            return;
        }
        log.info("login rate limit reached: ip={} retryAfter={}s requestId={}", address, retryAfter.getAsLong(),
                RequestIdFilter.get(request));
        response.setHeader(HttpHeaders.RETRY_AFTER, Long.toString(retryAfter.getAsLong()));
        request.setAttribute(ProblemDetails.CODE_ATTRIBUTE, ErrorCode.RATE_LIMITED);
        request.setAttribute(ProblemDetails.DETAIL_ATTRIBUTE, DETAIL);
        response.sendError(429);
    }
}
