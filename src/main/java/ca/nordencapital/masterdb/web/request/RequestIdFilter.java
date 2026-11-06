package ca.nordencapital.masterdb.web.request;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.MDC;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.UUID;
import java.util.regex.Pattern;

/**
 * Gives every request an id: the caller's {@code X-Request-Id} when it is a
 * safe value (1-64 chars of {@code [A-Za-z0-9-]}), otherwise a new UUID.
 *
 * <p>The id goes into the logging MDC (key {@code requestId}, printed on every
 * log line), into a request attribute (for the error handlers, which may run
 * after the MDC is cleared), back to the caller as the {@code X-Request-Id}
 * response header, and into every error body.
 *
 * <p>Unsafe values are dropped, not cleaned: anything else could inject
 * newlines or markup into logs.
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class RequestIdFilter extends OncePerRequestFilter {

    public static final String HEADER = "X-Request-Id";
    public static final String MDC_KEY = "requestId";
    public static final String ATTRIBUTE = RequestIdFilter.class.getName() + ".requestId";

    private static final Pattern SAFE = Pattern.compile("[A-Za-z0-9-]{1,64}");

    /** The id of this request, or {@code null} if the filter did not run for it. */
    public static String get(HttpServletRequest request) {
        Object id = request.getAttribute(ATTRIBUTE);
        return id instanceof String s ? s : null;
    }

    static String resolve(String incoming) {
        return incoming != null && SAFE.matcher(incoming).matches() ? incoming : UUID.randomUUID().toString();
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        String id = resolve(request.getHeader(HEADER));
        request.setAttribute(ATTRIBUTE, id);
        response.setHeader(HEADER, id);
        MDC.put(MDC_KEY, id);
        try {
            chain.doFilter(request, response);
        } finally {
            MDC.remove(MDC_KEY);
        }
    }
}
