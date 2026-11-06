package ca.nordencapital.masterdb.web.request;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * One access-log line per request: {@code method path status durationMs requestId}.
 *
 * <p>Logs the path only. Never the query string, headers or bodies: contact
 * emails will travel in them. {@code /actuator/health} is skipped (the deploy
 * and monitors poll it).
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 1)
public class RequestLoggingFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(RequestLoggingFilter.class);

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getRequestURI();
        return path.equals("/actuator/health") || path.startsWith("/actuator/health/");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        long start = System.nanoTime();
        boolean failed = true;
        try {
            chain.doFilter(request, response);
            failed = false;
        } finally {
            // An exception escaping here becomes a 500 via /error after this line is written.
            int status = failed ? 500 : response.getStatus();
            long durationMs = (System.nanoTime() - start) / 1_000_000;
            log.info("{} {} {} {}ms requestId={}", request.getMethod(), request.getRequestURI(), status,
                    durationMs, RequestIdFilter.get(request));
        }
    }
}
