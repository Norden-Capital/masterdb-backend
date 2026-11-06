package ca.nordencapital.masterdb.config;

import jakarta.servlet.Filter;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;

/**
 * When the API docs are off (the default, and always in production), every
 * docs path answers a plain 404 problem+json, as if it never existed.
 *
 * <p>springdoc already drops /api/v3/api-docs/** and /swagger-ui/** when
 * disabled, but Spring Boot's own /webjars/** handler would still serve the
 * swagger-ui webjar. This filter closes all of them in one place, so the
 * result does not depend on springdoc's internals.
 *
 * <p>It only calls {@code sendError(404)}: the container forwards to /error
 * and ProblemErrorController writes the usual body, with the request id.
 */
@Configuration
@ConditionalOnProperty(name = "app.docs.enabled", havingValue = "false", matchIfMissing = true)
public class DocsDisabledConfig {

    /** Servlet URL patterns: exact paths, or a prefix ending in "/*" (which also matches the prefix itself). */
    static final String[] DOCS_PATHS = {
            "/api/docs", "/api/docs/*",
            "/api/v3/api-docs", "/api/v3/api-docs/*", "/api/v3/api-docs.yaml",
            "/swagger-ui.html", "/swagger-ui/*",
            "/v3/api-docs", "/v3/api-docs/*",
            "/webjars/swagger-ui/*",
    };

    @Bean
    FilterRegistrationBean<Filter> docsDisabledFilter() {
        Filter notFound = (request, response, chain) -> ((HttpServletResponse) response).sendError(404);
        FilterRegistrationBean<Filter> bean = new FilterRegistrationBean<>(notFound);
        bean.setName("docsDisabledFilter");
        bean.addUrlPatterns(DOCS_PATHS);
        // After RequestIdFilter and RequestLoggingFilter, so the 404 carries the request id and is logged.
        bean.setOrder(Ordered.HIGHEST_PRECEDENCE + 10);
        return bean;
    }
}
