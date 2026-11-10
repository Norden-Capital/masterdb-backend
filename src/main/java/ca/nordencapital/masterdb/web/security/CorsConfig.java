package ca.nordencapital.masterdb.web.security;

import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.ServerHttpResponse;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.DefaultCorsProcessor;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

import java.io.IOException;
import java.util.List;

/**
 * Which websites a browser may call this API from: only the MasterDB website
 * ({@code APP_CORS_ALLOWED_ORIGINS}, comma-separated, default
 * {@code https://db.nordencapital.ca}); the {@code local} profile adds
 * {@code http://localhost:3000}.
 *
 * <p>In practice no browser calls this server: the website's own server
 * forwards {@code /api/...} here, and that is not a CORS request (the website
 * drops the browser's Origin). This keeps other websites' pages from calling
 * the API from a visitor's browser. Credentials are allowed because the login (M1)
 * will use an HttpOnly cookie.
 *
 * <p>A filter, not WebMvcConfigurer: it runs before Spring Security, so a
 * preflight is answered rather than refused for having no session. A refused origin
 * gets 403 problem+json like every other error, not Spring's plain-text body.
 */
@Configuration
public class CorsConfig {

    static final int ORDER = Ordered.HIGHEST_PRECEDENCE + 2;

    @Bean
    FilterRegistrationBean<CorsFilter> corsFilter(
            @Value("${app.cors.allowed-origins}") List<String> allowedOrigins) {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOrigins(allowedOrigins.stream().map(String::trim).filter(o -> !o.isEmpty()).toList());
        config.setAllowedMethods(List.of("GET", "POST", "PUT", "PATCH", "DELETE"));
        config.setAllowedHeaders(List.of("*"));
        config.setExposedHeaders(List.of("X-Request-Id"));
        config.setAllowCredentials(true);
        config.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);

        CorsFilter filter = new CorsFilter(source);
        filter.setCorsProcessor(new ProblemCorsProcessor());
        FilterRegistrationBean<CorsFilter> bean = new FilterRegistrationBean<>(filter);
        bean.setName("corsFilter");
        // After RequestIdFilter and RequestLoggingFilter (refusals are logged with
        // their id), before the login rate limit and Spring Security.
        bean.setOrder(ORDER);
        return bean;
    }

    /** Refusals go through /error, so they are problem+json with a request id. */
    static class ProblemCorsProcessor extends DefaultCorsProcessor {
        @Override
        protected void rejectRequest(ServerHttpResponse response) throws IOException {
            if (response instanceof ServletServerHttpResponse servlet) {
                // Vary headers set so far would be lost by sendError on some containers: keep them.
                HttpHeaders headers = response.getHeaders();
                HttpServletResponse raw = servlet.getServletResponse();
                headers.getOrEmpty(HttpHeaders.VARY).forEach(v -> raw.addHeader(HttpHeaders.VARY, v));
                raw.sendError(HttpServletResponse.SC_FORBIDDEN);
                return;
            }
            super.rejectRequest(response);
        }
    }
}
