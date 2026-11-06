package ca.nordencapital.masterdb.web.security;

import ca.nordencapital.masterdb.auth.session.SessionCookie;
import ca.nordencapital.masterdb.auth.session.SessionService;
import ca.nordencapital.masterdb.web.error.ErrorCode;
import ca.nordencapital.masterdb.web.error.ProblemDetails;
import jakarta.servlet.DispatcherType;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter;

import java.io.IOException;

/**
 * Who may call what.
 *
 * <p>Filter order on every request (lowest first): RequestIdFilter,
 * RequestLoggingFilter, CORS, ProxySecretFilter, LoginRateLimitFilter, the API
 * docs 404 filter, then this Spring Security chain (Boot's default order -100),
 * which reads the session cookie ({@link SessionAuthenticationFilter}) and
 * applies the rules below.
 *
 * <p><b>Rules (fail closed).</b> Open without a session: {@code POST
 * /api/v1/auth/login}, {@code GET /api/v1/status}, {@code /actuator/health},
 * the API docs paths (which answer 404 unless docs are switched on, i.e.
 * locally), and error dispatches. <b>Everything else needs a signed-in
 * user</b>, so an endpoint added later is protected unless it is listed here on
 * purpose.
 *
 * <p>Stateless: no HTTP session, no JSESSIONID; the {@code md_session} cookie
 * and its database row are the only state. 401 and 403 answer in the usual
 * problem+json (codes {@code UNAUTHENTICATED}, {@code FORBIDDEN}) through
 * /error, like ProxySecretFilter's refusals.
 *
 * <p><b>CSRF</b> is off here on purpose: browsers never reach this server (the
 * proxy secret keeps them out), and the website's proxy refuses cross-site
 * writes before forwarding them (Origin / Sec-Fetch-Site check in
 * masterdb-frontend's {@code app/api/[...path]/route.ts}), on top of the
 * cookie's SameSite=Lax. CORS is handled by CorsConfig's filter, earlier.
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    static final String UNAUTHENTICATED_DETAIL = "Sign in to continue.";
    static final String FORBIDDEN_DETAIL = "You do not have permission to do this.";

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http, SessionService sessions, SessionCookie cookie)
            throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .cors(AbstractHttpConfigurer::disable)
                .httpBasic(AbstractHttpConfigurer::disable)
                .formLogin(AbstractHttpConfigurer::disable)
                .logout(AbstractHttpConfigurer::disable)
                .requestCache(AbstractHttpConfigurer::disable)
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .exceptionHandling(e -> e
                        .authenticationEntryPoint(authenticationEntryPoint(cookie))
                        .accessDeniedHandler(accessDeniedHandler()))
                .addFilterBefore(new SessionAuthenticationFilter(sessions), AnonymousAuthenticationFilter.class)
                .authorizeHttpRequests(auth -> auth
                        // The /error forward after a refusal must not be refused again.
                        .dispatcherTypeMatchers(DispatcherType.ERROR, DispatcherType.FORWARD).permitAll()
                        .requestMatchers("/error").permitAll()
                        .requestMatchers("/actuator/health", "/actuator/health/**").permitAll()
                        .requestMatchers(HttpMethod.POST, "/api/v1/auth/login").permitAll()
                        .requestMatchers(HttpMethod.GET, "/api/v1/status").permitAll()
                        // Answer 404 unless docs are on (DocsDisabledConfig runs before this chain).
                        .requestMatchers("/api/docs", "/api/v3/api-docs", "/api/v3/api-docs/**",
                                "/api/v3/api-docs.yaml", "/swagger-ui.html", "/swagger-ui/**").permitAll()
                        .anyRequest().authenticated());
        return http.build();
    }

    /** POST /api/v1/auth/login is limited per client address before anything else reads it. */
    @Bean
    FilterRegistrationBean<LoginRateLimitFilter> loginRateLimitFilter(LoginRateLimiter limiter, ClientIp clientIp) {
        FilterRegistrationBean<LoginRateLimitFilter> bean =
                new FilterRegistrationBean<>(new LoginRateLimitFilter(limiter, clientIp));
        bean.setName("loginRateLimitFilter");
        bean.setOrder(LoginRateLimitFilter.ORDER);
        return bean;
    }

    /** No usable session: 401 UNAUTHENTICATED, and a stale cookie is deleted. */
    static AuthenticationEntryPoint authenticationEntryPoint(SessionCookie cookie) {
        return (request, response, exception) -> {
            if (Boolean.TRUE.equals(request.getAttribute(SessionAuthenticationFilter.STALE_COOKIE_ATTRIBUTE))) {
                response.addHeader(HttpHeaders.SET_COOKIE, cookie.clear().toString());
            }
            refuse(request, response, HttpServletResponse.SC_UNAUTHORIZED, ErrorCode.UNAUTHENTICATED,
                    UNAUTHENTICATED_DETAIL);
        };
    }

    /** Signed in, not allowed: 403 FORBIDDEN. */
    static AccessDeniedHandler accessDeniedHandler() {
        return (request, response, exception) -> refuse(request, response, HttpServletResponse.SC_FORBIDDEN,
                ErrorCode.FORBIDDEN, FORBIDDEN_DETAIL);
    }

    /** ProblemErrorController writes the body (with request id and path) on the /error forward. */
    private static void refuse(HttpServletRequest request, HttpServletResponse response, int status, ErrorCode code,
            String detail) throws IOException {
        request.setAttribute(ProblemDetails.CODE_ATTRIBUTE, code);
        request.setAttribute(ProblemDetails.DETAIL_ATTRIBUTE, detail);
        response.sendError(status);
    }
}
