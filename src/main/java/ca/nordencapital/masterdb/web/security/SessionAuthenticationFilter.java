package ca.nordencapital.masterdb.web.security;

import ca.nordencapital.masterdb.auth.session.AuthPrincipal;
import ca.nordencapital.masterdb.auth.session.SessionCookie;
import ca.nordencapital.masterdb.auth.session.SessionService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

/**
 * Inside the Spring Security chain: turns the {@code md_session} cookie into
 * the signed-in user for this request, by looking the session up in the
 * database every time (so a revoked session is refused at once).
 *
 * <p>No cookie, or one that does not lead to a usable session: the request
 * simply stays anonymous, and the access rules answer 401 where a user is
 * needed. Not a bean on purpose: as a bean, Spring Boot would also register it
 * as a plain servlet filter outside the chain.
 */
public class SessionAuthenticationFilter extends OncePerRequestFilter {

    /** Set when the request brought a session cookie that did not work, so the 401 can delete it. */
    static final String STALE_COOKIE_ATTRIBUTE = SessionAuthenticationFilter.class.getName() + ".staleCookie";

    private final SessionService sessions;
    private final SecurityContextHolderStrategy contexts = SecurityContextHolder.getContextHolderStrategy();

    public SessionAuthenticationFilter(SessionService sessions) {
        this.sessions = sessions;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        String token = SessionCookie.read(request);
        if (token != null) {
            sessions.authenticate(token).ifPresentOrElse(
                    principal -> signIn(principal),
                    () -> request.setAttribute(STALE_COOKIE_ATTRIBUTE, Boolean.TRUE));
        }
        chain.doFilter(request, response);
    }

    private void signIn(AuthPrincipal principal) {
        // Authorities stay minimal until permissions (M1.4) arrive.
        List<SimpleGrantedAuthority> authorities = principal.owner()
                ? List.of(new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("ROLE_OWNER"))
                : List.of(new SimpleGrantedAuthority("ROLE_USER"));
        SecurityContext context = contexts.createEmptyContext();
        context.setAuthentication(UsernamePasswordAuthenticationToken.authenticated(principal, null, authorities));
        contexts.setContext(context);
    }
}
