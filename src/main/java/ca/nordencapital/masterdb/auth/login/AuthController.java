package ca.nordencapital.masterdb.auth.login;

import ca.nordencapital.masterdb.auth.session.AuthPrincipal;
import ca.nordencapital.masterdb.auth.session.SessionCookie;
import ca.nordencapital.masterdb.auth.session.SessionService;
import ca.nordencapital.masterdb.auth.user.Emails;
import ca.nordencapital.masterdb.auth.user.User;
import ca.nordencapital.masterdb.web.request.RequestIdFilter;
import ca.nordencapital.masterdb.web.security.ClientIp;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Clock;
import java.util.UUID;

/**
 * Sign in, sign out, and "who am I". The session lives in the HttpOnly cookie
 * {@code md_session}; the browser never sees the token in a body.
 */
@Tag(name = "Authentication")
@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {

    private static final Logger log = LoggerFactory.getLogger(AuthController.class);

    /** Login's success state. M1.3 adds a second-factor state next to it. */
    static final String AUTHENTICATED = "AUTHENTICATED";

    private final LoginService loginService;
    private final SessionService sessions;
    private final SessionCookie cookie;
    private final ClientIp clientIp;
    private final Clock clock;

    public AuthController(LoginService loginService, SessionService sessions, SessionCookie cookie, ClientIp clientIp,
            Clock clock) {
        this.loginService = loginService;
        this.sessions = sessions;
        this.cookie = cookie;
        this.clientIp = clientIp;
        this.clock = clock;
    }

    @Operation(summary = "Sign in", description = "Sets the md_session cookie. Every failure is the same 401 "
            + "INVALID_CREDENTIALS; too many wrong passwords give 429 ACCOUNT_LOCKED, too many attempts from one "
            + "address 429 RATE_LIMITED.")
    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(@Valid @RequestBody LoginRequest body, HttpServletRequest request) {
        LoginResult result = loginService.login(body.email(), body.password(), clientIp.resolve(request),
                request.getHeader(HttpHeaders.USER_AGENT));
        return switch (result) {
            case LoginResult.Authenticated ok -> ResponseEntity.ok()
                    .header(HttpHeaders.SET_COOKIE,
                            cookie.create(ok.session().token(), sessions.cookieMaxAge()).toString())
                    .body(new LoginResponse(AUTHENTICATED, UserSummary.of(ok.user())));
            case LoginResult.InvalidCredentials ignored -> throw new InvalidCredentialsException();
            case LoginResult.Locked locked -> throw new AccountLockedException(locked.until(), clock.instant());
        };
    }

    @Operation(summary = "Sign out", description = "Ends the current session and deletes the cookie.")
    @PostMapping("/logout")
    public ResponseEntity<Void> logout(@AuthenticationPrincipal AuthPrincipal principal, HttpServletRequest request) {
        sessions.revoke(principal.sessionId());
        log.info("logout: {} user={} session={} ip={} requestId={}", Emails.mask(principal.email()),
                principal.userPublicId(), principal.sessionPublicId(), clientIp.resolve(request),
                RequestIdFilter.get(request));
        return ResponseEntity.noContent().header(HttpHeaders.SET_COOKIE, cookie.clear().toString()).build();
    }

    @Operation(summary = "Current user", description = "The signed-in user; 401 UNAUTHENTICATED without a session.")
    @GetMapping("/me")
    public UserSummary me(@AuthenticationPrincipal AuthPrincipal principal) {
        return new UserSummary(principal.userPublicId(), principal.email(), principal.fullName(), principal.owner());
    }

    /** The password is never part of {@link #toString()} (or any log line). */
    public record LoginRequest(
            @NotBlank @Size(max = Emails.MAX_LENGTH) String email,
            @NotBlank @Size(max = 1024) String password) {
        @Override
        public String toString() {
            return "LoginRequest[email=" + Emails.mask(email) + "]";
        }
    }

    public record LoginResponse(String state, UserSummary user) {
    }

    public record UserSummary(UUID publicId, String email, String fullName, boolean isOwner) {
        static UserSummary of(User user) {
            return new UserSummary(user.getPublicId(), user.getEmail(), user.getFullName(), user.isOwner());
        }
    }
}
