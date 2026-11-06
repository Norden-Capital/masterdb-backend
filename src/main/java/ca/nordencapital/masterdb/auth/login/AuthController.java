package ca.nordencapital.masterdb.auth.login;

import ca.nordencapital.masterdb.activity.ActivityAction;
import ca.nordencapital.masterdb.activity.ActivityLog;
import ca.nordencapital.masterdb.activity.ActivityLog.Party;
import ca.nordencapital.masterdb.auth.session.AuthPrincipal;
import ca.nordencapital.masterdb.auth.session.SessionCookie;
import ca.nordencapital.masterdb.auth.session.SessionService;
import ca.nordencapital.masterdb.auth.twofactor.LoginChallenge;
import ca.nordencapital.masterdb.auth.twofactor.TwoFactorService;
import ca.nordencapital.masterdb.auth.twofactor.TwoFactorService.CodeResult;
import ca.nordencapital.masterdb.auth.user.Emails;
import ca.nordencapital.masterdb.web.request.RequestIdFilter;
import ca.nordencapital.masterdb.web.security.ClientIp;
import com.fasterxml.jackson.annotation.JsonInclude;
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
import java.time.Duration;
import java.util.List;
import java.util.UUID;

/**
 * Sign in (password, then 2FA code), sign out, and "who am I". The session
 * lives in the HttpOnly cookie {@code md_session}, the 2FA step in
 * {@code md_preauth}; no token ever appears in a body.
 *
 * <pre>
 * POST /login {email,password}     → 200 {state: TWO_FACTOR_REQUIRED | TWO_FACTOR_SETUP_REQUIRED} + md_preauth
 * POST /login/2fa {code}           → 200 {state: AUTHENTICATED, user} + md_session   (code or recovery code)
 * POST /2fa/setup                  → 200 {secret, otpauthUri, issuer, account}     (SETUP only)
 * POST /2fa/setup/confirm {code}   → 200 {state: AUTHENTICATED, user, recoveryCodes} + md_session
 * </pre>
 */
@Tag(name = "Authentication")
@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {

    private static final Logger log = LoggerFactory.getLogger(AuthController.class);

    static final String AUTHENTICATED = "AUTHENTICATED";
    static final String TWO_FACTOR_REQUIRED = "TWO_FACTOR_REQUIRED";
    static final String TWO_FACTOR_SETUP_REQUIRED = "TWO_FACTOR_SETUP_REQUIRED";

    private final LoginService loginService;
    private final TwoFactorService twoFactor;
    private final SessionService sessions;
    private final SessionCookie cookie;
    private final ClientIp clientIp;
    private final UserSummaries summaries;
    private final Clock clock;
    private final ActivityLog activity;

    public AuthController(LoginService loginService, TwoFactorService twoFactor, SessionService sessions,
            SessionCookie cookie, ClientIp clientIp, UserSummaries summaries, Clock clock, ActivityLog activity) {
        this.activity = activity;
        this.loginService = loginService;
        this.twoFactor = twoFactor;
        this.sessions = sessions;
        this.cookie = cookie;
        this.clientIp = clientIp;
        this.summaries = summaries;
        this.clock = clock;
    }

    @Operation(summary = "Sign in, step 1: password", description = "Opens the 2FA step (md_preauth cookie). "
            + "Every failure is the same 401 INVALID_CREDENTIALS; too many wrong attempts give 429 ACCOUNT_LOCKED, "
            + "too many from one address 429 RATE_LIMITED.")
    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(@Valid @RequestBody LoginRequest body, HttpServletRequest request) {
        LoginResult result = loginService.login(body.email(), body.password(), clientIp.resolve(request),
                request.getHeader(HttpHeaders.USER_AGENT));
        return switch (result) {
            case LoginResult.SecondFactorRequired next -> {
                TwoFactorService.Started c = next.challenge();
                String state = c.purpose() == LoginChallenge.Purpose.SETUP ? TWO_FACTOR_SETUP_REQUIRED
                        : TWO_FACTOR_REQUIRED;
                yield ResponseEntity.ok()
                        .header(HttpHeaders.SET_COOKIE, cookie.createPreAuth(c.token(),
                                Duration.between(clock.instant(), c.expiresAt())).toString())
                        .body(new LoginResponse(state, null, null));
            }
            case LoginResult.InvalidCredentials ignored -> throw new InvalidCredentialsException();
            case LoginResult.Locked locked -> throw new AccountLockedException(locked.until(), clock.instant());
        };
    }

    @Operation(summary = "Sign in, step 2: code", description = "An authenticator code or a recovery code. "
            + "401 INVALID_TWO_FACTOR_CODE, 401 LOGIN_CHALLENGE_INVALID (sign in again), 429 ACCOUNT_LOCKED.")
    @PostMapping("/login/2fa")
    public ResponseEntity<LoginResponse> loginCode(@Valid @RequestBody CodeRequest body, HttpServletRequest request) {
        return finish(twoFactor.verify(SessionCookie.readPreAuth(request), body.code(), clientIp.resolve(request),
                request.getHeader(HttpHeaders.USER_AGENT)));
    }

    @Operation(summary = "2FA enrolment: new secret", description = "Only in the TWO_FACTOR_SETUP_REQUIRED step. "
            + "The secret is for the QR code (otpauthUri) or manual entry; calling again replaces it.")
    @PostMapping("/2fa/setup")
    public TwoFactorService.SetupInfo setup(HttpServletRequest request) {
        return twoFactor.beginSetup(SessionCookie.readPreAuth(request))
                .orElseThrow(TwoFactorExceptions.ChallengeInvalid::new);
    }

    @Operation(summary = "2FA enrolment: confirm", description = "The first code from the app. Signs in and "
            + "returns 10 recovery codes, shown this once.")
    @PostMapping("/2fa/setup/confirm")
    public ResponseEntity<LoginResponse> confirmSetup(@Valid @RequestBody CodeRequest body,
            HttpServletRequest request) {
        return finish(twoFactor.confirmSetup(SessionCookie.readPreAuth(request), body.code(),
                clientIp.resolve(request), request.getHeader(HttpHeaders.USER_AGENT)));
    }

    @Operation(summary = "Sign out", description = "Ends the current session and deletes the cookie.")
    @PostMapping("/logout")
    public ResponseEntity<Void> logout(@AuthenticationPrincipal AuthPrincipal principal, HttpServletRequest request) {
        sessions.revoke(principal.sessionId());
        log.info("logout: {} user={} session={} ip={} requestId={}", Emails.mask(principal.email()),
                principal.userPublicId(), principal.sessionPublicId(), clientIp.resolve(request),
                RequestIdFilter.get(request));
        activity.record(ActivityAction.LOGOUT, Party.of(principal), Party.of(principal),
                java.util.Map.of("session", principal.sessionPublicId().toString()));
        return ResponseEntity.noContent().header(HttpHeaders.SET_COOKIE, cookie.clear().toString()).build();
    }

    @Operation(summary = "Current user", description = "The signed-in user; 401 UNAUTHENTICATED without a session.")
    @GetMapping("/me")
    public UserSummary me(@AuthenticationPrincipal AuthPrincipal principal) {
        return summaries.of(principal);
    }

    private ResponseEntity<LoginResponse> finish(CodeResult result) {
        return switch (result) {
            case CodeResult.Authenticated ok -> ResponseEntity.ok()
                    .header(HttpHeaders.SET_COOKIE,
                            cookie.create(ok.session().token(), sessions.cookieMaxAge()).toString())
                    .header(HttpHeaders.SET_COOKIE, cookie.clearPreAuth().toString())
                    .body(new LoginResponse(AUTHENTICATED, summaries.of(ok.user()), ok.recoveryCodes()));
            case CodeResult.InvalidCode ignored -> throw new TwoFactorExceptions.InvalidCode();
            case CodeResult.ChallengeInvalid ignored -> throw new TwoFactorExceptions.ChallengeInvalid();
            case CodeResult.Locked locked -> throw new AccountLockedException(locked.until(), clock.instant());
        };
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

    public record CodeRequest(@NotBlank @Size(max = 64) String code) {
        @Override
        public String toString() {
            return "CodeRequest[***]";
        }
    }

    /** {@code user} only when signed in; {@code recoveryCodes} only right after enrolment. */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record LoginResponse(String state, UserSummary user, List<String> recoveryCodes) {
        @Override
        public String toString() {
            return "LoginResponse[" + state + "]";
        }
    }

    /**
     * What the frontend needs about the signed-in user. {@code permissions} are
     * the effective ones ({@code MODULE:ACTION}; every one for the Owner), so the
     * UI can hide what the user cannot do. The API checks again regardless.
     */
    public record UserSummary(UUID publicId, String email, String fullName, boolean isOwner,
            List<String> permissions) {
    }
}
