package ca.nordencapital.masterdb.auth.account;

import ca.nordencapital.masterdb.auth.session.SessionCookie;
import ca.nordencapital.masterdb.auth.twofactor.TwoFactorService;
import ca.nordencapital.masterdb.web.security.ClientIp;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Clock;
import java.time.Duration;

/**
 * Accepting an invitation, without a session. The token comes from the link's
 * {@code #fragment}, read by the page and sent in the body (never in a URL).
 * Any unusable link: 410 {@code LINK_INVALID}.
 */
@Tag(name = "Invitations")
@RestController
@RequestMapping("/api/v1/invites")
public class InviteController {

    private final InviteService invites;
    private final SessionCookie cookie;
    private final ClientIp clientIp;
    private final Clock clock;

    public InviteController(InviteService invites, SessionCookie cookie, ClientIp clientIp, Clock clock) {
        this.invites = invites;
        this.cookie = cookie;
        this.clientIp = clientIp;
        this.clock = clock;
    }

    public record TokenRequest(@NotBlank @Size(max = 64) String token) {
        @Override
        public String toString() {
            return "TokenRequest[***]";
        }
    }

    public record AcceptRequest(@NotBlank @Size(max = 64) String token, @NotBlank @Size(max = 200) String fullName,
            @NotBlank @Size(max = 1024) String password) {
        @Override
        public String toString() {
            return "AcceptRequest[***]";
        }
    }

    public record AcceptResponse(String state) {
    }

    @Operation(summary = "Check an invitation link", description = "The email (and name, if given) it is for.")
    @PostMapping("/check")
    public InviteService.InviteInfo check(@Valid @RequestBody TokenRequest body) {
        return invites.check(body.token());
    }

    @Operation(summary = "Accept an invitation", description = "Sets name and password, then continues like a first "
            + "sign-in: 200 {state: TWO_FACTOR_SETUP_REQUIRED} + md_preauth, then /api/v1/auth/2fa/setup.")
    @PostMapping("/accept")
    public ResponseEntity<AcceptResponse> accept(@Valid @RequestBody AcceptRequest body, HttpServletRequest request) {
        TwoFactorService.Started started = invites.accept(body.token(), body.fullName(), body.password(),
                clientIp.resolve(request), request.getHeader(HttpHeaders.USER_AGENT));
        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, cookie.createPreAuth(started.token(),
                        Duration.between(clock.instant(), started.expiresAt())).toString())
                .body(new AcceptResponse("TWO_FACTOR_SETUP_REQUIRED"));
    }
}
