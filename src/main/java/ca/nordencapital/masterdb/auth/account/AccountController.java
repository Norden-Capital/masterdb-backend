package ca.nordencapital.masterdb.auth.account;

import ca.nordencapital.masterdb.auth.session.AuthPrincipal;
import ca.nordencapital.masterdb.auth.session.SessionCookie;
import ca.nordencapital.masterdb.auth.session.SessionService.SessionView;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.UUID;

/** "My account / security": any signed-in user, about themselves only. */
@Tag(name = "My account")
@RestController
@RequestMapping("/api/v1/account")
public class AccountController {

    private final AccountService account;
    private final SessionCookie cookie;

    public AccountController(AccountService account, SessionCookie cookie) {
        this.account = account;
        this.cookie = cookie;
    }

    public record PasswordRequest(@NotBlank @Size(max = 1024) String currentPassword,
            @NotBlank @Size(max = 1024) String newPassword) {
        @Override
        public String toString() {
            return "PasswordRequest[***]";
        }
    }

    public record CodeRequest(@NotBlank @Size(max = 16) String code) {
        @Override
        public String toString() {
            return "CodeRequest[***]";
        }
    }

    public record RecoveryCodesResponse(List<String> recoveryCodes) {
        @Override
        public String toString() {
            return "RecoveryCodesResponse[" + recoveryCodes.size() + "]";
        }
    }

    public record RevokedResponse(int sessionsEnded) {
    }

    @Operation(summary = "Change my password", description = "Re-checks the current password (400 "
            + "CURRENT_PASSWORD_INCORRECT); signs out every other session.")
    @PostMapping("/password")
    public ResponseEntity<Void> changePassword(@AuthenticationPrincipal AuthPrincipal me,
            @Valid @RequestBody PasswordRequest body) {
        account.changePassword(me, body.currentPassword(), body.newPassword());
        return ResponseEntity.noContent().build();
    }

    @Operation(summary = "My sessions", description = "Where I am signed in; `current` marks this browser.")
    @GetMapping("/sessions")
    public List<SessionView> sessions(@AuthenticationPrincipal AuthPrincipal me) {
        return account.sessions(me);
    }

    @DeleteMapping("/sessions/{sessionId}")
    public ResponseEntity<Void> revoke(@AuthenticationPrincipal AuthPrincipal me, @PathVariable UUID sessionId) {
        account.revokeSession(me, sessionId);
        ResponseEntity.BodyBuilder ok = ResponseEntity.status(204);
        return ok.build();
    }

    @Operation(summary = "Sign out my other sessions")
    @PostMapping("/sessions/revoke-others")
    public RevokedResponse revokeOthers(@AuthenticationPrincipal AuthPrincipal me) {
        return new RevokedResponse(account.revokeOtherSessions(me));
    }

    @Operation(summary = "Log out everywhere", description = "Every session, this one included; deletes the cookie.")
    @PostMapping("/logout-everywhere")
    public ResponseEntity<RevokedResponse> logoutEverywhere(@AuthenticationPrincipal AuthPrincipal me) {
        return ResponseEntity.ok().header(HttpHeaders.SET_COOKIE, cookie.clear().toString())
                .body(new RevokedResponse(account.logoutEverywhere(me)));
    }

    @GetMapping("/2fa")
    public AccountService.TwoFactorStatus twoFactor(@AuthenticationPrincipal AuthPrincipal me) {
        return account.twoFactorStatus(me);
    }

    @Operation(summary = "New recovery codes", description = "Needs a current authenticator code (400 "
            + "INVALID_TWO_FACTOR_CODE). The old codes stop working; the new ones are shown this once.")
    @PostMapping("/2fa/recovery-codes")
    public RecoveryCodesResponse regenerate(@AuthenticationPrincipal AuthPrincipal me,
            @Valid @RequestBody CodeRequest body) {
        return new RecoveryCodesResponse(account.regenerateRecoveryCodes(me, body.code()));
    }
}
