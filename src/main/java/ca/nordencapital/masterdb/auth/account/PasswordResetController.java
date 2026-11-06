package ca.nordencapital.masterdb.auth.account;

import ca.nordencapital.masterdb.auth.user.Emails;
import ca.nordencapital.masterdb.web.security.ClientIp;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;

/** Forgot / reset password, without a session. Any unusable link: 410 {@code LINK_INVALID}. */
@Tag(name = "Authentication")
@RestController
@RequestMapping("/api/v1/auth/password")
public class PasswordResetController {

    static final String SENT = "If this email has an active account, a link to reset the password is on its way. "
            + "It works once, for 30 minutes.";

    private final PasswordResetService resets;
    private final ClientIp clientIp;

    public PasswordResetController(PasswordResetService resets, ClientIp clientIp) {
        this.resets = resets;
        this.clientIp = clientIp;
    }

    public record ForgotRequest(@NotBlank @Size(max = Emails.MAX_LENGTH) String email) {
        @Override
        public String toString() {
            return "ForgotRequest[" + Emails.mask(email) + "]";
        }
    }

    public record TokenRequest(@NotBlank @Size(max = 64) String token) {
        @Override
        public String toString() {
            return "TokenRequest[***]";
        }
    }

    public record ResetRequest(@NotBlank @Size(max = 64) String token, @NotBlank @Size(max = 1024) String password) {
        @Override
        public String toString() {
            return "ResetRequest[***]";
        }
    }

    public record MessageResponse(String message) {
    }

    public record CheckResponse(Instant expiresAt) {
    }

    @Operation(summary = "Forgot password", description = "Always 202 with the same message, whether or not the "
            + "email has an account.")
    @PostMapping("/forgot")
    public ResponseEntity<MessageResponse> forgot(@Valid @RequestBody ForgotRequest body, HttpServletRequest request) {
        resets.forgot(body.email(), clientIp.resolve(request));
        return ResponseEntity.status(HttpStatus.ACCEPTED).body(new MessageResponse(SENT));
    }

    @Operation(summary = "Check a reset link")
    @PostMapping("/reset/check")
    public CheckResponse check(@Valid @RequestBody TokenRequest body) {
        return new CheckResponse(resets.check(body.token()));
    }

    @Operation(summary = "Reset the password", description = "Ends every session; then sign in with the new "
            + "password and the authenticator code.")
    @PostMapping("/reset")
    public ResponseEntity<Void> reset(@Valid @RequestBody ResetRequest body, HttpServletRequest request) {
        resets.reset(body.token(), body.password(), clientIp.resolve(request));
        return ResponseEntity.noContent().build();
    }
}
