package ca.nordencapital.masterdb.dns.namecheap;

import ca.nordencapital.masterdb.auth.permission.Action;
import ca.nordencapital.masterdb.auth.permission.Module;
import ca.nordencapital.masterdb.auth.permission.RequiresPermission;
import ca.nordencapital.masterdb.auth.session.AuthPrincipal;
import ca.nordencapital.masterdb.dns.namecheap.NamecheapAccountService.AccountView;
import ca.nordencapital.masterdb.dns.namecheap.NamecheapAccountService.TestResult;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.constraints.Size;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** The one Namecheap account (DNS job 1). The API key goes in, never out. */
@Tag(name = "DNS")
@RestController
@RequestMapping("/api/v1/dns/namecheap/account")
public class NamecheapAccountController {

    private final NamecheapAccountService service;

    public NamecheapAccountController(NamecheapAccountService service) {
        this.service = service;
    }

    /** {@code apiKey} blank = keep the saved key (required the first time). */
    public record SaveRequest(@Size(max = 200) String apiUser, @Size(max = 200) String username,
            @Size(max = 200) String apiKey) {
        @Override
        public String toString() {
            return "SaveRequest[apiUser=" + apiUser + ", username=" + username + ", apiKey=(hidden)]";
        }
    }

    @Operation(summary = "The Namecheap account", description = "API user, username, whether a key is set, the "
            + "client IP this server sends, and the last connection test. The key itself is never returned.")
    @RequiresPermission(module = Module.DNS, action = Action.VIEW)
    @GetMapping
    public AccountView get() {
        return service.view();
    }

    @Operation(summary = "Add or change the account", description = "`apiKey` is required when adding; when "
            + "changing, leave it blank to keep the saved key or send a new one to replace it.")
    @RequiresPermission(module = Module.DNS, action = Action.EDIT)
    @PutMapping
    public AccountView save(@AuthenticationPrincipal AuthPrincipal caller,
            @Validated @RequestBody SaveRequest body) {
        return service.save(caller, body.apiUser(), body.username(), body.apiKey());
    }

    @Operation(summary = "Remove the account", description = "Deletes the saved key. Domains stay.")
    @RequiresPermission(module = Module.DNS, action = Action.DELETE)
    @DeleteMapping
    public ResponseEntity<Void> remove(@AuthenticationPrincipal AuthPrincipal caller) {
        service.remove(caller);
        return ResponseEntity.noContent().build();
    }

    @Operation(summary = "Test the connection", description = "Calls namecheap.domains.getList. Always 200 with "
            + "`ok`; on failure `code` is NAMECHEAP_IP_NOT_WHITELISTED, NAMECHEAP_INVALID_KEY, NAMECHEAP_ERROR or "
            + "NAMECHEAP_UNREACHABLE. 409 NAMECHEAP_NOT_CONFIGURED without an account.")
    @RequiresPermission(module = Module.DNS, action = Action.RUN)
    @PostMapping("/test")
    public TestResult test(@AuthenticationPrincipal AuthPrincipal caller) {
        return service.test(caller);
    }
}
