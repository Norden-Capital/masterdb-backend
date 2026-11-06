package ca.nordencapital.masterdb.auth.admin;

import ca.nordencapital.masterdb.auth.admin.UserAdminService.UserDetail;
import ca.nordencapital.masterdb.auth.admin.UserAdminService.UserItem;
import ca.nordencapital.masterdb.auth.permission.Action;
import ca.nordencapital.masterdb.auth.permission.Module;
import ca.nordencapital.masterdb.auth.permission.Permission;
import ca.nordencapital.masterdb.auth.permission.RequiresPermission;
import ca.nordencapital.masterdb.auth.session.AuthPrincipal;
import ca.nordencapital.masterdb.auth.session.SessionService.SessionView;
import ca.nordencapital.masterdb.auth.user.Emails;
import ca.nordencapital.masterdb.auth.user.UserStatus;
import ca.nordencapital.masterdb.web.error.BadRequestException;
import ca.nordencapital.masterdb.web.paging.PageParams;
import ca.nordencapital.masterdb.web.paging.PageResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import org.springdoc.core.annotations.ParameterObject;
import org.springframework.data.domain.Sort;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;

/** Users and invitations (M1.5). Every call needs a USERS permission; see UserAdminService for the rest. */
@Tag(name = "Users")
@RestController
@RequestMapping("/api/v1/users")
public class UsersController {

    static final Set<String> SORTABLE = Set.of("email", "fullName", "status", "createdAt", "lastLoginAt");

    private final UserAdminService service;

    public UsersController(UserAdminService service) {
        this.service = service;
    }

    public record InviteRequest(@NotBlank @Size(max = Emails.MAX_LENGTH) String email,
            @Size(max = 200) String fullName, List<String> permissions) {
        @Override
        public String toString() {
            return "InviteRequest[" + Emails.mask(email) + "]";
        }
    }

    public record PermissionsRequest(@NotNull List<String> permissions) {
    }

    public record PermissionsResponse(List<String> permissions) {
    }

    public record RevokedResponse(int sessionsEnded) {
    }

    @Operation(summary = "List users", description = "Search `q` in email and name, filter by `status`. "
            + "Sort: email, fullName, status, createdAt, lastLoginAt.")
    @RequiresPermission(module = Module.USERS, action = Action.VIEW)
    @GetMapping
    public PageResponse<UserItem> list(@ParameterObject PageParams params,
            @RequestParam(required = false) String q, @RequestParam(required = false) UserStatus status) {
        return PageResponse.from(service.list(params.toPageable(SORTABLE, Sort.by("createdAt").descending()), q,
                status));
    }

    @Operation(summary = "One user", description = "With effective permissions, recovery codes left and open sessions.")
    @RequiresPermission(module = Module.USERS, action = Action.VIEW)
    @GetMapping("/{id}")
    public UserDetail detail(@PathVariable UUID id) {
        return service.detail(id);
    }

    @Operation(summary = "Invite someone", description = "Emails a link valid 72 hours, once. 409 if the email "
            + "already has an account or a pending invitation.")
    @RequiresPermission(module = Module.USERS, action = Action.CREATE)
    @PostMapping("/invites")
    public ResponseEntity<UserItem> invite(@AuthenticationPrincipal AuthPrincipal caller,
            @Valid @RequestBody InviteRequest body) {
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(service.invite(caller, body.email(), body.fullName(), parse(body.permissions())));
    }

    @Operation(summary = "Resend an invitation", description = "A new link; the old one stops working.")
    @RequiresPermission(module = Module.USERS, action = Action.CREATE)
    @PostMapping("/{id}/invite/resend")
    public UserItem resend(@AuthenticationPrincipal AuthPrincipal caller, @PathVariable UUID id) {
        return service.resendInvite(caller, id);
    }

    @Operation(summary = "Cancel an invitation", description = "Removes the never-used account.")
    @RequiresPermission(module = Module.USERS, action = Action.DELETE)
    @DeleteMapping("/{id}/invite")
    public ResponseEntity<Void> cancel(@AuthenticationPrincipal AuthPrincipal caller, @PathVariable UUID id) {
        service.cancelInvite(caller, id);
        return ResponseEntity.noContent().build();
    }

    @Operation(summary = "Disable", description = "Signs the person out everywhere. Never the Owner or yourself.")
    @RequiresPermission(module = Module.USERS, action = Action.EDIT)
    @PostMapping("/{id}/disable")
    public UserItem disable(@AuthenticationPrincipal AuthPrincipal caller, @PathVariable UUID id) {
        return service.disable(caller, id);
    }

    @RequiresPermission(module = Module.USERS, action = Action.EDIT)
    @PostMapping("/{id}/enable")
    public UserItem enable(@AuthenticationPrincipal AuthPrincipal caller, @PathVariable UUID id) {
        return service.enable(caller, id);
    }

    @Operation(summary = "Reset two-factor", description = "The person enrols again at the next sign-in; "
            + "their sessions end.")
    @RequiresPermission(module = Module.USERS, action = Action.EDIT)
    @PostMapping("/{id}/2fa/reset")
    public UserItem resetTwoFactor(@AuthenticationPrincipal AuthPrincipal caller, @PathVariable UUID id) {
        return service.resetTwoFactor(caller, id);
    }

    @Operation(summary = "Replace permissions", description = "MODULE:ACTION list. VIEW is added for any module "
            + "with another action. You can only grant or remove permissions you hold.")
    @RequiresPermission(module = Module.USERS, action = Action.EDIT)
    @PutMapping("/{id}/permissions")
    public PermissionsResponse setPermissions(@AuthenticationPrincipal AuthPrincipal caller, @PathVariable UUID id,
            @Valid @RequestBody PermissionsRequest body) {
        return new PermissionsResponse(service.setPermissions(caller, id, parse(body.permissions())));
    }

    @RequiresPermission(module = Module.USERS, action = Action.VIEW)
    @GetMapping("/{id}/sessions")
    public List<SessionView> sessions(@PathVariable UUID id) {
        return service.sessionsOf(id);
    }

    @RequiresPermission(module = Module.USERS, action = Action.EDIT)
    @DeleteMapping("/{id}/sessions/{sessionId}")
    public ResponseEntity<Void> revokeSession(@AuthenticationPrincipal AuthPrincipal caller, @PathVariable UUID id,
            @PathVariable UUID sessionId) {
        service.revokeSession(caller, id, sessionId);
        return ResponseEntity.noContent().build();
    }

    @RequiresPermission(module = Module.USERS, action = Action.EDIT)
    @DeleteMapping("/{id}/sessions")
    public RevokedResponse revokeAll(@AuthenticationPrincipal AuthPrincipal caller, @PathVariable UUID id) {
        return new RevokedResponse(service.revokeAllSessions(caller, id));
    }

    static Set<Permission> parse(List<String> values) {
        Set<Permission> out = new LinkedHashSet<>();
        if (values == null) {
            return out;
        }
        for (String value : values) {
            try {
                out.add(Permission.parse(value));
            } catch (IllegalArgumentException e) {
                throw BadRequestException.validation("permissions", "unknown permission (MODULE:ACTION from the catalogue)");
            }
        }
        return out;
    }
}
