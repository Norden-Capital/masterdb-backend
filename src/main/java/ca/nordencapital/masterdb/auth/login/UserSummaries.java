package ca.nordencapital.masterdb.auth.login;

import ca.nordencapital.masterdb.auth.login.AuthController.UserSummary;
import ca.nordencapital.masterdb.auth.permission.Permission;
import ca.nordencapital.masterdb.auth.permission.PermissionService;
import ca.nordencapital.masterdb.auth.session.AuthPrincipal;
import ca.nordencapital.masterdb.auth.user.User;
import org.springframework.stereotype.Component;

/** Builds the user summary the login and /me answers carry, with the effective permissions. */
@Component
public class UserSummaries {

    private final PermissionService permissions;

    public UserSummaries(PermissionService permissions) {
        this.permissions = permissions;
    }

    public UserSummary of(User user) {
        return new UserSummary(user.getPublicId(), user.getEmail(), user.getFullName(), user.isOwner(),
                permissions.effective(user).stream().map(Permission::toString).toList());
    }

    public UserSummary of(AuthPrincipal principal) {
        return new UserSummary(principal.userPublicId(), principal.email(), principal.fullName(), principal.owner(),
                principal.permissions().stream().map(Permission::toString).toList());
    }
}
