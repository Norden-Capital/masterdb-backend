package ca.nordencapital.masterdb.auth.login;

import ca.nordencapital.masterdb.auth.login.AuthController.UserSummary;
import ca.nordencapital.masterdb.auth.session.AuthPrincipal;
import ca.nordencapital.masterdb.auth.user.User;
import org.springframework.stereotype.Component;

/** Builds the user summary the login and /me answers carry. */
@Component
public class UserSummaries {

    public UserSummary of(User user) {
        return new UserSummary(user.getPublicId(), user.getEmail(), user.getFullName(), user.isOwner());
    }

    public UserSummary of(AuthPrincipal principal) {
        return new UserSummary(principal.userPublicId(), principal.email(), principal.fullName(), principal.owner());
    }
}
