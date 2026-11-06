package ca.nordencapital.masterdb.auth.session;

import ca.nordencapital.masterdb.auth.permission.Action;
import ca.nordencapital.masterdb.auth.permission.Module;
import ca.nordencapital.masterdb.auth.permission.Permission;
import ca.nordencapital.masterdb.auth.user.Emails;

import java.util.Set;
import java.util.SortedSet;
import java.util.UUID;

/**
 * Who is calling: the signed-in user, the session they used and what they may
 * do, as loaded for this request. Controllers get it with
 * {@code @AuthenticationPrincipal}.
 *
 * <p>{@link #toString()} masks the email, so a principal in a log line is safe.
 */
public record AuthPrincipal(
        Long userId,
        UUID userPublicId,
        String email,
        String fullName,
        boolean owner,
        Long sessionId,
        UUID sessionPublicId,
        SortedSet<Permission> permissions) {

    public AuthPrincipal {
        permissions = permissions == null ? new java.util.TreeSet<>() : permissions;
    }

    /** The Owner may do everything; anyone else what is granted. */
    public boolean can(Module module, Action action) {
        return owner || permissions.contains(new Permission(module, action));
    }

    public boolean can(Permission permission) {
        return owner || permissions.contains(permission);
    }

    public boolean canAll(Set<Permission> wanted) {
        return owner || permissions.containsAll(wanted);
    }

    @Override
    public String toString() {
        return "AuthPrincipal[user=" + userPublicId + ", email=" + Emails.mask(email) + ", session="
                + sessionPublicId + "]";
    }
}
