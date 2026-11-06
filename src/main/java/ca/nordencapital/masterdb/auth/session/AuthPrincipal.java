package ca.nordencapital.masterdb.auth.session;

import ca.nordencapital.masterdb.auth.user.Emails;

import java.util.UUID;

/**
 * Who is calling: the signed-in user and the session they used, as loaded for
 * this request. Controllers get it with {@code @AuthenticationPrincipal}.
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
        UUID sessionPublicId) {

    @Override
    public String toString() {
        return "AuthPrincipal[user=" + userPublicId + ", email=" + Emails.mask(email) + ", session="
                + sessionPublicId + "]";
    }
}
