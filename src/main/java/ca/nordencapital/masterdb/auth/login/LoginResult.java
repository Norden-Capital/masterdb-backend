package ca.nordencapital.masterdb.auth.login;

import ca.nordencapital.masterdb.auth.session.SessionService.IssuedSession;
import ca.nordencapital.masterdb.auth.user.User;

import java.time.Instant;

/**
 * What a login attempt ended in. The service returns it instead of throwing,
 * so that a failed attempt's bookkeeping (failure count, lock) is committed
 * rather than rolled back with an exception.
 *
 * <p><b>Where 2FA goes (M1.3):</b> add a {@code SecondFactorRequired(challenge)}
 * state. {@link LoginService} returns it instead of {@link Authenticated} when
 * the password is right, without starting a session; a second endpoint
 * ({@code POST /api/v1/auth/login/2fa}) takes the challenge and the code and
 * only then starts the session. The controller maps the new state to its own
 * response; nothing else here changes.
 */
public sealed interface LoginResult {

    /** Password right, account active: a session was started. */
    record Authenticated(User user, IssuedSession session) implements LoginResult {
    }

    /** Unknown email, wrong password, or an account that cannot sign in. Deliberately one case. */
    record InvalidCredentials() implements LoginResult {
    }

    /** Too many wrong passwords; no password is checked until {@code until}. */
    record Locked(Instant until) implements LoginResult {
    }
}
