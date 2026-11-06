package ca.nordencapital.masterdb.auth.login;

import ca.nordencapital.masterdb.auth.twofactor.TwoFactorService.Started;

import java.time.Instant;

/**
 * What a login attempt ended in. The service returns it instead of throwing,
 * so that a failed attempt's bookkeeping (failure count, lock) is committed
 * rather than rolled back with an exception.
 *
 * <p>A right password never signs in by itself (M1.3): it opens a 2FA
 * challenge, and TwoFactorService starts the session after the code.
 */
public sealed interface LoginResult {

    /** Password right, account active: a 2FA challenge was opened (VERIFY or SETUP). */
    record SecondFactorRequired(Started challenge) implements LoginResult {
    }

    /** Unknown email, wrong password, or an account that cannot sign in. Deliberately one case. */
    record InvalidCredentials() implements LoginResult {
    }

    /** Too many wrong passwords; no password is checked until {@code until}. */
    record Locked(Instant until) implements LoginResult {
    }
}
