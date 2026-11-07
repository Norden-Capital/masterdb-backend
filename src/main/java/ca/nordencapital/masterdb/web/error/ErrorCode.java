package ca.nordencapital.masterdb.web.error;

import org.springframework.http.HttpStatusCode;

/**
 * Stable, machine-readable error codes, sent as {@code code} in every error body.
 *
 * <p>The frontend switches on these, never on {@code title} or {@code detail}
 * (those are for people and may be reworded). Add new codes; never rename one.
 */
public enum ErrorCode {

    /** Input broke a rule: bean validation, wrong type, missing parameter, unknown sort field. Has {@code errors}. */
    VALIDATION_FAILED,
    /** The body is not readable JSON (syntax error, wrong shape, empty). */
    MALFORMED_JSON,
    /** Any other client mistake. */
    BAD_REQUEST,
    UNAUTHORIZED,
    /** No valid session: no cookie, or one that is unknown, ended, expired or idle too long. Sign in again. */
    UNAUTHENTICATED,
    /** Login refused: unknown email, wrong password, or an account that cannot sign in (which one is never said). */
    INVALID_CREDENTIALS,
    /** Login refused: too many wrong passwords; has {@code retryAfterSeconds} and a {@code Retry-After} header. */
    ACCOUNT_LOCKED,
    /** The 2FA code (authenticator or recovery code) is wrong or was already used. */
    INVALID_TWO_FACTOR_CODE,
    /** The 2FA step has no valid login challenge (expired, used up, missing): sign in again. */
    LOGIN_CHALLENGE_INVALID,
    /** An emailed link (invite, password reset) is unknown, used, withdrawn or expired. */
    LINK_INVALID,
    /** Changing your password: the current password given is wrong. */
    CURRENT_PASSWORD_INCORRECT,
    /** Too many login attempts from one address; {@code Retry-After} says when to try again. */
    RATE_LIMITED,
    /** The request did not come through the MasterDB website (X-Proxy-Secret missing or wrong; which one is not said). */
    PROXY_SECRET_INVALID,
    /** Signed in, but not allowed to do this. */
    FORBIDDEN,
    NOT_FOUND,
    /** DNS: no Namecheap account is saved yet. */
    NAMECHEAP_NOT_CONFIGURED,
    /** Namecheap refused the call because this server's IP is not on the account's API whitelist. */
    NAMECHEAP_IP_NOT_WHITELISTED,
    /** Namecheap refused the API key or API user (wrong key, or API access not turned on). */
    NAMECHEAP_INVALID_KEY,
    /** Namecheap answered with another error; {@code detail} has its message. */
    NAMECHEAP_ERROR,
    /** Namecheap could not be reached or sent something unreadable. */
    NAMECHEAP_UNREACHABLE,
    /** DNS: the records at Namecheap changed after the preview; preview again before writing. */
    DNS_CHANGED_SINCE_PREVIEW,
    /** DNS: the records can't be written safely (not a Namecheap domain, other DNS host, record type setHosts can't keep, ...). */
    DNS_WRITE_REFUSED,
    /** Servers: the server presented a different SSH host key than the pinned one; blocked until the Owner accepts it. */
    SERVER_HOST_KEY_CHANGED,
    /** Servers: no trusted host key yet (connect and trust the fingerprint first), or the server can't be used now. */
    SERVER_NOT_READY,
    /** Servers: the SSH connection or the remote command failed; {@code detail} says why. */
    SSH_FAILED,
    /** MTA: an install is already running on this server. */
    MTA_INSTALL_RUNNING,
    METHOD_NOT_ALLOWED,
    NOT_ACCEPTABLE,
    CONFLICT,
    CONTENT_TOO_LARGE,
    UNSUPPORTED_MEDIA_TYPE,
    TOO_MANY_REQUESTS,
    SERVICE_UNAVAILABLE,
    /** Anything unexpected on our side. The body never says what. */
    INTERNAL_ERROR;

    /** Fallback code for a bare HTTP status. */
    public static ErrorCode fromStatus(HttpStatusCode status) {
        return switch (status.value()) {
            case 400 -> BAD_REQUEST;
            case 401 -> UNAUTHORIZED;
            case 403 -> FORBIDDEN;
            case 404 -> NOT_FOUND;
            case 405 -> METHOD_NOT_ALLOWED;
            case 406 -> NOT_ACCEPTABLE;
            case 409 -> CONFLICT;
            case 413 -> CONTENT_TOO_LARGE;
            case 415 -> UNSUPPORTED_MEDIA_TYPE;
            case 429 -> TOO_MANY_REQUESTS;
            case 503 -> SERVICE_UNAVAILABLE;
            default -> status.is4xxClientError() ? BAD_REQUEST : INTERNAL_ERROR;
        };
    }
}
