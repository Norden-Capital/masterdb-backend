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
    /** The request did not come through the MasterDB website (X-Proxy-Secret missing or wrong; which one is not said). */
    PROXY_SECRET_INVALID,
    FORBIDDEN,
    NOT_FOUND,
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
