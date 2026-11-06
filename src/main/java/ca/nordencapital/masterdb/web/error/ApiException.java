package ca.nordencapital.masterdb.web.error;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;

import java.util.List;
import java.util.Map;

/**
 * Base for the errors the app throws on purpose. The global handler turns each
 * into a problem+json response with this status and code.
 *
 * <p><b>The message is shown to the caller as {@code detail}.</b> Write it for
 * the user ("Contact 42 was not found") and never put internals, SQL or
 * exception text in it. Anything that is not an {@code ApiException} is
 * answered with a generic 500 instead.
 */
public abstract class ApiException extends RuntimeException {

    private final HttpStatus status;
    private final ErrorCode code;
    private final List<FieldViolation> errors;

    protected ApiException(HttpStatus status, ErrorCode code, String message, List<FieldViolation> errors) {
        super(message);
        this.status = status;
        this.code = code;
        this.errors = errors == null ? List.of() : List.copyOf(errors);
    }

    public HttpStatus getStatus() {
        return status;
    }

    public ErrorCode getCode() {
        return code;
    }

    /** Per-field problems; empty unless the code is {@code VALIDATION_FAILED}. */
    public List<FieldViolation> getErrors() {
        return errors;
    }

    /** Extra response headers (for example {@code Retry-After}). None by default. */
    public HttpHeaders getHeaders() {
        return new HttpHeaders();
    }

    /** Extra fields for the error body, next to {@code code}. None by default. Never user input. */
    public Map<String, Object> getProperties() {
        return Map.of();
    }
}
