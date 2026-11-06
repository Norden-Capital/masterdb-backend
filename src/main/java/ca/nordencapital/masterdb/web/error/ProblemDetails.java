package ca.nordencapital.masterdb.web.error;

import org.springframework.http.HttpStatusCode;
import org.springframework.http.ProblemDetail;

import java.time.Instant;
import java.util.List;

/**
 * Builds the one error shape (RFC 9457 problem+json) used by every error
 * response: the standard {@code type, title, status, detail, instance} plus
 * {@code code}, {@code timestamp}, {@code requestId} and, for validation
 * failures, {@code errors}.
 */
public final class ProblemDetails {

    public static final String CODE = "code";
    public static final String TIMESTAMP = "timestamp";
    public static final String REQUEST_ID = "requestId";
    public static final String ERRORS = "errors";

    /**
     * Request attributes a servlet filter sets before {@code sendError(...)} to
     * give the /error body its own {@link ErrorCode} and detail instead of the
     * status's defaults (see ProblemErrorController).
     */
    public static final String CODE_ATTRIBUTE = ProblemDetails.class.getName() + ".code";
    public static final String DETAIL_ATTRIBUTE = ProblemDetails.class.getName() + ".detail";

    static final String VALIDATION_DETAIL = "The request has invalid fields.";
    static final String INTERNAL_DETAIL = "An unexpected error occurred. Quote the requestId when reporting it.";
    static final String NOT_FOUND_DETAIL = "The requested resource was not found.";

    private ProblemDetails() {
    }

    public static ProblemDetail of(HttpStatusCode status, ErrorCode code, String detail) {
        ProblemDetail problem = ProblemDetail.forStatusAndDetail(status, detail);
        problem.setProperty(CODE, code.name());
        return problem;
    }

    public static ProblemDetail validation(List<FieldViolation> errors) {
        ProblemDetail problem = of(HttpStatusCode.valueOf(400), ErrorCode.VALIDATION_FAILED, VALIDATION_DETAIL);
        problem.setProperty(ERRORS, List.copyOf(errors));
        return problem;
    }

    /**
     * Adds the properties every error carries. Server errors always get the
     * generic detail, whatever was set before, so no exception text can leak.
     */
    public static ProblemDetail complete(ProblemDetail problem, String requestId) {
        HttpStatusCode status = HttpStatusCode.valueOf(problem.getStatus());
        if (status.is5xxServerError()) {
            problem.setDetail(INTERNAL_DETAIL);
        }
        if (problem.getProperties() == null || !problem.getProperties().containsKey(CODE)) {
            problem.setProperty(CODE, ErrorCode.fromStatus(status).name());
        }
        problem.setProperty(TIMESTAMP, Instant.now());
        problem.setProperty(REQUEST_ID, requestId);
        return problem;
    }
}
