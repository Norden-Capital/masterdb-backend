package ca.nordencapital.masterdb.web.error;

import org.springframework.http.HttpStatus;

import java.util.List;

/**
 * 400. Plain {@code new BadRequestException("...")} gives {@code BAD_REQUEST};
 * {@link #validation} gives {@code VALIDATION_FAILED} with an {@code errors}
 * array, for rules bean validation cannot express.
 */
public class BadRequestException extends ApiException {

    public BadRequestException(String message) {
        super(HttpStatus.BAD_REQUEST, ErrorCode.BAD_REQUEST, message, null);
    }

    private BadRequestException(List<FieldViolation> errors) {
        super(HttpStatus.BAD_REQUEST, ErrorCode.VALIDATION_FAILED, ProblemDetails.VALIDATION_DETAIL, errors);
    }

    public static BadRequestException validation(String field, String message) {
        return new BadRequestException(List.of(new FieldViolation(field, message)));
    }

    public static BadRequestException validation(List<FieldViolation> errors) {
        return new BadRequestException(errors);
    }
}
