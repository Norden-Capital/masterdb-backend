package ca.nordencapital.masterdb.auth.permission;

import ca.nordencapital.masterdb.web.error.ApiException;
import ca.nordencapital.masterdb.web.error.ErrorCode;
import org.springframework.http.HttpStatus;

/** 403 {@code FORBIDDEN}: signed in, but not allowed to do this. */
public class ForbiddenException extends ApiException {

    public static final String DETAIL = "You do not have permission to do this.";

    public ForbiddenException() {
        this(DETAIL);
    }

    public ForbiddenException(String message) {
        super(HttpStatus.FORBIDDEN, ErrorCode.FORBIDDEN, message, null);
    }
}
