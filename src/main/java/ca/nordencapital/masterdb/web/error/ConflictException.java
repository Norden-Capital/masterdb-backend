package ca.nordencapital.masterdb.web.error;

import org.springframework.http.HttpStatus;

/** 409 {@code CONFLICT}: the request clashes with the current state (duplicate, already running, ...). */
public class ConflictException extends ApiException {

    public ConflictException(String message) {
        super(HttpStatus.CONFLICT, ErrorCode.CONFLICT, message, null);
    }
}
