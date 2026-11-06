package ca.nordencapital.masterdb.web.error;

import org.springframework.http.HttpStatus;

/** 404 {@code NOT_FOUND}: the thing asked for does not exist. */
public class NotFoundException extends ApiException {

    public NotFoundException(String message) {
        super(HttpStatus.NOT_FOUND, ErrorCode.NOT_FOUND, message, null);
    }
}
