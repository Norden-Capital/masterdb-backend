package ca.nordencapital.masterdb.auth.login;

import ca.nordencapital.masterdb.web.error.ApiException;
import ca.nordencapital.masterdb.web.error.ErrorCode;
import org.springframework.http.HttpStatus;

/** 401 {@code INVALID_CREDENTIALS}: one answer for every failed login, whatever the reason. */
public class InvalidCredentialsException extends ApiException {

    static final String DETAIL = "The email or password is incorrect.";

    public InvalidCredentialsException() {
        super(HttpStatus.UNAUTHORIZED, ErrorCode.INVALID_CREDENTIALS, DETAIL, null);
    }
}
