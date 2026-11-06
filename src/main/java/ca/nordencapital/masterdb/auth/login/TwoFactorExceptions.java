package ca.nordencapital.masterdb.auth.login;

import ca.nordencapital.masterdb.web.error.ApiException;
import ca.nordencapital.masterdb.web.error.ErrorCode;
import org.springframework.http.HttpStatus;

/** The 2FA step's refusals. */
final class TwoFactorExceptions {

    private TwoFactorExceptions() {
    }

    /** 401 {@code INVALID_TWO_FACTOR_CODE}. */
    static final class InvalidCode extends ApiException {
        static final String DETAIL = "The code is incorrect or was already used.";

        InvalidCode() {
            super(HttpStatus.UNAUTHORIZED, ErrorCode.INVALID_TWO_FACTOR_CODE, DETAIL, null);
        }
    }

    /** 401 {@code LOGIN_CHALLENGE_INVALID}. */
    static final class ChallengeInvalid extends ApiException {
        static final String DETAIL = "Your sign-in has expired. Sign in again with your password.";

        ChallengeInvalid() {
            super(HttpStatus.UNAUTHORIZED, ErrorCode.LOGIN_CHALLENGE_INVALID, DETAIL, null);
        }
    }
}
