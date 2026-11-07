package ca.nordencapital.masterdb.mta;

import ca.nordencapital.masterdb.web.error.ApiException;
import ca.nordencapital.masterdb.web.error.ErrorCode;
import org.springframework.http.HttpStatus;

/** 409 MTA_INSTALL_RUNNING: an install is running on this server, so this can't happen now. */
public class MtaBusyException extends ApiException {

    public MtaBusyException(String message) {
        super(HttpStatus.CONFLICT, ErrorCode.MTA_INSTALL_RUNNING, message, null);
    }
}
