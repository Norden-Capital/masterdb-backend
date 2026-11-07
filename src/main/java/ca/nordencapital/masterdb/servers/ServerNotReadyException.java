package ca.nordencapital.masterdb.servers;

import ca.nordencapital.masterdb.web.error.ApiException;
import ca.nordencapital.masterdb.web.error.ErrorCode;
import org.springframework.http.HttpStatus;

/** 409 SERVER_NOT_READY: the server can't be used for this yet (not connected, not privileged, ...). */
public class ServerNotReadyException extends ApiException {

    public ServerNotReadyException(String message) {
        super(HttpStatus.CONFLICT, ErrorCode.SERVER_NOT_READY, message, null);
    }
}
