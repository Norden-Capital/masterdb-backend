package ca.nordencapital.masterdb.dns.namecheap;

import ca.nordencapital.masterdb.web.error.ApiException;
import ca.nordencapital.masterdb.web.error.ErrorCode;
import org.springframework.http.HttpStatus;

/**
 * A Namecheap call failed. 502: the problem is between us and Namecheap, not
 * in the request. The message is written for the user and never contains
 * the API key (the client removes it from anything Namecheap sends back).
 */
public class NamecheapException extends ApiException {

    public NamecheapException(ErrorCode code, String message) {
        super(code == ErrorCode.NAMECHEAP_NOT_CONFIGURED ? HttpStatus.CONFLICT : HttpStatus.BAD_GATEWAY, code,
                message, null);
    }

    public static NamecheapException notConfigured() {
        return new NamecheapException(ErrorCode.NAMECHEAP_NOT_CONFIGURED,
                "No Namecheap account is saved yet. Add it on the Namecheap account page.");
    }
}
