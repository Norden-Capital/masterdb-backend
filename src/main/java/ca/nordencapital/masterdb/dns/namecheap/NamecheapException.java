package ca.nordencapital.masterdb.dns.namecheap;

import ca.nordencapital.masterdb.web.error.ApiException;
import ca.nordencapital.masterdb.web.error.ErrorCode;
import org.springframework.http.HttpStatus;

/**
 * A Namecheap call failed. 424 Failed Dependency: the request was fine but
 * the call it depends on failed. Not 502: every 5xx detail is replaced by a
 * generic text (ProblemDetails), and here the user needs the reason ("IP not
 * whitelisted"). The message never contains the API key (the client removes
 * it from anything Namecheap sends back).
 */
public class NamecheapException extends ApiException {

    public NamecheapException(ErrorCode code, String message) {
        super(code == ErrorCode.NAMECHEAP_NOT_CONFIGURED ? HttpStatus.CONFLICT : HttpStatus.FAILED_DEPENDENCY, code,
                message, null);
    }

    public static NamecheapException notConfigured() {
        return new NamecheapException(ErrorCode.NAMECHEAP_NOT_CONFIGURED,
                "No Namecheap account is saved yet. Add it on the Namecheap account page.");
    }
}
