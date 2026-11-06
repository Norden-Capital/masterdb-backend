package ca.nordencapital.masterdb.auth.account;

import ca.nordencapital.masterdb.web.error.ApiException;
import ca.nordencapital.masterdb.web.error.ErrorCode;
import org.springframework.http.HttpStatus;

/** 410 {@code LINK_INVALID}: an emailed link that cannot be used (any reason, never which). */
public class LinkInvalidException extends ApiException {

    public static final String DETAIL = "This link is invalid or has expired. Ask for a new one.";

    public LinkInvalidException() {
        super(HttpStatus.GONE, ErrorCode.LINK_INVALID, DETAIL, null);
    }
}
