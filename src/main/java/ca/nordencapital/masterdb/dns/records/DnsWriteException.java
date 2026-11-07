package ca.nordencapital.masterdb.dns.records;

import ca.nordencapital.masterdb.web.error.ApiException;
import ca.nordencapital.masterdb.web.error.ErrorCode;
import org.springframework.http.HttpStatus;

/** 409: records can't be written now (DNS_WRITE_REFUSED or DNS_CHANGED_SINCE_PREVIEW). */
public class DnsWriteException extends ApiException {

    public DnsWriteException(ErrorCode code, String message) {
        super(HttpStatus.CONFLICT, code, message, null);
    }

    static DnsWriteException refused(String message) {
        return new DnsWriteException(ErrorCode.DNS_WRITE_REFUSED, message);
    }

    static DnsWriteException changed() {
        return new DnsWriteException(ErrorCode.DNS_CHANGED_SINCE_PREVIEW,
                "The records at Namecheap changed since the preview. Preview again before writing.");
    }
}
