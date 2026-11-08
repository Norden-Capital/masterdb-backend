package ca.nordencapital.masterdb.lists.imports;

import ca.nordencapital.masterdb.web.error.ApiException;
import ca.nordencapital.masterdb.web.error.ErrorCode;
import org.springframework.http.HttpStatus;

import java.util.Map;

/** A list upload refused with its own status and code (the message is the {@code detail}). */
public class ListException extends ApiException {

    private final Map<String, Object> properties;

    public ListException(HttpStatus status, ErrorCode code, String message) {
        this(status, code, message, Map.of());
    }

    public ListException(HttpStatus status, ErrorCode code, String message, Map<String, Object> properties) {
        super(status, code, message, null);
        this.properties = properties;
    }

    @Override
    public Map<String, Object> getProperties() {
        return properties;
    }
}
