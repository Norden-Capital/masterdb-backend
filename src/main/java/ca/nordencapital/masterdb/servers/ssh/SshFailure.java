package ca.nordencapital.masterdb.servers.ssh;

import ca.nordencapital.masterdb.web.error.ApiException;
import ca.nordencapital.masterdb.web.error.ErrorCode;
import org.springframework.http.HttpStatus;

/**
 * An SSH connection or command that did not work. The message is for the
 * user (it becomes {@code detail}): never a key, a command's secret input or
 * a stack trace. HOST_KEY_CHANGED answers 409 SERVER_HOST_KEY_CHANGED, the
 * rest 424 SSH_FAILED (the request was fine; the server it depends on was not).
 */
public class SshFailure extends ApiException {

    public enum Kind {
        /** No TCP connection, or it broke before SSH was set up. */
        UNREACHABLE,
        /** No answer in time. */
        TIMEOUT,
        /** The server did not accept MasterDB's key for this user. */
        AUTH_REFUSED,
        /** The server presented another host key than the pinned one. */
        HOST_KEY_CHANGED,
        /** Anything else in the SSH protocol. */
        PROTOCOL
    }

    private final Kind kind;
    private final transient SshRunner.PresentedKey presented;

    public SshFailure(Kind kind, String message) {
        this(kind, message, null);
    }

    public SshFailure(Kind kind, String message, SshRunner.PresentedKey presented) {
        super(kind == Kind.HOST_KEY_CHANGED ? HttpStatus.CONFLICT : HttpStatus.FAILED_DEPENDENCY,
                kind == Kind.HOST_KEY_CHANGED ? ErrorCode.SERVER_HOST_KEY_CHANGED : ErrorCode.SSH_FAILED, message,
                null);
        this.kind = kind;
        this.presented = presented;
    }

    public Kind kind() {
        return kind;
    }

    /** The key the server showed (HOST_KEY_CHANGED only). */
    public SshRunner.PresentedKey presented() {
        return presented;
    }
}
