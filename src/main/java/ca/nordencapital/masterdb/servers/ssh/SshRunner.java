package ca.nordencapital.masterdb.servers.ssh;

import java.time.Duration;

/**
 * SSH to the VPS servers, with MasterDB's own key only. Tests point it at an
 * embedded fake SSH server: no test ever reaches a real machine.
 */
public interface SshRunner {

    /**
     * Opens a connection only far enough to see the server's host key, then
     * drops it: never logs in, so a server that isn't trusted yet never gets
     * a login attempt.
     */
    PresentedKey probe(String host, int port, Duration timeout);

    /**
     * Logs in and runs one command. The server must present exactly the
     * pinned host key, otherwise nothing is sent and {@link SshFailure} with
     * HOST_KEY_CHANGED is thrown. {@code stdin} (may be null) is sent and
     * closed; each output line (stdout and stderr) goes to {@code sink} as it
     * arrives.
     */
    Result exec(Target target, String command, byte[] stdin, Duration timeout, LineSink sink);

    /**
     * Like {@link #exec} but logs in with a password instead of MasterDB's key:
     * only to put MasterDB's key on a new server. The same strict host-key
     * check comes first, so the password is never sent to another machine.
     * The password is not kept or logged.
     */
    Result execWithPassword(Target target, String password, String command, Duration timeout);

    /**
     * Logs in with MasterDB's key (same strict host-key check as {@link #exec})
     * and keeps the connection open for TCP connections made <b>by the server</b>
     * (SSH "direct-tcpip"): an SMTP probe through it leaves from the server's IP.
     * Nothing runs on the server. The caller closes it.
     */
    Tunnel tunnel(Target target, Duration timeout);

    record Target(String host, int port, String user, String pinnedKey) {
    }

    /** An open SSH connection to one server, for TCP connections from it. */
    interface Tunnel extends AutoCloseable {

        /**
         * Asks the server to connect to {@code host:port}; reads from the stream
         * time out after {@code readTimeout}. Throws {@link java.io.IOException}
         * when the server can't connect (port 25 blocked, host down).
         */
        Stream connect(String host, int port, Duration readTimeout) throws java.io.IOException;

        boolean isOpen();

        @Override
        void close();
    }

    /** One TCP connection through a {@link Tunnel}. */
    interface Stream extends AutoCloseable {
        java.io.InputStream in();

        java.io.OutputStream out();

        @Override
        void close();
    }

    /** A host key as the server presented it. */
    record PresentedKey(String type, String fingerprint, String publicKey) {
    }

    /** Exit code (-1 if the server sent none), the output (capped) and whether it was cut. */
    record Result(int exitCode, String output, boolean truncated) {
    }

    @FunctionalInterface
    interface LineSink {
        LineSink NONE = line -> { };

        void line(String line);
    }
}
