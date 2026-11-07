package ca.nordencapital.masterdb.servers.ssh;

import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.auth.keyboard.UserAuthKeyboardInteractiveFactory;
import org.apache.sshd.client.auth.password.PasswordIdentityProvider;
import org.apache.sshd.client.auth.password.UserAuthPasswordFactory;
import org.apache.sshd.client.auth.pubkey.UserAuthPublicKeyFactory;
import org.apache.sshd.client.channel.ChannelDirectTcpip;
import org.apache.sshd.client.channel.ChannelExec;
import org.apache.sshd.common.channel.ChannelPipedInputStream;
import org.apache.sshd.common.util.net.SshdSocketAddress;
import java.io.InputStream;
import org.apache.sshd.client.channel.ClientChannelEvent;
import org.apache.sshd.client.config.hosts.HostConfigEntryResolver;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.client.session.ClientSession.ClientSessionEvent;
import org.apache.sshd.common.AttributeRepository;
import org.apache.sshd.common.AttributeRepository.AttributeKey;
import org.apache.sshd.common.SshException;
import org.apache.sshd.common.keyprovider.KeyIdentityProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.DisposableBean;
import org.springframework.stereotype.Component;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.ConnectException;
import java.net.NoRouteToHostException;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PublicKey;
import java.time.Duration;
import java.util.EnumSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;

/**
 * {@link SshRunner} on Apache Mina SSHD. One client for the app; each call
 * carries the pinned key in its own connection context, so the host-key
 * check is decided per connection with no shared state.
 *
 * <p>The client is locked down: MasterDB's key (or a one-time password for adding it), no ~/.ssh/config, no
 * keys or known_hosts from the backend's home folder. MasterDB's key comes
 * from {@link SshIdentityService} for each login.
 */
@Component
public class MinaSshRunner implements SshRunner, DisposableBean {

    static final int MAX_OUTPUT = 512 * 1024;
    static final int MAX_LINE = 4000;
    private static final Duration AUTH_TIMEOUT = Duration.ofSeconds(15);
    private static final AttributeKey<String> EXPECTED = new AttributeKey<>();
    private static final AttributeKey<AtomicReference<PublicKey>> SEEN = new AttributeKey<>();
    private static final Logger log = LoggerFactory.getLogger(MinaSshRunner.class);

    private final SshClient client;
    private final SshIdentityService identity;

    public MinaSshRunner(SshIdentityService identity) {
        this.identity = identity;
        this.client = SshClient.setUpDefaultClient();
        client.setHostConfigEntryResolver(HostConfigEntryResolver.EMPTY);
        client.setKeyIdentityProvider(KeyIdentityProvider.EMPTY_KEYS_PROVIDER);
        client.setPasswordIdentityProvider(PasswordIdentityProvider.EMPTY_PASSWORDS_PROVIDER);
        // Password methods only ever run in a session that added a password (execWithPassword);
        // the client has no password of its own.
        client.setUserAuthFactories(List.of(UserAuthPublicKeyFactory.INSTANCE, UserAuthPasswordFactory.INSTANCE,
                UserAuthKeyboardInteractiveFactory.INSTANCE));
        client.setServerKeyVerifier((session, address, key) -> {
            AttributeRepository ctx = session.getConnectionContext();
            if (ctx == null) {
                return false;
            }
            AtomicReference<PublicKey> seen = ctx.getAttribute(SEEN);
            if (seen != null) {
                seen.set(key);
            }
            String expected = ctx.getAttribute(EXPECTED);
            return expected != null && SshKeys.same(key, expected);
        });
        client.start();
    }

    @Override
    public void destroy() throws IOException {
        client.stop();
        client.close();
    }

    @Override
    public PresentedKey probe(String host, int port, Duration timeout) {
        AtomicReference<PublicKey> seen = new AtomicReference<>();
        AttributeRepository ctx = AttributeRepository.ofAttributesMap(Map.of(SEEN, seen));
        try (ClientSession session = connect("probe", host, port, ctx, timeout)) {
            // No EXPECTED key: the verifier records the key and refuses, so the session ends before any login.
            session.waitFor(EnumSet.of(ClientSessionEvent.CLOSED), timeout.toMillis());
        } catch (IOException e) {
            if (seen.get() == null) {
                throw failure(e, host, port);
            }
        }
        PublicKey key = seen.get();
        if (key == null) {
            throw new SshFailure(SshFailure.Kind.TIMEOUT, "No SSH host key from " + host + ":" + port
                    + " within " + timeout.toSeconds() + " seconds.");
        }
        return presented(key);
    }

    @Override
    public Result exec(Target target, String command, byte[] stdin, Duration timeout, LineSink sink) {
        KeyPair key = identity.keyPair();
        return session(target, timeout, session -> session.addPublicKeyIdentity(key), "The server refused "
                + "MasterDB's SSH key for user " + target.user() + ". Add the public key (Add VPS server page) to "
                + "that user's ~/.ssh/authorized_keys, or let MasterDB add it with the password.",
                session -> run(session, command, stdin, timeout, sink));
    }

    @Override
    public Result execWithPassword(Target target, String password, String command, Duration timeout) {
        return session(target, timeout, session -> {
            session.addPasswordIdentity(password);
        }, "The server refused the password for user " + target.user() + ". Check it and try again.",
                session -> run(session, command, null, timeout, null));
    }

    private interface SessionStep<T> {
        T apply(ClientSession session) throws IOException;
    }

    private interface AuthSetup {
        void apply(ClientSession session) throws IOException;
    }

    private <T> T session(Target target, Duration timeout, AuthSetup auth, String refused, SessionStep<T> work) {
        try (ClientSession session = login(target, timeout, auth, refused)) {
            return work.apply(session);
        } catch (SshFailure f) {
            throw f;
        } catch (IOException e) {
            throw failure(e, target.host(), target.port());
        }
    }

    /** A logged-in session (the caller closes it); the host key must be the pinned one. */
    private ClientSession login(Target target, Duration timeout, AuthSetup auth, String refused) {
        AtomicReference<PublicKey> seen = new AtomicReference<>();
        AttributeRepository ctx = AttributeRepository.ofAttributesMap(Map.of(SEEN, seen, EXPECTED,
                target.pinnedKey()));
        Duration connectTimeout = Duration.ofSeconds(Math.min(20, Math.max(5, timeout.toSeconds())));
        ClientSession session = null;
        try {
            session = connect(target.user(), target.host(), target.port(), ctx, connectTimeout);
            auth.apply(session);
            try {
                session.auth().verify(AUTH_TIMEOUT);
            } catch (IOException e) {
                PublicKey shown = seen.get();
                if (shown != null && !SshKeys.same(shown, target.pinnedKey())) {
                    throw new SshFailure(SshFailure.Kind.HOST_KEY_CHANGED, "The server at " + target.host() + ":"
                            + target.port() + " presented a different SSH host key (" + SshKeys.fingerprint(shown)
                            + "). Nothing was sent to it.", presented(shown));
                }
                if (shown == null) {
                    throw failure(e, target.host(), target.port());
                }
                throw new SshFailure(SshFailure.Kind.AUTH_REFUSED, refused);
            }
            return session;
        } catch (SshFailure f) {
            closeQuietly(session);
            throw f;
        } catch (IOException e) {
            closeQuietly(session);
            throw failure(e, target.host(), target.port());
        }
    }

    private static void closeQuietly(ClientSession session) {
        if (session != null) {
            try {
                session.close();
            } catch (IOException ignored) {
                // already failing
            }
        }
    }

    @Override
    public Tunnel tunnel(Target target, Duration timeout) {
        KeyPair key = identity.keyPair();
        ClientSession session = login(target, timeout, s -> s.addPublicKeyIdentity(key), "The server refused "
                + "MasterDB's SSH key for user " + target.user() + ".");
        return new MinaTunnel(session);
    }

    /** direct-tcpip channels on one session: the server opens the TCP connection. */
    private record MinaTunnel(ClientSession session) implements Tunnel {

        @Override
        public Stream connect(String host, int port, Duration readTimeout) throws IOException {
            ChannelDirectTcpip channel = session.createDirectTcpipChannel(new SshdSocketAddress("127.0.0.1", 0),
                    new SshdSocketAddress(host, port));
            try {
                channel.open().verify(readTimeout);
            } catch (IOException e) {
                channel.close(true);
                throw new IOException("The server could not connect to " + host + ":" + port, e);
            }
            InputStream in = channel.getInvertedOut();
            if (in instanceof ChannelPipedInputStream piped) {
                piped.setTimeout(readTimeout.toMillis());
            }
            OutputStream out = channel.getInvertedIn();
            return new Stream() {
                @Override
                public InputStream in() {
                    return in;
                }

                @Override
                public OutputStream out() {
                    return out;
                }

                @Override
                public void close() {
                    // Graceful: what was written (QUIT) is sent first.
                    channel.close(false);
                }
            };
        }

        @Override
        public boolean isOpen() {
            return session.isOpen() && session.isAuthenticated();
        }

        @Override
        public void close() {
            closeQuietly(session);
        }
    }

    private static Result run(ClientSession session, String command, byte[] stdin, Duration timeout, LineSink sink)
            throws IOException {
        Lines out = new Lines(sink);
        try (ChannelExec channel = session.createExecChannel(command)) {
            channel.setIn(new ByteArrayInputStream(stdin == null ? new byte[0] : stdin));
            channel.setOut(out);
            channel.setErr(out);
            channel.open().verify(Duration.ofSeconds(15));
            Set<ClientChannelEvent> events = channel.waitFor(EnumSet.of(ClientChannelEvent.CLOSED),
                    timeout.toMillis());
            out.finish();
            if (events.contains(ClientChannelEvent.TIMEOUT)) {
                throw new SshFailure(SshFailure.Kind.TIMEOUT, "The command did not finish within "
                        + timeout.toSeconds() + " seconds.");
            }
            Integer code = channel.getExitStatus();
            return new Result(code == null ? -1 : code, out.text(), out.truncated);
        }
    }

    private ClientSession connect(String user, String host, int port, AttributeRepository ctx, Duration timeout)
            throws IOException {
        return client.connect(user, host, port, ctx, null).verify(timeout).getSession();
    }

    private static PresentedKey presented(PublicKey key) {
        return new PresentedKey(SshKeys.type(key), SshKeys.fingerprint(key), SshKeys.openSsh(key));
    }

    /** A reason for the user; the exception goes to the log at DEBUG only (it holds no secret anyway). */
    static SshFailure failure(Throwable e, String host, int port) {
        log.debug("ssh to {}:{} failed", host, port, e);
        String where = host + ":" + port;
        for (Throwable t = e; t != null; t = t.getCause()) {
            if (t instanceof ConnectException) {
                return new SshFailure(SshFailure.Kind.UNREACHABLE, "Connection to " + where
                        + " was refused. Check the IP, the SSH port and the VPS firewall.");
            }
            if (t instanceof SocketTimeoutException || (t.getMessage() != null
                    && t.getMessage().toLowerCase(Locale.ROOT).contains("timeout"))) {
                return new SshFailure(SshFailure.Kind.TIMEOUT, "No answer from " + where
                        + " in time. Check the IP, the SSH port and the VPS firewall.");
            }
            if (t instanceof NoRouteToHostException || t instanceof UnknownHostException) {
                return new SshFailure(SshFailure.Kind.UNREACHABLE, "No route to " + where + ".");
            }
        }
        if (e instanceof SshException) {
            return new SshFailure(SshFailure.Kind.PROTOCOL, "The SSH connection to " + where
                    + " closed unexpectedly. Try again; if it keeps happening, check the server's SSH service.");
        }
        return new SshFailure(SshFailure.Kind.UNREACHABLE, "Couldn't connect to " + where + ".");
    }

    /** Splits the output into lines for the sink and keeps the text (capped). */
    static final class Lines extends OutputStream {
        private final LineSink sink;
        private final ByteArrayOutputStream line = new ByteArrayOutputStream();
        private final StringBuilder all = new StringBuilder();
        private boolean truncated;

        Lines(LineSink sink) {
            this.sink = sink == null ? LineSink.NONE : sink;
        }

        @Override
        public synchronized void write(int b) {
            if (b == '\n') {
                flushLine();
            } else if (b != '\r' && line.size() < MAX_LINE) {
                line.write(b);
            }
        }

        @Override
        public synchronized void write(byte[] b, int off, int len) {
            for (int i = off; i < off + len; i++) {
                write(b[i]);
            }
        }

        synchronized void finish() {
            if (line.size() > 0) {
                flushLine();
            }
        }

        synchronized String text() {
            return all.toString();
        }

        private void flushLine() {
            String text = line.toString(StandardCharsets.UTF_8);
            line.reset();
            if (all.length() + text.length() + 1 <= MAX_OUTPUT) {
                all.append(text).append('\n');
            } else {
                truncated = true;
            }
            sink.line(text);
        }
    }
}
