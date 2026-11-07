package ca.nordencapital.testsupport;

import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.config.keys.PublicKeyEntry;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.command.AbstractCommandSupport;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.function.Predicate;

/**
 * An SSH server on 127.0.0.1 for tests and local trials: Mina SSHD with
 * scripted answers instead of a shell. Nothing is ever run on this machine.
 *
 * <ul>
 *   <li>The host key can be swapped ({@link #newHostKey()}) to play a reinstalled
 *       or impostor server.</li>
 *   <li>Only authorized public keys log in ({@link #authorize}, or an
 *       authorized_keys file for {@code LocalDevServer}).</li>
 *   <li>Each command (with what was sent on stdin) is recorded, and answered by the
 *       first rule whose marker is in the command or stdin; otherwise exit 0, no output.</li>
 * </ul>
 */
public final class FakeSshServer implements AutoCloseable {

    /** One recorded command: the user, the command line and its stdin. */
    public record Exchange(String user, String command, String stdin) {
        public boolean has(String marker) {
            return command.contains(marker) || stdin.contains(marker);
        }
    }

    /** An answer; {@code gate} (optional) holds it until released, to look at a job mid-way. */
    public record Reply(int exit, String output, CountDownLatch gate) {
    }

    private record Rule(Predicate<Exchange> when, Reply reply) {
    }

    private final SshServer server;
    private volatile KeyPair hostKey;
    private final Set<String> authorized = java.util.concurrent.ConcurrentHashMap.newKeySet();
    private volatile Path authorizedKeysFile;
    private final List<Exchange> exchanges = new CopyOnWriteArrayList<>();
    private final List<String> logins = new CopyOnWriteArrayList<>();
    private final List<Rule> rules = new CopyOnWriteArrayList<>();
    private final List<Rule> effects = new CopyOnWriteArrayList<>();
    private volatile String password;

    public FakeSshServer(int port) {
        newHostKey();
        server = SshServer.setUpDefaultServer();
        server.setHost("127.0.0.1");
        server.setPort(port);
        server.setKeyPairProvider(session -> List.of(hostKey));
        server.setPasswordAuthenticator((user, pw, session) -> {
            logins.add(user);
            String expected = password;
            return expected != null && expected.equals(pw);
        });
        server.setKeyboardInteractiveAuthenticator(null);
        server.setPublickeyAuthenticator((user, key, session) -> {
            logins.add(user);
            return isAuthorized(key);
        });
        server.setCommandFactory((channel, command) -> new Scripted(command));
        // SMTP probes go through "direct-tcpip"; tests point them at a FakeSmtpServer on 127.0.0.1.
        server.setForwardingFilter(org.apache.sshd.server.forward.AcceptAllForwardingFilter.INSTANCE);
        try {
            server.start();
        } catch (IOException e) {
            throw new IllegalStateException("fake SSH server did not start", e);
        }
    }

    public int port() {
        return server.getPort();
    }

    /** A new random host key (as after a reinstall); returns its fingerprint. */
    public synchronized String newHostKey() {
        try {
            hostKey = KeyUtils.generateKeyPair("ssh-ed25519", 256);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
        return fingerprint();
    }

    public String fingerprint() {
        return KeyUtils.getFingerPrint(hostKey.getPublic());
    }

    /** Lets this public key ("ssh-ed25519 AAAA... comment") log in. */
    public void authorize(String openSshLine) {
        authorized.add(keyPart(openSshLine));
    }

    /** Also accepts every key listed in this file (re-read at each login), like ~/.ssh/authorized_keys. */
    public void authorizedKeysFile(Path file) {
        this.authorizedKeysFile = file;
    }

    /** Answers commands whose line or stdin contains {@code marker}. Later rules for the same marker win. */
    public FakeSshServer on(String marker, int exit, String output) {
        return on(marker, new Reply(exit, output, null));
    }

    public FakeSshServer on(String marker, Reply reply) {
        rules.addFirst(new Rule(e -> e.has(marker), reply));
        return this;
    }

    /** Also accepts this password (any user); null = passwords refused. */
    public void password(String value) {
        this.password = value;
    }

    /** Runs {@code action} when a command with this marker arrives (e.g. "the key was added"). */
    public FakeSshServer whenRun(String marker, Runnable action) {
        effects.add(new Rule(e -> e.has(marker), new Reply(0, "", null)));
        effectActions.add(action);
        return this;
    }

    private final List<Runnable> effectActions = new CopyOnWriteArrayList<>();

    public List<Exchange> exchanges() {
        return List.copyOf(exchanges);
    }

    /** User names that tried to log in (any key, accepted or not). */
    public List<String> logins() {
        return List.copyOf(logins);
    }

    public void reset() {
        exchanges.clear();
        logins.clear();
        rules.clear();
        effects.clear();
        effectActions.clear();
        password = null;
        authorized.clear();
        newHostKey();
    }

    @Override
    public void close() throws IOException {
        server.stop(true);
    }

    private boolean isAuthorized(PublicKey key) {
        String line = PublicKeyEntry.toString(key);
        if (authorized.contains(keyPart(line))) {
            return true;
        }
        Path file = authorizedKeysFile;
        if (file != null && Files.exists(file)) {
            try {
                for (String l : Files.readAllLines(file, StandardCharsets.UTF_8)) {
                    if (!l.isBlank() && keyPart(l).equals(keyPart(line))) {
                        return true;
                    }
                }
            } catch (IOException ignored) {
                return false;
            }
        }
        return false;
    }

    /** "type base64" without a comment. */
    private static String keyPart(String line) {
        String[] p = line.trim().split("\\s+");
        return p.length >= 2 ? p[0] + " " + p[1] : line.trim();
    }

    private final class Scripted extends AbstractCommandSupport {
        Scripted(String command) {
            super(command, null);
        }

        @Override
        public void run() {
            int exit = 0;
            try {
                String stdin = new String(getInputStream().readAllBytes(), StandardCharsets.UTF_8);
                Exchange e = new Exchange(getServerSession().getUsername(), getCommand(), stdin);
                exchanges.add(e);
                for (int i = 0; i < effects.size(); i++) {
                    if (effects.get(i).when().test(e)) {
                        effectActions.get(i).run();
                    }
                }
                Reply reply = new Reply(0, "", null);
                for (Rule r : new ArrayList<>(rules)) {
                    if (r.when().test(e)) {
                        reply = r.reply();
                        break;
                    }
                }
                if (reply.gate() != null) {
                    reply.gate().await(30, TimeUnit.SECONDS);
                }
                OutputStream out = getOutputStream();
                out.write(reply.output().getBytes(StandardCharsets.UTF_8));
                out.flush();
                exit = reply.exit();
            } catch (IOException | InterruptedException ex) {
                exit = 255;
            }
            onExit(exit);
        }
    }
}
