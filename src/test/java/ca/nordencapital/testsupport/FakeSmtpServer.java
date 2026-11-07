package ca.nordencapital.testsupport;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * A mail server on 127.0.0.1 for tests: answers the SMTP conversation of a
 * check with scripted replies, never stores or relays anything. Tests reach it
 * through the fake SSH server's direct-tcpip, the way a real check leaves a VPS.
 *
 * <ul>
 *   <li>{@link #recipient} sets the RCPT TO answer for one address (any text, multi-line with
 *       {@code \n}); any other address (the made-up catch-all controls) gets {@link #others}.</li>
 *   <li>{@code "STALL"} as an answer never replies (a timeout).</li>
 *   <li>Every command received is recorded.</li>
 * </ul>
 */
public final class FakeSmtpServer implements AutoCloseable {

    /** The one the flow tests share (same Spring context for all of them). */
    public static final FakeSmtpServer SHARED = new FakeSmtpServer();

    /** Points app.validation.smtp-port at {@link #SHARED}; call from a {@code @DynamicPropertySource}. */
    public static void register(org.springframework.test.context.DynamicPropertyRegistry registry) {
        registry.add("app.validation.smtp-port", SHARED::port);
    }

    private final ServerSocket socket;
    private final Map<String, String> recipients = new ConcurrentHashMap<>();
    private final List<String> commands = new CopyOnWriteArrayList<>();
    private volatile String greeting = "220 mx.fake ESMTP";
    private volatile String mailFrom = "250 2.1.0 Ok";
    private volatile String others = "550 5.1.1 <x>: Recipient address rejected: User unknown";
    private volatile int connections;

    public FakeSmtpServer() {
        try {
            socket = new ServerSocket(0, 50, InetAddress.getByName("127.0.0.1"));
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
        Thread t = new Thread(this::accept, "fake-smtp");
        t.setDaemon(true);
        t.start();
    }

    public int port() {
        return socket.getLocalPort();
    }

    public FakeSmtpServer recipient(String address, String reply) {
        recipients.put(address.toLowerCase(Locale.ROOT), reply);
        return this;
    }

    public FakeSmtpServer others(String reply) {
        this.others = reply;
        return this;
    }

    public FakeSmtpServer greeting(String reply) {
        this.greeting = reply;
        return this;
    }

    public FakeSmtpServer mailFrom(String reply) {
        this.mailFrom = reply;
        return this;
    }

    public List<String> commands() {
        return List.copyOf(commands);
    }

    public int connections() {
        return connections;
    }

    public void reset() {
        recipients.clear();
        commands.clear();
        connections = 0;
        greeting = "220 mx.fake ESMTP";
        mailFrom = "250 2.1.0 Ok";
        others = "550 5.1.1 <x>: Recipient address rejected: User unknown";
    }

    @Override
    public void close() throws IOException {
        socket.close();
    }

    private void accept() {
        while (!socket.isClosed()) {
            try {
                Socket s = socket.accept();
                connections++;
                Thread t = new Thread(() -> serve(s), "fake-smtp-conn");
                t.setDaemon(true);
                t.start();
            } catch (IOException e) {
                return;
            }
        }
    }

    private void serve(Socket s) {
        try (s) {
            BufferedReader in = new BufferedReader(new InputStreamReader(s.getInputStream(), StandardCharsets.US_ASCII));
            OutputStream out = s.getOutputStream();
            if (!send(out, greeting) || !greeting.startsWith("220")) {
                return;
            }
            String line;
            while ((line = in.readLine()) != null) {
                commands.add(line);
                String upper = line.toUpperCase(Locale.ROOT);
                String answer;
                if (upper.startsWith("EHLO") || upper.startsWith("HELO")) {
                    answer = "250-mx.fake\n250 PIPELINING";
                } else if (upper.startsWith("MAIL FROM")) {
                    answer = mailFrom;
                } else if (upper.startsWith("RCPT TO:<")) {
                    String rcpt = line.substring(9, line.indexOf('>') < 0 ? line.length() : line.indexOf('>'))
                            .toLowerCase(Locale.ROOT);
                    answer = recipients.getOrDefault(rcpt, others);
                } else if (upper.startsWith("RSET")) {
                    answer = "250 2.0.0 Ok";
                } else if (upper.startsWith("QUIT")) {
                    send(out, "221 2.0.0 Bye");
                    return;
                } else {
                    answer = "502 5.5.2 Command not recognized";
                }
                if (!send(out, answer)) {
                    return;
                }
            }
        } catch (IOException ignored) {
            // the client went away
        }
    }

    /** False = "STALL": say nothing and let the client time out. */
    private static boolean send(OutputStream out, String reply) throws IOException {
        if (reply.equals("STALL")) {
            try {
                Thread.sleep(30_000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            return false;
        }
        out.write((reply.replace("\n", "\r\n") + "\r\n").getBytes(StandardCharsets.US_ASCII));
        out.flush();
        return true;
    }
}
