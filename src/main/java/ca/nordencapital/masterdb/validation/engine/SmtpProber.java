package ca.nordencapital.masterdb.validation.engine;

import ca.nordencapital.masterdb.servers.ssh.SshRunner.Stream;
import ca.nordencapital.masterdb.servers.ssh.SshRunner.Tunnel;
import ca.nordencapital.masterdb.validation.Category;
import ca.nordencapital.masterdb.validation.engine.MxResolver.Destinations;
import ca.nordencapital.masterdb.validation.engine.MxResolver.Host;
import ca.nordencapital.masterdb.validation.engine.SmtpRules.Control;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The SMTP check of one address, through an SSH tunnel so it leaves from the
 * validation server's IP: greeting, {@code EHLO <helo host>}, {@code MAIL
 * FROM:<server's address>}, {@code RCPT TO:<address>}, then (when accepted)
 * two made-up addresses at the same domain to tell a real "yes" from a domain
 * that accepts everything. No message is ever sent: the conversation stops
 * before DATA, with QUIT.
 *
 * <p>Mail servers are tried in MX order. A clear answer about the address
 * (accepted, no such mailbox, full, policy refusal, slow down) is final; only
 * a server that can't be reached or gives a temporary answer moves on to the
 * next one, up to {@link MxResolver#MAX_HOSTS}.
 */
@Component
public class SmtpProber {

    static final int MAX_TRANSCRIPT = 60;
    private static final Duration CONTROL_TTL = Duration.ofMinutes(15);
    private static final String ALNUM = "abcdefghijklmnopqrstuvwxyz0123456789";

    private final MxResolver mx;
    private final Clock clock;
    private final int port;
    private final Duration timeout;
    private final SecureRandom random = new SecureRandom();
    private final Map<String, Evidence> controls = new LinkedHashMap<>(256, .75f, true) {
        @Override
        protected boolean removeEldestEntry(Map.Entry<String, Evidence> eldest) {
            return size() > 4096;
        }
    };

    public SmtpProber(MxResolver mx, Clock clock, @Value("${app.validation.smtp-port:25}") int port,
            @Value("${app.validation.smtp-timeout:20s}") Duration timeout) {
        this.mx = mx;
        this.clock = clock;
        this.port = port;
        this.timeout = timeout;
    }

    /** The server's greeting name and sender address (its probe identity). */
    public record Identity(String heloHost, String mailFrom) {
    }

    /**
     * The answer. {@code reason} is for people; {@code reply} is the provider's
     * own words (cleaned, cut); {@code mx} the mail server that answered (or the
     * first one). {@code rateLimited} / {@code blocked} drive the pacing.
     */
    public record Verdict(Category category, int code, String mx, String reason, String reply,
            List<String> transcript, boolean rateLimited, boolean blocked) {
    }

    private record Evidence(Control state, Instant at) {
    }

    private record Reply(int code, String text) {
    }

    /** Drops every remembered catch-all result and MX answer (tests). */
    public void forget() {
        synchronized (controls) {
            controls.clear();
        }
        mx.forget();
    }

    /** Where a check would go: the domain's mail servers (for pacing, before the check). */
    public Destinations destinations(EmailAddress email) {
        return mx.resolve(email.domain());
    }

    public Verdict verify(Tunnel tunnel, Identity identity, EmailAddress email) {
        Destinations dest = mx.resolve(email.domain());
        List<String> transcript = new ArrayList<>();
        if (dest.nullMx()) {
            return new Verdict(Category.BOUNCE, 0, "", "The domain accepts no mail at all (it publishes a "
                    + "\"null MX\").", "", transcript, false, false);
        }
        if (dest.problem() != null) {
            return new Verdict(Category.UNKNOWN, 0, dest.primary(email.domain()), dest.problem(), "", transcript,
                    false, false);
        }
        Verdict lastUnknown = null;
        Verdict lastReject = null;
        for (Host host : dest.hosts()) {
            if (!host.ready()) {
                lastUnknown = new Verdict(Category.UNKNOWN, 0, host.name(), "Mail server " + host.name() + ": "
                        + host.problem() + ".", "", transcript, false, false);
                continue;
            }
            Attempt a = probe(tunnel, identity, email, host, transcript);
            if (a.isFinal()) {
                return a.verdict();
            }
            if (a.verdict().category() == Category.REJECT) {
                lastReject = a.verdict();
            } else {
                lastUnknown = a.verdict();
            }
        }
        if (lastUnknown != null) {
            return lastUnknown;
        }
        if (lastReject != null) {
            return lastReject;
        }
        return new Verdict(Category.UNKNOWN, 0, dest.primary(email.domain()), "No mail server answered.", "",
                transcript, false, false);
    }

    /** One mail server's answer; {@code isFinal} = no need to ask the next one. */
    private record Attempt(Verdict verdict, boolean isFinal) {
    }

    private Attempt probe(Tunnel tunnel, Identity id, EmailAddress email, Host host, List<String> t) {
        String mxName = host.name();
        note(t, "-- " + mxName + " (" + host.ip() + ")");
        Stream stream;
        try {
            stream = tunnel.connect(host.ip(), port, timeout);
        } catch (IOException e) {
            note(t, "!! no connection");
            return new Attempt(new Verdict(Category.UNKNOWN, 0, mxName, "The validation server couldn't connect "
                    + "to mail server " + mxName + " on port 25.", "", t, false, false), false);
        }
        try (stream) {
            BufferedReader in = new BufferedReader(new InputStreamReader(stream.in(), StandardCharsets.ISO_8859_1));
            OutputStream out = stream.out();
            Reply greeting = reply(in, t);
            if (greeting.code() != 220) {
                return early(greeting, mxName, "The mail server refused the connection", t);
            }
            Reply hello = command(out, in, "EHLO " + id.heloHost(), t);
            if (hello.code() >= 500) {
                hello = command(out, in, "HELO " + id.heloHost(), t);
            }
            if (hello.code() != 250) {
                return early(hello, mxName, "The mail server refused our greeting", t);
            }
            Reply sender = command(out, in, "MAIL FROM:<" + id.mailFrom() + ">", t);
            if (sender.code() != 250) {
                return early(sender, mxName, "The mail server refused our sender address", t);
            }
            Reply rcpt = command(out, in, "RCPT TO:<" + email.address() + ">", t);
            Attempt answer = recipient(rcpt, mxName, t);
            if (answer != null) {
                quit(out);
                return answer;
            }
            Control control = control(out, in, id.mailFrom(), email.domain(), host, t);
            quit(out);
            return switch (control) {
                case CATCH_ALL -> new Attempt(new Verdict(Category.CATCH_ALL, rcpt.code(), mxName, "The domain "
                        + "accepts any address (two made-up addresses were accepted too), so this one can't be "
                        + "proven.", clean(rcpt.text()), t, false, false), true);
                case NOT_CATCH_ALL -> new Attempt(new Verdict(Category.VALID, rcpt.code(), mxName, "The mail "
                        + "server accepted this address and refused two made-up ones at the same domain.",
                        clean(rcpt.text()), t, false, false), true);
                case UNKNOWN -> new Attempt(new Verdict(Category.UNKNOWN, rcpt.code(), mxName, "The address was "
                        + "accepted, but the catch-all check (two made-up addresses) gave no clear answer.",
                        clean(rcpt.text()), t, false, false), true);
            };
        } catch (IOException e) {
            note(t, "!! " + (e.getMessage() == null ? "connection lost" : clean(e.getMessage())));
            return new Attempt(new Verdict(Category.UNKNOWN, 0, mxName, "The conversation with mail server "
                    + mxName + " broke off or timed out.", "", t, false, false), false);
        }
    }

    /** The answer to RCPT TO for the real address; null = accepted (go on to the catch-all check). */
    private static Attempt recipient(Reply rcpt, String mxName, List<String> t) {
        int code = rcpt.code();
        String text = rcpt.text();
        if (code == 250 || code == 251) {
            return null;
        }
        boolean limited = SmtpRules.rateLimited(code, text);
        boolean blocked = SmtpRules.providerBlocked(code, text);
        Category c = SmtpRules.refusal(code, text, mxName);
        String reason = switch (c) {
            case BOUNCE -> "The mailbox doesn't exist.";
            case SOFT_BOUNCE -> "The mailbox exists but is full.";
            case REJECT -> blocked ? "The provider refused because it blocks this validation server (blocklist or "
                    + "reputation)." : "The provider refused the address by policy.";
            default -> limited ? "The provider asked to slow down (rate limit or greylisting). Retry later."
                    : "The provider gave a temporary or unclear answer.";
        };
        boolean isFinal = c != Category.UNKNOWN || limited || blocked;
        return new Attempt(new Verdict(c, code, mxName, reason, clean(text), t, limited, blocked), isFinal);
    }

    /** A refusal before the address was even asked: never a bounce. */
    private static Attempt early(Reply r, String mxName, String what, List<String> t) {
        boolean limited = SmtpRules.rateLimited(r.code(), r.text());
        boolean blocked = SmtpRules.providerBlocked(r.code(), r.text());
        Category c = SmtpRules.refusal(r.code(), r.text(), mxName);
        if (c == Category.BOUNCE || c == Category.SOFT_BOUNCE) {
            c = Category.UNKNOWN;
        }
        String reason = what + (limited ? " and asked to slow down (rate limit). Retry later."
                : blocked ? ": it blocks this validation server (blocklist or reputation)."
                : c == Category.REJECT ? " by policy." : ".");
        return new Attempt(new Verdict(c, r.code(), mxName, reason, clean(r.text()), t, limited, blocked),
                limited || blocked);
    }

    private Control control(OutputStream out, BufferedReader in, String mailFrom, String domain, Host host,
            List<String> t) throws IOException {
        String key = host.ip() + "/" + domain;
        Instant now = clock.instant();
        synchronized (controls) {
            Evidence e = controls.get(key);
            if (e != null && e.at().plus(CONTROL_TTL).isAfter(now)) {
                note(t, "-- catch-all check: " + e.state().name().toLowerCase() + " (remembered from "
                        + e.at() + ")");
                return e.state();
            }
        }
        Reply first = madeUp(out, in, mailFrom, domain, t);
        boolean conclusive = first.code() == 250 || SmtpRules.controlRejected(first.code(), first.text(),
                host.name());
        Reply second = conclusive ? madeUp(out, in, mailFrom, domain, t) : new Reply(0, "skipped");
        Control state = SmtpRules.control(first.code(), first.text(), second.code(), second.text(), host.name());
        if (state != Control.UNKNOWN) {
            synchronized (controls) {
                controls.put(key, new Evidence(state, now));
            }
        }
        return state;
    }

    private Reply madeUp(OutputStream out, BufferedReader in, String mailFrom, String domain, List<String> t)
            throws IOException {
        Reply reset = command(out, in, "RSET", t);
        if (reset.code() != 250) {
            return reset;
        }
        Reply sender = command(out, in, "MAIL FROM:<" + mailFrom + ">", t);
        if (sender.code() != 250) {
            return sender;
        }
        return command(out, in, "RCPT TO:<" + randomLocal() + "@" + domain + ">", t);
    }

    private String randomLocal() {
        StringBuilder b = new StringBuilder(14);
        b.append(ALNUM.charAt(random.nextInt(26)));
        for (int i = 0; i < 13; i++) {
            b.append(ALNUM.charAt(random.nextInt(ALNUM.length())));
        }
        return b.toString();
    }

    private static void quit(OutputStream out) {
        try {
            out.write("QUIT\r\n".getBytes(StandardCharsets.US_ASCII));
            out.flush();
        } catch (IOException ignored) {
            // the answer is already known
        }
    }

    private static Reply command(OutputStream out, BufferedReader in, String text, List<String> t)
            throws IOException {
        note(t, ">> " + text);
        out.write((text + "\r\n").getBytes(StandardCharsets.US_ASCII));
        out.flush();
        return reply(in, t);
    }

    /** One reply, every continuation line joined; anything malformed is an IOException. */
    static Reply reply(BufferedReader in, List<String> t) throws IOException {
        StringBuilder all = new StringBuilder();
        for (int i = 0; i < 30; i++) {
            String line = in.readLine();
            if (line == null) {
                throw new IOException("the mail server closed the connection");
            }
            if (line.length() < 3 || line.length() > 2048 || !line.substring(0, 3).chars().allMatch(Character::isDigit)) {
                throw new IOException("not an SMTP reply");
            }
            note(t, "<< " + line);
            if (!all.isEmpty()) {
                all.append(' ');
            }
            all.append(line);
            if (line.length() < 4 || line.charAt(3) != '-') {
                return new Reply(Integer.parseInt(line.substring(0, 3)), all.toString());
            }
        }
        throw new IOException("SMTP reply too long");
    }

    private static void note(List<String> t, String line) {
        if (t.size() < MAX_TRANSCRIPT) {
            t.add(line.length() > 300 ? line.substring(0, 300) : line);
        }
    }

    static String clean(String v) {
        if (v == null) {
            return "";
        }
        String s = v.replaceAll("[\\r\\n\\t]", " ").replaceAll("[^\\x20-\\x7e]", "?").trim();
        return s.length() > 500 ? s.substring(0, 500) : s;
    }
}
