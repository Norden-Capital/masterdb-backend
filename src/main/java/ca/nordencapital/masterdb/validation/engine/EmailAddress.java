package ca.nordencapital.masterdb.validation.engine;

import java.net.IDN;
import java.util.Locale;
import java.util.Optional;
import java.util.regex.Pattern;

/**
 * Syntax of an email address, as the old app checked it (ASCII local part,
 * no dots at the ends or doubled, a real domain name with a letters-only TLD).
 * The domain is lowercased and turned into its ASCII (punycode) form; the
 * local part is kept as typed, since a few providers treat its case as part
 * of the name.
 */
public record EmailAddress(String local, String domain) {

    private static final Pattern LOCAL = Pattern.compile("[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+");
    private static final Pattern DOMAIN = Pattern.compile("(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z]{2,63}");

    public String address() {
        return local + "@" + domain;
    }

    /** The address, or empty if it isn't one. Surrounding spaces and {@code <>} are ignored. */
    public static Optional<EmailAddress> parse(String raw) {
        if (raw == null) {
            return Optional.empty();
        }
        String email = raw.trim();
        if (email.startsWith("<") && email.endsWith(">")) {
            email = email.substring(1, email.length() - 1).trim();
        }
        if (email.isEmpty() || email.length() > 254) {
            return Optional.empty();
        }
        int at = email.lastIndexOf('@');
        if (at < 1 || at != email.indexOf('@') || at > 64) {
            return Optional.empty();
        }
        String local = email.substring(0, at);
        if (local.startsWith(".") || local.endsWith(".") || local.contains("..") || !LOCAL.matcher(local).matches()) {
            return Optional.empty();
        }
        String domain;
        try {
            domain = IDN.toASCII(email.substring(at + 1).toLowerCase(Locale.ROOT));
        } catch (IllegalArgumentException e) {
            return Optional.empty();
        }
        if (domain.length() > 253 || !DOMAIN.matcher(domain).matches()) {
            return Optional.empty();
        }
        return Optional.of(new EmailAddress(local, domain));
    }

    /** Lowercased whole address: how bulk jobs spot duplicates. */
    public String normalized() {
        return address().toLowerCase(Locale.ROOT);
    }
}
