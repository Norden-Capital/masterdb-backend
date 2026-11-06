package ca.nordencapital.masterdb.auth.user;

import java.util.Locale;
import java.util.regex.Pattern;

/** Email helpers for accounts: one stored form, one masked form for logs. */
public final class Emails {

    /** The longest address SMTP can carry (and the column's length). */
    public static final int MAX_LENGTH = 254;

    // Deliberately simple: one @, something on each side, a dot in the domain,
    // no spaces. Real proof that an address works is the invite email.
    private static final Pattern FORMAT = Pattern.compile("^[^@\\s]+@[^@\\s]+\\.[^@\\s.]+$");

    private Emails() {
    }

    /** The stored form: trimmed and lowercased, so Jane@X.com and jane@x.com are one account. */
    public static String normalize(String email) {
        return email == null ? null : email.trim().toLowerCase(Locale.ROOT);
    }

    /** True for a plausible address, already normalised or not. */
    public static boolean isValid(String email) {
        String value = normalize(email);
        return value != null && value.length() <= MAX_LENGTH && FORMAT.matcher(value).matches();
    }

    /**
     * For logs: {@code jane@nordencapital.ca} → {@code j***@nordencapital.ca}.
     * Enough to recognise whose account it is, not enough to harvest addresses
     * from a log file. Anything that is not an address is masked entirely.
     */
    public static String mask(String email) {
        String value = normalize(email);
        if (value == null) {
            return "***";
        }
        int at = value.lastIndexOf('@');
        if (at < 1 || at == value.length() - 1) {
            return "***";
        }
        return value.charAt(0) + "***" + value.substring(at);
    }
}
