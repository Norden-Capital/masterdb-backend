package ca.nordencapital.masterdb.dns.domain;

import java.net.IDN;
import java.util.Locale;
import java.util.regex.Pattern;

/**
 * Domain name rules. Stored form: trimmed, lowercase ASCII (punycode for
 * international names), without a trailing dot. Same syntax check as the old
 * app: labels of letters, digits and inner dashes, a TLD of 2 to 63 letters
 * (or a punycode TLD).
 */
public final class DomainNames {

    public static final int MAX_LENGTH = 253;
    private static final Pattern NAME = Pattern.compile(
            "^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})$");

    private DomainNames() {
    }

    /** The stored form, or null when the input is not a domain name. */
    public static String normalize(String input) {
        if (input == null) {
            return null;
        }
        String v = input.trim().toLowerCase(Locale.ROOT);
        if (v.endsWith(".")) {
            v = v.substring(0, v.length() - 1);
        }
        if (v.isEmpty() || v.contains("/") || v.contains(":") || v.contains("@") || v.contains(" ")) {
            return null;
        }
        try {
            v = IDN.toASCII(v, IDN.USE_STD3_ASCII_RULES).toLowerCase(Locale.ROOT);
        } catch (IllegalArgumentException e) {
            return null;
        }
        return v.length() <= MAX_LENGTH && NAME.matcher(v).matches() ? v : null;
    }

    /** Namecheap's SLD and TLD: split at the first dot ("example" + "co.uk"). */
    public static String[] sldTld(String name) {
        int dot = name.indexOf('.');
        return new String[] {name.substring(0, dot), name.substring(dot + 1)};
    }
}
