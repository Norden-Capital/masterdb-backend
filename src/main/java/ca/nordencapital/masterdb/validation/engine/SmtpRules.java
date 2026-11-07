package ca.nordencapital.masterdb.validation.engine;

import ca.nordencapital.masterdb.validation.Category;

import java.util.Locale;
import java.util.regex.Pattern;

/**
 * What an SMTP reply means. Ported from the old app's {@code SmtpValidator}
 * (same words, same codes) plus the fixes agreed on 2026-11-07:
 * <ul>
 *   <li>Gmail {@code 5.2.1} "account ... disabled" on the target = the mailbox is gone (bounce);</li>
 *   <li>Microsoft {@code 550 5.5.0 ... (S2017062302)} on the target = no such mailbox (bounce), as the
 *       old app already read it for the made-up control addresses;</li>
 *   <li>a clear answer from the first mail server is final (see {@link SmtpProber}), so Gmail is
 *       no longer "unknown" for having more than three MX hosts.</li>
 * </ul>
 * {@code message} is the reply's text, every line joined (codes included).
 */
public final class SmtpRules {

    private static final Pattern MISSING = Pattern.compile(".*\\b5\\.1\\.(?:1|10)\\b.*");
    private static final Pattern GMAIL_DISABLED = Pattern.compile(".*\\b5\\.2\\.1\\b.*");
    private static final Pattern FULL = Pattern.compile(".*\\b[45]\\.2\\.2\\b.*");
    private static final Pattern POLICY_4 = Pattern.compile(".*\\b4\\.7\\.[0-9]+\\b.*");
    private static final Pattern POLICY_5 = Pattern.compile(".*\\b5\\.7\\.[0-9]+\\b.*");

    private SmtpRules() {
    }

    /** The mailbox doesn't exist. {@code mx} is the mail server that answered. */
    public static boolean mailboxMissing(int code, String message, String mx) {
        if (code < 500 || code > 599) {
            return false;
        }
        String lower = lower(message);
        if (MISSING.matcher(lower).matches() || lower.contains("user unknown") || lower.contains("no such user")
                || lower.contains("unknown recipient") || lower.contains("no such mailbox")
                || lower.contains("recipient does not exist") || lower.contains("mailbox does not exist")) {
            return true;
        }
        if (GMAIL_DISABLED.matcher(lower).matches() && lower.contains("disabled")) {
            return true;
        }
        return microsoftMissing(code, lower, mx);
    }

    /** Microsoft's answer for an address it has no mailbox for. */
    static boolean microsoftMissing(int code, String lower, String mx) {
        return code == 550 && lower(mx).endsWith(".protection.outlook.com") && lower.contains("5.5.0")
                && lower.contains("s2017062302");
    }

    /** The mailbox exists but is full. */
    public static boolean mailboxFull(int code, String message) {
        if (code < 400 || code > 599) {
            return false;
        }
        String lower = lower(message);
        return FULL.matcher(lower).matches() || lower.contains("mailbox full") || lower.contains("mailbox is full")
                || lower.contains("over quota") || lower.contains("quota exceeded") || lower.contains("mailbox quota");
    }

    /** The provider asks us to slow down (or greylists): a cooldown, and the address stays unknown. */
    public static boolean rateLimited(int code, String message) {
        String lower = lower(message);
        return code == 421 || lower.contains("rate limit") || lower.contains("too many")
                || lower.contains("throttl") || lower.contains("try again later")
                || lower.contains("temporarily deferred") || lower.contains("greylist")
                || lower.contains("temporarily blocked")
                || (code >= 400 && code < 500 && POLICY_4.matcher(lower).matches());
    }

    /** The provider blocks this server (blocklist, reputation): a long cooldown. */
    public static boolean providerBlocked(int code, String message) {
        if (code < 500 || code > 599) {
            return false;
        }
        String lower = lower(message);
        return lower.contains("blacklist") || lower.contains("blocklist") || lower.contains("ip blocked")
                || lower.contains("poor reputation") || lower.contains("sender reputation");
    }

    /** A refusal: bounce, soft bounce, reject or unknown. */
    public static Category refusal(int code, String message, String mx) {
        if (mailboxMissing(code, message, mx)) {
            return Category.BOUNCE;
        }
        if (mailboxFull(code, message)) {
            return Category.SOFT_BOUNCE;
        }
        if (rateLimited(code, message) || code < 500 || code > 599) {
            return Category.UNKNOWN;
        }
        String lower = lower(message);
        if (POLICY_5.matcher(lower).matches() || lower.contains("policy") || lower.contains("blocked")
                || lower.contains("blacklist") || lower.contains("blocklist") || lower.contains("spam")
                || lower.contains("reputation") || lower.contains("not authorized") || lower.contains("access denied")) {
            return Category.REJECT;
        }
        return Category.UNKNOWN;
    }

    /** A made-up control address was refused as "no such mailbox". */
    public static boolean controlRejected(int code, String message, String mx) {
        return mailboxMissing(code, message, mx);
    }

    /** Result of the two made-up control addresses. */
    public enum Control { CATCH_ALL, NOT_CATCH_ALL, UNKNOWN }

    public static Control control(int firstCode, String firstMessage, int secondCode, String secondMessage,
            String mx) {
        if (firstCode == 250 && secondCode == 250) {
            return Control.CATCH_ALL;
        }
        if (controlRejected(firstCode, firstMessage, mx) && controlRejected(secondCode, secondMessage, mx)) {
            return Control.NOT_CATCH_ALL;
        }
        return Control.UNKNOWN;
    }

    private static String lower(String v) {
        return v == null ? "" : v.toLowerCase(Locale.ROOT);
    }
}
