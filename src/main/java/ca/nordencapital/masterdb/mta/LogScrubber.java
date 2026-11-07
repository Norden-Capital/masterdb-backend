package ca.nordencapital.masterdb.mta;

import java.util.Collection;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Cleans remote command output before it is stored or shown. Removes: the
 * exact secret values the job knows (a webmail password), any PEM private
 * key block, and "password=..."-style values. Stateful across lines, so a
 * private key printed over many lines is hidden from its BEGIN line to its
 * END line. One scrubber per job.
 */
public final class LogScrubber {

    static final String HIDDEN = "[hidden]";
    private static final Pattern KEY_BEGIN = Pattern.compile("-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----");
    private static final Pattern KEY_END = Pattern.compile("-----END [A-Z0-9 ]*PRIVATE KEY-----");
    private static final Pattern ASSIGNED = Pattern.compile(
            "(?i)(?<![a-z0-9])(password|passwd|pass|secret|token|api[_-]?key)(\\s*[=:]\\s*)(\"[^\"]*\"|'[^']*'|\\S+)");

    private final Collection<String> secrets;
    private boolean inKey;

    public LogScrubber(Collection<String> secrets) {
        this.secrets = secrets.stream().filter(s -> s != null && s.length() >= 4).toList();
    }

    /** The line to keep, or null to drop it (inside a private key block). */
    public String line(String raw) {
        String v = raw;
        if (inKey) {
            if (KEY_END.matcher(v).find()) {
                inKey = false;
            }
            return null;
        }
        Matcher begin = KEY_BEGIN.matcher(v);
        if (begin.find()) {
            inKey = !KEY_END.matcher(v).find();
            return v.substring(0, begin.start()) + "[private key hidden]";
        }
        for (String s : secrets) {
            v = v.replace(s, HIDDEN);
        }
        return ASSIGNED.matcher(v).replaceAll("$1$2" + HIDDEN);
    }
}
