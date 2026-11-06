package ca.nordencapital.masterdb.mail;

import ca.nordencapital.masterdb.auth.user.Emails;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Does not send: writes one log line instead. Used in the {@code local}
 * profile and the tests, and in production when no provider key is set.
 *
 * <p>The one-time link is printed in full only when {@code showLinks} is on
 * (the {@code local} profile, so a developer can click it); everywhere else
 * its token is masked, so a log file never holds a working link.
 */
public class LogMailSender implements MailSender {

    private static final Logger log = LoggerFactory.getLogger(LogMailSender.class);

    private final boolean showLinks;
    private final String reason;

    public LogMailSender(boolean showLinks, String reason) {
        this.showLinks = showLinks;
        this.reason = reason;
    }

    @Override
    public boolean send(MailMessage message, String linkForLog) {
        String link = linkForLog == null ? "-" : showLinks ? linkForLog : maskLink(linkForLog);
        log.info("email not sent ({}): to={} subject=\"{}\" link={}", reason, Emails.mask(message.to()),
                message.subject(), link);
        return false;
    }

    /** {@code https://x/invite#abcdef...} → {@code https://x/invite#abcd…} */
    static String maskLink(String link) {
        int hash = link.indexOf('#');
        if (hash < 0) {
            return link;
        }
        String token = link.substring(hash + 1);
        return link.substring(0, hash + 1) + (token.length() <= 4 ? "…" : token.substring(0, 4) + "…");
    }
}
