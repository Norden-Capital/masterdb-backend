package ca.nordencapital.masterdb.mail;

import ca.nordencapital.masterdb.auth.user.Emails;

/**
 * One email. {@code text} and {@code html} carry the same content.
 * {@link #toString()} never shows the body (it holds one-time links).
 */
public record MailMessage(String to, String subject, String text, String html) {

    @Override
    public String toString() {
        return "MailMessage[to=" + Emails.mask(to) + ", subject=" + subject + "]";
    }
}
