package ca.nordencapital.masterdb.mail;

/**
 * Sends an email. Implementations never throw: a failed send is logged (the
 * caller's action, e.g. creating an invite, still succeeds and can be resent).
 *
 * @return true when the provider accepted the message
 */
public interface MailSender {

    boolean send(MailMessage message, String linkForLog);
}
