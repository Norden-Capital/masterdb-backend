package ca.nordencapital.masterdb.mail;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Locale;

/**
 * The account emails (invite, password reset): plain, clean HTML with a
 * text twin, no images or tracking. Links point at the website
 * ({@code app.frontend-url}) and carry the token after {@code #}, so it is
 * never sent to a server or written to an access log.
 */
@Component
public class AccountMails {

    static final DateTimeFormatter WHEN = DateTimeFormatter.ofPattern("MMMM d, yyyy 'at' h:mm a z", Locale.ENGLISH)
            .withZone(ZoneId.of("America/Toronto"));

    private final MailSender sender;
    private final String frontendUrl;

    public AccountMails(MailSender sender, @Value("${app.frontend-url}") String frontendUrl) {
        this.sender = sender;
        this.frontendUrl = frontendUrl.replaceAll("/+$", "");
    }

    public String inviteLink(String token) {
        return frontendUrl + "/accept-invite#" + token;
    }

    public String resetLink(String token) {
        return frontendUrl + "/reset-password#" + token;
    }

    public boolean sendInvite(String to, String name, String inviterName, String token, Instant expiresAt) {
        String link = inviteLink(token);
        String greeting = name == null || name.isBlank() ? "Hello," : "Hello " + name + ",";
        String intro = inviterName + " invited you to MasterDB, Norden Capital's contact database.";
        String expiry = "The link works once and expires on " + WHEN.format(expiresAt) + ".";
        String text = greeting + "\n\n" + intro + "\n\nSet your password and two-factor sign-in here:\n" + link
                + "\n\n" + expiry + "\nIf you did not expect this email, you can ignore it.\n\n— MasterDB\n";
        String html = page("You are invited to MasterDB", greeting, intro, "Accept the invitation", link,
                expiry + " You will set a password and two-factor sign-in.",
                "If you did not expect this email, you can ignore it.");
        return sender.send(new MailMessage(to, "You are invited to MasterDB", text, html), link);
    }

    public boolean sendPasswordReset(String to, String name, String token, Instant expiresAt, Instant now) {
        String link = resetLink(token);
        long minutes = Math.max(1, Duration.between(now, expiresAt).toMinutes());
        String greeting = name == null || name.isBlank() ? "Hello," : "Hello " + name + ",";
        String intro = "Someone asked to reset the password of your MasterDB account.";
        String expiry = "The link works once and expires in " + minutes + " minutes. Resetting signs you out "
                + "everywhere.";
        String text = greeting + "\n\n" + intro + "\n\nChoose a new password here:\n" + link + "\n\n" + expiry
                + "\nIf it was not you, ignore this email: your password stays as it is.\n\n— MasterDB\n";
        String html = page("Reset your MasterDB password", greeting, intro, "Choose a new password", link, expiry,
                "If it was not you, ignore this email: your password stays as it is.");
        return sender.send(new MailMessage(to, "Reset your MasterDB password", text, html), link);
    }

    private static String page(String title, String greeting, String intro, String button, String link,
            String note, String footer) {
        return """
                <!doctype html>
                <html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
                <title>%s</title></head>
                <body style="margin:0;padding:0;background:#f4f5f7;font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;color:#1f2933;">
                <table role="presentation" width="100%%" cellpadding="0" cellspacing="0" style="background:#f4f5f7;padding:32px 16px;">
                <tr><td align="center">
                <table role="presentation" width="100%%" cellpadding="0" cellspacing="0" style="max-width:520px;background:#ffffff;border:1px solid #e4e7eb;border-radius:8px;">
                <tr><td style="padding:28px 32px 8px;font-size:13px;font-weight:600;letter-spacing:.04em;color:#52606d;">MASTERDB · NORDEN CAPITAL</td></tr>
                <tr><td style="padding:8px 32px 0;font-size:20px;font-weight:600;line-height:1.3;">%s</td></tr>
                <tr><td style="padding:16px 32px 0;font-size:15px;line-height:1.6;">%s<br><br>%s</td></tr>
                <tr><td style="padding:24px 32px;"><a href="%s" style="display:inline-block;background:#1f2933;color:#ffffff;text-decoration:none;font-size:15px;font-weight:600;padding:12px 20px;border-radius:6px;">%s</a></td></tr>
                <tr><td style="padding:0 32px;font-size:13px;line-height:1.6;color:#52606d;">%s<br><br>Button not working? Paste this link into your browser:<br><span style="word-break:break-all;color:#1f2933;">%s</span></td></tr>
                <tr><td style="padding:24px 32px 28px;font-size:12px;line-height:1.6;color:#7b8794;border-top:1px solid #e4e7eb;margin-top:24px;">%s</td></tr>
                </table></td></tr></table></body></html>
                """.formatted(esc(title), esc(title), esc(greeting), esc(intro), esc(link), esc(button), esc(note),
                esc(link), esc(footer));
    }

    static String esc(String value) {
        return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
                .replace("'", "&#39;");
    }
}
