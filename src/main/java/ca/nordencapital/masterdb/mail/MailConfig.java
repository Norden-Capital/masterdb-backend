package ca.nordencapital.masterdb.mail;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Which {@link MailSender} the app uses:
 * <ul>
 *   <li>{@code app.mail.enabled=false} (the {@code local} profile, the tests):
 *       never sends, logs instead ({@link LogMailSender}).</li>
 *   <li>enabled and {@code RESEND_API_KEY} set (production): Resend.</li>
 *   <li>enabled but no key: the app still starts; a WARN now and one WARN per
 *       email that is not sent. Invites can be resent once the key is set.</li>
 * </ul>
 */
@Configuration
public class MailConfig {

    private static final Logger log = LoggerFactory.getLogger(MailConfig.class);

    @Bean
    MailSender mailSender(@Value("${app.mail.enabled:true}") boolean enabled,
            @Value("${app.mail.resend.api-key:}") String apiKey,
            @Value("${app.mail.resend.base-url:https://api.resend.com}") String baseUrl,
            @Value("${app.mail.from}") String from,
            @Value("${app.mail.log-links:false}") boolean logLinks) {
        if (!enabled) {
            return new LogMailSender(logLinks, "sending disabled here", false);
        }
        String key = apiKey == null ? "" : apiKey.trim();
        if (key.isEmpty()) {
            log.warn("RESEND_API_KEY is not set: emails (invitations, password resets) will NOT be sent.");
            return new LogMailSender(logLinks, "RESEND_API_KEY not set", true);
        }
        return new ResendMailSender(baseUrl, key, from);
    }
}
