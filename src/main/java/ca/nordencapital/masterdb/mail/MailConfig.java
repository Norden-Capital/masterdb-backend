package ca.nordencapital.masterdb.mail;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/** Which {@link MailSender} the app uses. */
@Configuration
public class MailConfig {

    @Bean
    MailSender mailSender(@Value("${app.mail.log-links:false}") boolean logLinks) {
        return new LogMailSender(logLinks, "no email provider configured");
    }
}
