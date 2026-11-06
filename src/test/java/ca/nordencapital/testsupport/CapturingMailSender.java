package ca.nordencapital.testsupport;

import ca.nordencapital.masterdb.mail.MailMessage;
import ca.nordencapital.masterdb.mail.MailSender;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Keeps every email instead of sending it, so tests can follow the links. Import {@link Config}. */
public class CapturingMailSender implements MailSender {

    private static final Pattern TOKEN = Pattern.compile("#([A-Za-z0-9_-]{43})");

    private final List<MailMessage> sent = new CopyOnWriteArrayList<>();

    @Override
    public boolean send(MailMessage message, String linkForLog) {
        sent.add(message);
        return true;
    }

    public List<MailMessage> sent() {
        return sent;
    }

    public void clear() {
        sent.clear();
    }

    public MailMessage last() {
        return sent.getLast();
    }

    /** The token in the last email's link. */
    public String lastToken() {
        Matcher m = TOKEN.matcher(last().text());
        if (!m.find()) {
            throw new AssertionError("no link in the last email");
        }
        return m.group(1);
    }

    @TestConfiguration(proxyBeanMethods = false)
    public static class Config {
        @Bean
        @Primary
        CapturingMailSender capturingMailSender() {
            return new CapturingMailSender();
        }
    }
}
