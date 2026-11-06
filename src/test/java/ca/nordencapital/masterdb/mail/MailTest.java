package ca.nordencapital.masterdb.mail;

import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

/** Resend sender against a local stub, the sender choice, log masking and the templates. */
@ExtendWith(OutputCaptureExtension.class)
class MailTest {

    /** Test values only. */
    static final String KEY = "re_test_key_never_logged_123";
    static final String TOKEN = "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789_-abcde";

    HttpServer server;
    final AtomicReference<String> body = new AtomicReference<>();
    final AtomicReference<String> auth = new AtomicReference<>();
    final AtomicInteger status = new AtomicInteger(200);
    final AtomicReference<String> answer = new AtomicReference<>("{\"id\":\"4ef9a417-02e9-4d39-ad75-9611e0fcc33c\"}");

    @BeforeEach
    void start() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/emails", exchange -> {
            body.set(new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
            auth.set(exchange.getRequestHeaders().getFirst("Authorization"));
            byte[] out = answer.get().getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(status.get(), out.length);
            exchange.getResponseBody().write(out);
            exchange.close();
        });
        server.start();
    }

    @AfterEach
    void stop() {
        server.stop(0);
    }

    String base() {
        return "http://127.0.0.1:" + server.getAddress().getPort();
    }

    AccountMails mails(MailSender sender) {
        return new AccountMails(sender, "https://db.nordencapital.ca/");
    }

    @Test
    void sendsThroughResend(CapturedOutput output) {
        ResendMailSender sender = new ResendMailSender(base(), KEY, "MasterDB <no-reply@nordencapital.ca>");
        boolean sent = mails(sender).sendInvite("jane@example.com", "Jane", "Olivia Owner", TOKEN,
                Instant.parse("2026-11-09T17:00:00Z"));

        assertThat(sent).isTrue();
        assertThat(auth.get()).isEqualTo("Bearer " + KEY);
        assertThat(body.get()).contains("\"from\":\"MasterDB <no-reply@nordencapital.ca>\"",
                "\"to\":[\"jane@example.com\"]", "\"subject\":\"You are invited to MasterDB\"", "\"html\":\"",
                "\"text\":\"", "https://db.nordencapital.ca/accept-invite#" + TOKEN);
        assertThat(output.getAll()).contains("email sent: to=j***@example.com",
                "id=4ef9a417-02e9-4d39-ad75-9611e0fcc33c").doesNotContain(KEY).doesNotContain(TOKEN);
    }

    @Test
    void aRefusalIsOneErrorLineWithoutSecrets(CapturedOutput output) {
        status.set(422);
        answer.set("{\"statusCode\":422,\"name\":\"validation_error\",\"message\":\"Invalid `to`: jane@example.com\"}");
        ResendMailSender sender = new ResendMailSender(base(), KEY, "MasterDB <no-reply@nordencapital.ca>");
        boolean sent = mails(sender).sendPasswordReset("jane@example.com", "Jane", TOKEN,
                Instant.parse("2026-11-06T12:30:00Z"), Instant.parse("2026-11-06T12:00:00Z"));

        assertThat(sent).isFalse();
        assertThat(output.getAll()).contains("email failed: to=j***@example.com", "status=422",
                "error=validation_error").doesNotContain(KEY).doesNotContain(TOKEN).doesNotContain("jane@example.com");
    }

    @Test
    void anUnreachableProviderNeverThrows(CapturedOutput output) {
        ResendMailSender sender = new ResendMailSender("http://127.0.0.1:1", KEY, "x <a@b.c>");
        assertThat(sender.send(new MailMessage("jane@example.com", "S", "t", "h"), null)).isFalse();
        assertThat(output.getAll()).contains("email failed").doesNotContain(KEY);
    }

    @Test
    void theSenderIsChosenByConfiguration(CapturedOutput output) {
        MailConfig config = new MailConfig();
        assertThat(config.mailSender(false, KEY, base(), "f", true)).isInstanceOf(LogMailSender.class);
        assertThat(config.mailSender(true, KEY, base(), "f", false)).isInstanceOf(ResendMailSender.class);
        MailSender missing = config.mailSender(true, " ", base(), "f", false);
        assertThat(missing).isInstanceOf(LogMailSender.class);
        assertThat(output.getAll()).contains("WARN", "RESEND_API_KEY is not set");

        missing.send(new MailMessage("jane@example.com", "S", "t", "h"), "https://x/accept-invite#" + TOKEN);
        assertThat(output.getAll()).contains("email not sent (RESEND_API_KEY not set): to=j***@example.com",
                "link=https://x/accept-invite#AbCd…").doesNotContain(TOKEN);
    }

    @Test
    void locallyTheFullLinkIsLoggedSoItCanBeClicked(CapturedOutput output) {
        new LogMailSender(true, "sending disabled here", false)
                .send(new MailMessage("jane@example.com", "S", "t", "h"), "http://localhost:3000/accept-invite#" + TOKEN);
        assertThat(output.getAll()).contains("http://localhost:3000/accept-invite#" + TOKEN);
    }

    @Test
    void templatesEscapeWhatTheyInsert() {
        CapturedSender sender = new CapturedSender();
        mails(sender).sendInvite("x@example.com", "<b>Eve</b>", "Mallory & \"Co\"", TOKEN,
                Instant.parse("2026-11-09T17:00:00Z"));
        assertThat(sender.message.html()).contains("&lt;b&gt;Eve&lt;/b&gt;", "Mallory &amp; &quot;Co&quot;")
                .doesNotContain("<b>Eve</b>");
        assertThat(sender.message.text()).contains("expires on November 9, 2026 at 12:00 PM EST",
                "https://db.nordencapital.ca/accept-invite#" + TOKEN);
    }

    static final class CapturedSender implements MailSender {
        MailMessage message;

        @Override
        public boolean send(MailMessage message, String linkForLog) {
            this.message = message;
            return true;
        }
    }
}
