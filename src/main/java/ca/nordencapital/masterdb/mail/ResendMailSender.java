package ca.nordencapital.masterdb.mail;

import ca.nordencapital.masterdb.auth.user.Emails;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Sends through Resend's HTTP API ({@code POST /emails}), with
 * {@code RESEND_API_KEY} as a bearer token. The domain nordencapital.ca is
 * verified in Resend (its DNS records exist), so mail from
 * {@code no-reply@nordencapital.ca} is signed (SPF/DKIM).
 *
 * <p>Never throws and never retries: a failure is one ERROR line with the HTTP
 * status and Resend's error name, the masked recipient and the subject. Never
 * the key, the body, the link or Resend's free-text message (it can quote the
 * address).
 */
public class ResendMailSender implements MailSender {

    private static final Logger log = LoggerFactory.getLogger(ResendMailSender.class);
    private static final JsonMapper JSON = JsonMapper.builder().build();

    private final HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();
    private final URI endpoint;
    private final String apiKey;
    private final String from;

    public ResendMailSender(String baseUrl, String apiKey, String from) {
        this.endpoint = URI.create(baseUrl.replaceAll("/+$", "") + "/emails");
        this.apiKey = apiKey;
        this.from = from;
    }

    @Override
    public boolean send(MailMessage message, String linkForLog) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("from", from);
        body.put("to", List.of(message.to()));
        body.put("subject", message.subject());
        body.put("html", message.html());
        body.put("text", message.text());
        String to = Emails.mask(message.to());
        try {
            HttpRequest request = HttpRequest.newBuilder(endpoint)
                    .timeout(Duration.ofSeconds(10))
                    .header("Authorization", "Bearer " + apiKey)
                    .header("Content-Type", "application/json")
                    .header("User-Agent", "masterdb-backend")
                    .POST(HttpRequest.BodyPublishers.ofString(JSON.writeValueAsString(body)))
                    .build();
            HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() / 100 == 2) {
                log.info("email sent: to={} subject=\"{}\" id={}", to, message.subject(),
                        field(response.body(), "id"));
                return true;
            }
            log.error("email failed: to={} subject=\"{}\" status={} error={}", to, message.subject(),
                    response.statusCode(), field(response.body(), "name"));
            return false;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            log.error("email failed: to={} subject=\"{}\" (interrupted)", to, message.subject());
            return false;
        } catch (Exception e) {
            log.error("email failed: to={} subject=\"{}\" ({})", to, message.subject(), e.getClass().getSimpleName());
            return false;
        }
    }

    /** A short, safe field from Resend's JSON answer (letters, digits, - and _ only), or "-". */
    private static String field(String json, String name) {
        try {
            JsonNode node = JSON.readTree(json).get(name);
            String value = node == null ? null : node.asString();
            return value != null && value.matches("[A-Za-z0-9_-]{1,80}") ? value : "-";
        } catch (Exception e) {
            return "-";
        }
    }
}
