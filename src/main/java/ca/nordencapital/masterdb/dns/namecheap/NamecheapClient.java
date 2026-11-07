package ca.nordencapital.masterdb.dns.namecheap;

import ca.nordencapital.masterdb.web.error.ErrorCode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Talks to the Namecheap XML API (ported from the old app's NamecheapAccounts /
 * NamecheapDns). Every call is a form POST, so the API key travels in the
 * body, never in a URL that a proxy could log.
 *
 * <p><b>The key never leaves this class:</b> it is not logged, and anything
 * Namecheap sends back has it replaced by {@code [hidden]} before it reaches
 * a message. Log lines carry the command and the outcome only.
 */
@Component
public class NamecheapClient {

    private static final Logger log = LoggerFactory.getLogger(NamecheapClient.class);
    private static final int MAX_BYTES = 2_000_000;
    private static final int PAGE_SIZE = 100;
    private static final DateTimeFormatter US_DATE = DateTimeFormatter.ofPattern("MM/dd/yyyy");
    static final Pattern DOMAIN = Pattern.compile("^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z]{2,63}$");

    /** Namecheap error numbers (API docs, "Global error codes"). */
    private static final Set<String> IP_ERRORS = Set.of("1011150", "1017150", "1011105", "1017105");
    private static final Set<String> KEY_ERRORS = Set.of("1011102", "1010102", "1011101", "1010101", "1017101",
            "1050900", "1016103", "1017103", "1019103");

    private final HttpClient http;
    private final NamecheapProperties properties;

    public NamecheapClient(NamecheapProperties properties) {
        this.properties = properties;
        this.http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build();
    }

    public String clientIp() {
        return properties.clientIp();
    }

    /** One domain of {@code namecheap.domains.getList}. Dates may be null when Namecheap leaves them out. */
    public record AccountDomain(String name, LocalDate created, LocalDate expires, boolean expired, boolean locked,
            boolean autoRenew, boolean usesNamecheapDns) {
    }

    public record DomainList(List<AccountDomain> domains, int totalItems) {
    }

    /** First page only: enough to prove the credentials work, and gives the total. */
    public DomainList firstPage(NamecheapCredentials credentials) {
        return listPage(credentials, 1, 10);
    }

    /** Every domain on the account, page by page (100 per call, at most 100 pages). */
    public List<AccountDomain> allDomains(NamecheapCredentials credentials) {
        Map<String, AccountDomain> out = new LinkedHashMap<>();
        for (int page = 1; page <= 100; page++) {
            DomainList one = listPage(credentials, page, PAGE_SIZE);
            one.domains().forEach(d -> out.putIfAbsent(d.name(), d));
            if (one.domains().size() < PAGE_SIZE || (long) page * PAGE_SIZE >= one.totalItems()) {
                break;
            }
        }
        return new ArrayList<>(out.values());
    }

    private DomainList listPage(NamecheapCredentials credentials, int page, int size) {
        Map<String, String> params = new LinkedHashMap<>();
        params.put("Page", Integer.toString(page));
        params.put("PageSize", Integer.toString(size));
        Element root = call(credentials, "namecheap.domains.getList", params);
        List<AccountDomain> domains = new ArrayList<>();
        NodeList nodes = root.getElementsByTagNameNS("*", "Domain");
        for (int i = 0; i < nodes.getLength(); i++) {
            Element d = (Element) nodes.item(i);
            String name = d.getAttribute("Name").trim().toLowerCase(Locale.ROOT);
            if (!DOMAIN.matcher(name).matches()) {
                continue;
            }
            domains.add(new AccountDomain(name, date(d.getAttribute("Created")), date(d.getAttribute("Expires")),
                    bool(d.getAttribute("IsExpired")), bool(d.getAttribute("IsLocked")),
                    bool(d.getAttribute("AutoRenew")), bool(d.getAttribute("IsOurDNS"))));
        }
        int total = domains.size();
        NodeList totals = root.getElementsByTagNameNS("*", "TotalItems");
        if (totals.getLength() > 0) {
            try {
                total = Integer.parseInt(totals.item(0).getTextContent().trim());
            } catch (NumberFormatException ignored) {
                // keep the count of this page
            }
        }
        return new DomainList(domains, total);
    }

    /**
     * Calls one command and returns the root element of an {@code OK} answer.
     * Any failure becomes a {@link NamecheapException} with a message for the user.
     */
    Element call(NamecheapCredentials credentials, String command, Map<String, String> params) {
        StringBuilder body = new StringBuilder();
        field(body, "ApiUser", credentials.apiUser());
        field(body, "ApiKey", credentials.apiKey());
        field(body, "UserName", credentials.username());
        field(body, "ClientIp", properties.clientIp());
        field(body, "Command", command);
        params.forEach((k, v) -> field(body, k, v));
        HttpRequest request = HttpRequest.newBuilder(URI.create(properties.baseUrl()))
                .timeout(properties.timeout())
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header("User-Agent", "masterdb-backend")
                .POST(HttpRequest.BodyPublishers.ofString(body.toString()))
                .build();
        byte[] raw;
        try {
            HttpResponse<InputStream> response = http.send(request, HttpResponse.BodyHandlers.ofInputStream());
            try (InputStream in = response.body()) {
                if (response.statusCode() != 200) {
                    log.warn("namecheap {} failed: HTTP {}", command, response.statusCode());
                    throw new NamecheapException(ErrorCode.NAMECHEAP_UNREACHABLE,
                            "Namecheap answered HTTP " + response.statusCode() + ". Try again in a moment.");
                }
                raw = in.readNBytes(MAX_BYTES + 1);
            }
        } catch (IOException e) {
            log.warn("namecheap {} failed: {}", command, e.getClass().getSimpleName());
            throw new NamecheapException(ErrorCode.NAMECHEAP_UNREACHABLE,
                    "Could not reach the Namecheap API. Try again in a moment.");
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new NamecheapException(ErrorCode.NAMECHEAP_UNREACHABLE, "The Namecheap call was interrupted.");
        }
        if (raw.length > MAX_BYTES) {
            throw new NamecheapException(ErrorCode.NAMECHEAP_UNREACHABLE, "Namecheap's answer was too large.");
        }
        Element root = parse(raw).getDocumentElement();
        if (!"OK".equalsIgnoreCase(root.getAttribute("Status"))) {
            throw error(root, credentials.apiKey(), command);
        }
        log.info("namecheap {} ok", command);
        return root;
    }

    private NamecheapException error(Element root, String apiKey, String command) {
        NodeList errors = root.getElementsByTagNameNS("*", "Error");
        String number = "";
        String text = "the request failed";
        if (errors.getLength() > 0) {
            Element first = (Element) errors.item(0);
            number = first.getAttribute("Number").trim();
            text = first.getTextContent().trim();
        }
        text = scrub(text, apiKey);
        // Only the number reaches the log: the text may quote the request.
        log.warn("namecheap {} refused: error {}", command, number.isEmpty() ? "(none)" : number);
        String lower = text.toLowerCase(Locale.ROOT);
        if (IP_ERRORS.contains(number) || (lower.contains("ip") && (lower.contains("invalid request ip")
                || lower.contains("whitelist") || lower.contains("requestip") || lower.contains("clientip")))) {
            return new NamecheapException(ErrorCode.NAMECHEAP_IP_NOT_WHITELISTED,
                    "Namecheap refused this server's IP address (" + properties.clientIp() + "). In Namecheap, open "
                            + "Profile → Tools → Namecheap API Access, make sure API access is ON and add "
                            + properties.clientIp() + " to the whitelisted IPs. Changes can take a few minutes.");
        }
        if (KEY_ERRORS.contains(number) || lower.contains("apikey") || lower.contains("api key")
                || lower.contains("apiuser") || lower.contains("api user") || lower.contains("username")) {
            return new NamecheapException(ErrorCode.NAMECHEAP_INVALID_KEY,
                    "Namecheap refused the API user, username or API key. Check them on Namecheap's API Access "
                            + "page (API access must be ON), then replace the key here.");
        }
        return new NamecheapException(ErrorCode.NAMECHEAP_ERROR,
                "Namecheap: " + text + (number.isEmpty() ? "" : " (error " + number + ")"));
    }

    /** Removes the key and anything control-like; at most 250 characters. */
    static String scrub(String text, String apiKey) {
        String out = text == null ? "" : text;
        if (apiKey != null && !apiKey.isEmpty()) {
            out = out.replace(apiKey, "[hidden]");
        }
        out = out.replaceAll("[\\p{Cntrl}]+", " ").trim();
        return out.length() > 250 ? out.substring(0, 250) : out;
    }

    private static Document parse(byte[] raw) {
        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setNamespaceAware(true);
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
            factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
            factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
            factory.setExpandEntityReferences(false);
            return factory.newDocumentBuilder().parse(new ByteArrayInputStream(raw));
        } catch (Exception e) {
            throw new NamecheapException(ErrorCode.NAMECHEAP_UNREACHABLE, "Namecheap sent an unreadable answer.");
        }
    }

    private static void field(StringBuilder target, String key, String value) {
        if (!target.isEmpty()) {
            target.append('&');
        }
        target.append(URLEncoder.encode(key, StandardCharsets.UTF_8)).append('=')
                .append(URLEncoder.encode(value == null ? "" : value, StandardCharsets.UTF_8));
    }

    private static boolean bool(String value) {
        return "true".equalsIgnoreCase(value == null ? "" : value.trim());
    }

    private static LocalDate date(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        try {
            return LocalDate.parse(value.trim(), US_DATE);
        } catch (DateTimeParseException e) {
            return null;
        }
    }
}
