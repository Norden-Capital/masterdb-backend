package ca.nordencapital.testsupport;

import com.sun.net.httpserver.HttpServer;
import org.springframework.test.context.DynamicPropertyRegistry;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Function;

/**
 * A fake Namecheap XML API on 127.0.0.1, so no test ever calls the real one.
 * Answers come from XML fixtures in {@code src/test/resources/namecheap/},
 * written from Namecheap's API docs with made-up values. One server per JVM
 * (like {@link TestDatabase}), so Spring contexts that point at it can be shared.
 *
 * <p>Call {@link #register} from a {@code @DynamicPropertySource} method and
 * {@link #reset()} before each test.
 */
public final class NamecheapStub {

    private static HttpServer server;
    private static final List<Map<String, String>> REQUESTS = new CopyOnWriteArrayList<>();
    private static final Map<String, Function<Map<String, String>, String>> ANSWERS = new ConcurrentHashMap<>();

    private NamecheapStub() {
    }

    public static synchronized void register(DynamicPropertyRegistry registry) {
        start();
        String url = "http://127.0.0.1:" + server.getAddress().getPort() + "/xml.response";
        registry.add("app.namecheap.base-url", () -> url);
        registry.add("app.namecheap.client-ip", () -> "203.0.113.10");
    }

    private static void start() {
        if (server != null) {
            return;
        }
        try {
            server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        server.createContext("/xml.response", exchange -> {
            Map<String, String> params = form(new String(exchange.getRequestBody().readAllBytes(),
                    StandardCharsets.UTF_8));
            REQUESTS.add(params);
            Function<Map<String, String>, String> answer = ANSWERS.get(params.getOrDefault("Command", ""));
            String xml = answer == null ? fixture("error-unknown-command") : answer.apply(params);
            byte[] out = xml.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "text/xml; charset=utf-8");
            exchange.sendResponseHeaders(200, out.length);
            exchange.getResponseBody().write(out);
            exchange.close();
        });
        server.start();
    }

    public static void reset() {
        REQUESTS.clear();
        ANSWERS.clear();
    }

    /** Answer {@code command} with the fixture {@code name}.xml. */
    public static void answer(String command, String fixture) {
        String xml = fixture(fixture);
        ANSWERS.put(command, p -> xml);
    }

    public static void answer(String command, Function<Map<String, String>, String> answer) {
        ANSWERS.put(command, answer);
    }

    /** Every call so far, as the form fields Namecheap would have received. */
    public static List<Map<String, String>> requests() {
        return new ArrayList<>(REQUESTS);
    }

    public static List<Map<String, String>> requests(String command) {
        return REQUESTS.stream().filter(r -> command.equals(r.get("Command"))).toList();
    }

    public static String fixture(String name) {
        try (InputStream in = NamecheapStub.class.getResourceAsStream("/namecheap/" + name + ".xml")) {
            if (in == null) {
                throw new IllegalArgumentException("no fixture " + name);
            }
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private static Map<String, String> form(String body) {
        Map<String, String> out = new LinkedHashMap<>();
        for (String pair : body.split("&")) {
            String[] kv = pair.split("=", 2);
            if (kv.length == 2) {
                out.put(URLDecoder.decode(kv[0], StandardCharsets.UTF_8), URLDecoder.decode(kv[1], StandardCharsets.UTF_8));
            }
        }
        return out;
    }
}
