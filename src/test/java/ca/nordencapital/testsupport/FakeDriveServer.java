package ca.nordencapital.testsupport;

import ca.nordencapital.masterdb.lists.imports.DriveTransport;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * A fake Google Drive on 127.0.0.1 for the Drive download tests: answers are
 * set per host + path (query ignored). The test transport sends each request
 * the downloader makes (to https://drive.google.com/..., etc.) to this server
 * instead, with the original host in {@code X-Test-Host}; the downloader's own
 * checks still see the real-looking address. Nothing reaches Google.
 */
public final class FakeDriveServer {

    public static final FakeDriveServer SHARED = new FakeDriveServer();

    /** One canned answer. */
    public record Answer(int status, Map<String, String> headers, byte[] body) {
        public static Answer file(String text) {
            return new Answer(200, Map.of("Content-Type", "text/csv"), text.getBytes(StandardCharsets.UTF_8));
        }

        public static Answer html(String html) {
            return new Answer(200, Map.of("Content-Type", "text/html; charset=utf-8"),
                    html.getBytes(StandardCharsets.UTF_8));
        }

        public static Answer redirect(String location) {
            return new Answer(302, Map.of("Location", location), new byte[0]);
        }

        public static Answer status(int status) {
            return new Answer(status, Map.of("Content-Type", "text/plain"), new byte[0]);
        }
    }

    private final HttpServer server;
    private final Map<String, Answer> answers = new ConcurrentHashMap<>();
    /** Every request: "host path?query". */
    private final List<String> requests = new CopyOnWriteArrayList<>();

    private FakeDriveServer() {
        try {
            server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        server.createContext("/", this::handle);
        server.start();
    }

    public int port() {
        return server.getAddress().getPort();
    }

    public FakeDriveServer on(String host, String path, Answer answer) {
        answers.put(host + " " + path, answer);
        return this;
    }

    public List<String> requests() {
        return List.copyOf(requests);
    }

    public void reset() {
        answers.clear();
        requests.clear();
    }

    private void handle(HttpExchange ex) throws IOException {
        String host = ex.getRequestHeaders().getFirst("X-Test-Host");
        URI uri = ex.getRequestURI();
        requests.add(host + " " + uri.getRawPath() + (uri.getRawQuery() == null ? "" : "?" + uri.getRawQuery()));
        Answer a = answers.getOrDefault(host + " " + uri.getRawPath(), Answer.status(404));
        a.headers().forEach((k, v) -> ex.getResponseHeaders().add(k, v));
        ex.sendResponseHeaders(a.status(), a.body().length == 0 ? -1 : a.body().length);
        try (OutputStream out = ex.getResponseBody()) {
            out.write(a.body());
        }
    }

    /** The test transport: same rules as the real one (no redirects followed), but every request goes here. */
    @TestConfiguration
    public static class Config {
        @Bean
        @Primary
        public DriveTransport fakeDriveTransport() {
            HttpClient http = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build();
            return uri -> {
                URI local = URI.create("http://127.0.0.1:" + SHARED.port() + uri.getRawPath()
                        + (uri.getRawQuery() == null ? "" : "?" + uri.getRawQuery()));
                HttpResponse<InputStream> r = http.send(HttpRequest.newBuilder(local)
                        .header("X-Test-Host", uri.getHost()).GET().build(), HttpResponse.BodyHandlers.ofInputStream());
                return new DriveTransport.Response(r.statusCode(), r.headers().map(), r.body());
            };
        }
    }
}
