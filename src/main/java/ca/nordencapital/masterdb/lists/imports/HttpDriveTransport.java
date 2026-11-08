package ca.nordencapital.masterdb.lists.imports;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

/** The real transport: Java's HTTP client, redirects never followed automatically. */
@Component
public class HttpDriveTransport implements DriveTransport {

    private final HttpClient http;
    private final Duration timeout;

    public HttpDriveTransport(@Value("${app.lists.drive.timeout:60s}") Duration timeout) {
        this.timeout = timeout;
        this.http = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER)
                .connectTimeout(Duration.ofSeconds(20)).build();
    }

    @Override
    public Response get(URI uri) throws IOException, InterruptedException {
        HttpResponse<InputStream> r = http.send(HttpRequest.newBuilder(uri).timeout(timeout)
                .header("User-Agent", "MasterDB list import").GET().build(), HttpResponse.BodyHandlers.ofInputStream());
        return new Response(r.statusCode(), r.headers().map(), r.body());
    }
}
