package ca.nordencapital.masterdb.web.security;

import ca.nordencapital.testsupport.TestDatabase;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Browsers may call the API only from the website (production settings).
 * Real Tomcat, so refusals go through /error.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class CorsConfigTest {

    static final String FRONTEND = "https://db.nordencapital.ca";
    static final String OTHER = "https://evil.example.com";

    @DynamicPropertySource
    static void database(DynamicPropertyRegistry registry) {
        TestDatabase.register(registry);
    }

    @LocalServerPort
    int port;

    final HttpClient http = HttpClient.newHttpClient();

    HttpResponse<String> preflight(String origin, String method) throws Exception {
        return http.send(HttpRequest.newBuilder(URI.create("http://localhost:" + port + "/api/v1/status"))
                .method("OPTIONS", HttpRequest.BodyPublishers.noBody())
                .header("Origin", origin)
                .header("Access-Control-Request-Method", method)
                .header("Access-Control-Request-Headers", "content-type")
                .build(), HttpResponse.BodyHandlers.ofString());
    }

    HttpResponse<String> get(String origin) throws Exception {
        return http.send(HttpRequest.newBuilder(URI.create("http://localhost:" + port + "/api/v1/status"))
                .header("Origin", origin)
                .build(), HttpResponse.BodyHandlers.ofString());
    }

    @Test
    void preflightFromFrontendIsAllowedWithCredentials() throws Exception {
        for (String method : new String[] {"GET", "POST", "PUT", "PATCH", "DELETE"}) {
            HttpResponse<String> response = preflight(FRONTEND, method);
            assertThat(response.statusCode()).as(method).isEqualTo(200);
            assertThat(response.headers().firstValue("Access-Control-Allow-Origin")).hasValue(FRONTEND);
            assertThat(response.headers().firstValue("Access-Control-Allow-Credentials")).hasValue("true");
            assertThat(response.headers().firstValue("Access-Control-Allow-Methods")).hasValueSatisfying(
                    m -> assertThat(m).contains(method));
        }
    }

    @Test
    void preflightFromAnotherSiteIsRefused() throws Exception {
        HttpResponse<String> response = preflight(OTHER, "POST");
        assertThat(response.statusCode()).isEqualTo(403);
        assertThat(response.headers().firstValue("Access-Control-Allow-Origin")).isEmpty();
        assertThat(response.headers().firstValue("Content-Type")).hasValueSatisfying(
                ct -> assertThat(ct).startsWith("application/problem+json"));
        assertThat(response.body()).contains("\"code\":\"FORBIDDEN\"", "\"requestId\":");
    }

    @Test
    void unlistedMethodIsRefused() throws Exception {
        assertThat(preflight(FRONTEND, "TRACE").statusCode()).isEqualTo(403);
    }

    @Test
    void requestFromFrontendGetsCorsHeaders() throws Exception {
        HttpResponse<String> response = get(FRONTEND);
        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(response.headers().firstValue("Access-Control-Allow-Origin")).hasValue(FRONTEND);
        assertThat(response.headers().firstValue("Access-Control-Expose-Headers")).hasValueSatisfying(
                h -> assertThat(h).contains("X-Request-Id"));
    }

    @Test
    void requestFromAnotherSiteIsRefused() throws Exception {
        HttpResponse<String> response = get(OTHER);
        assertThat(response.statusCode()).isEqualTo(403);
        assertThat(response.headers().firstValue("Access-Control-Allow-Origin")).isEmpty();
    }
}
