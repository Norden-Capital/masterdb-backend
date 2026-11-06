package ca.nordencapital.masterdb.config;

import ca.nordencapital.testsupport.TestDatabase;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
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
 * Docs are OFF unless switched on, so this runs with the plain defaults (what
 * production gets). Through real Tomcat, not MockMvc, so redirects and the
 * container's /error forward are covered too.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class ApiDocsDisabledTest {

    @DynamicPropertySource
    static void database(DynamicPropertyRegistry registry) {
        TestDatabase.register(registry);
    }

    @LocalServerPort
    int port;

    private final HttpClient http = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build();

    @ParameterizedTest
    @ValueSource(strings = {
            "/api/docs",
            "/api/docs/",
            "/api/v3/api-docs",
            "/api/v3/api-docs.yaml",
            "/api/v3/api-docs/swagger-config",
            "/swagger-ui.html",
            "/swagger-ui",
            "/swagger-ui/",
            "/swagger-ui/index.html",
            "/swagger-ui/swagger-ui-bundle.js",
            "/swagger-ui/swagger-ui.css",
            "/swagger-ui/swagger-initializer.js",
            "/swagger-ui/favicon-32x32.png",
            "/v3/api-docs",
            "/webjars/swagger-ui/index.html",
    })
    void everyDocsPathIsAPlainProblemJson404(String path) throws Exception {
        HttpResponse<String> response = http.send(HttpRequest.newBuilder(URI.create("http://localhost:" + port + path))
                .header("Accept", "text/html").build(), HttpResponse.BodyHandlers.ofString());

        assertThat(response.statusCode()).as(path).isEqualTo(404);
        assertThat(response.headers().firstValue("Content-Type")).as(path).hasValueSatisfying(
                ct -> assertThat(ct).startsWith("application/problem+json"));
        assertThat(response.body()).as(path).contains("\"code\":\"NOT_FOUND\"", "\"requestId\":");
    }
}
