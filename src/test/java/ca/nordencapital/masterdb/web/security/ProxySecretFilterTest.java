package ca.nordencapital.masterdb.web.security;

import ca.nordencapital.masterdb.MasterdbBackendApplication;
import ca.nordencapital.testsupport.TestDatabase;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.env.YamlPropertySourceLoader;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.core.env.PropertySource;
import org.springframework.core.io.ClassPathResource;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Only the website (which knows PROXY_SECRET) may call the API, and production
 * cannot start without the secret. Through real Tomcat: the 401 body comes
 * from the container's /error forward, which MockMvc does not perform.
 */
class ProxySecretFilterTest {

    /** A test value only, 64 characters like the real one. */
    static final String SECRET = "test-proxy-secret-0123456789abcdef0123456789abcdef0123456789abcd";

    @Nested
    @SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
            "app.proxy.required=true",
            "app.proxy.secret=" + SECRET,
    })
    @ExtendWith(OutputCaptureExtension.class)
    class Enforced {

        @DynamicPropertySource
        static void database(DynamicPropertyRegistry registry) {
            TestDatabase.register(registry);
        }

        @LocalServerPort
        int port;

        final HttpClient http = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build();

        HttpResponse<String> get(String path, String secret) throws Exception {
            HttpRequest.Builder request = HttpRequest.newBuilder(URI.create("http://localhost:" + port + path));
            if (secret != null) {
                request.header(ProxySecretFilter.HEADER, secret);
            }
            return http.send(request.build(), HttpResponse.BodyHandlers.ofString());
        }

        void assertRejected(HttpResponse<String> response, String path) {
            assertThat(response.statusCode()).as(path).isEqualTo(401);
            assertThat(response.headers().firstValue("Content-Type")).as(path).hasValueSatisfying(
                    ct -> assertThat(ct).startsWith("application/problem+json"));
            String id = response.headers().firstValue("X-Request-Id").orElseThrow();
            assertThat(response.body()).as(path).contains(
                    "\"code\":\"PROXY_SECRET_INVALID\"",
                    "\"status\":401",
                    "\"requestId\":\"" + id + "\"",
                    "\"detail\":\"" + ProxySecretFilter.DETAIL + "\"");
        }

        @Test
        void noHeaderIs401() throws Exception {
            assertRejected(get("/api/v1/status", null), "/api/v1/status");
        }

        @Test
        void wrongHeaderIs401AndLooksExactlyLikeMissing(CapturedOutput output) throws Exception {
            String wrong = "wrong-value-that-must-never-be-logged";
            HttpResponse<String> response = get("/api/v1/status", wrong);
            assertRejected(response, "/api/v1/status");

            HttpResponse<String> missing = get("/api/v1/status", null);
            assertThat(strip(response.body())).isEqualTo(strip(missing.body()));

            // The rejection is logged with its request id; the header value never is.
            String id = response.headers().firstValue("X-Request-Id").orElseThrow();
            assertThat(output).contains("GET /api/v1/status 401").contains("requestId=" + id)
                    .doesNotContain(wrong).doesNotContain(SECRET);
        }

        @Test
        void almostRightHeaderIs401() throws Exception {
            assertRejected(get("/api/v1/status", SECRET.substring(0, SECRET.length() - 1)), "prefix");
            assertRejected(get("/api/v1/status", SECRET + "x"), "longer");
            assertRejected(get("/api/v1/status", SECRET.toUpperCase()), "case");
        }

        @Test
        void rightHeaderPasses() throws Exception {
            HttpResponse<String> response = get("/api/v1/status", SECRET);
            assertThat(response.statusCode()).isEqualTo(200);
            assertThat(response.body()).contains("\"status\":\"ok\"");
        }

        @Test
        void healthIsOpenWithoutHeader() throws Exception {
            HttpResponse<String> response = get("/actuator/health", null);
            assertThat(response.statusCode()).isEqualTo(200);
            assertThat(response.body()).contains("\"status\":\"UP\"");
        }

        /** Everything except health is closed, including tricks that decode to /api. */
        @ParameterizedTest
        @ValueSource(strings = {"/api/v1/nope", "/%61pi/v1/status", "/api/v1/status;x=1", "/", "/actuator",
                "/actuator/env", "/error"})
        void everythingElseIs401WithoutHeader(String path) throws Exception {
            assertRejected(get(path, null), path);
        }

        private static String strip(String body) {
            return body.replaceAll("\"(timestamp|requestId)\":\"[^\"]*\"", "");
        }
    }

    /** The check is never silently off in production. */
    @Nested
    class FailClosed {

        @Test
        void applicationRefusesToStartWithoutSecret() {
            List<String> args = new java.util.ArrayList<>(List.of(TestDatabase.args()));
            // What production has: required (the default) and PROXY_SECRET empty.
            args.add("--app.proxy.required=true");
            args.add("--app.proxy.secret=");
            args.add("--server.port=0");

            assertThatThrownBy(() -> new SpringApplicationBuilder(MasterdbBackendApplication.class)
                    .web(WebApplicationType.SERVLET)
                    .run(args.toArray(String[]::new)).close())
                    .rootCause().hasMessageContaining("PROXY_SECRET is not set");
        }

        @Test
        void shortSecretIsRefusedAndNotEchoed() {
            new ApplicationContextRunner()
                    .withUserConfiguration(ProxySecretFilter.class)
                    .withPropertyValues("app.proxy.secret=too-short-abc")
                    .run(context -> {
                        assertThat(context).hasFailed();
                        assertThat(context.getStartupFailure()).rootCause()
                                .hasMessageContaining("shorter than 32")
                                .message().doesNotContain("too-short-abc");
                    });
        }

        @Test
        void notRequiredAndEmptyMeansCheckOff() {
            new ApplicationContextRunner()
                    .withUserConfiguration(ProxySecretFilter.class)
                    .withPropertyValues("app.proxy.required=false", "app.proxy.secret=")
                    .run(context -> assertThat(context).hasNotFailed());
        }

        /** The jar's defaults require the secret; only the local profile relaxes it. */
        @Test
        void productionDefaultsRequireTheSecret() throws Exception {
            YamlPropertySourceLoader yaml = new YamlPropertySourceLoader();
            PropertySource<?> main = yaml.load("main", new ClassPathResource("application.yml")).getFirst();
            PropertySource<?> local = yaml.load("local", new ClassPathResource("application-local.yml")).getFirst();

            assertThat(main.getProperty("app.proxy.required")).hasToString("true");
            assertThat(main.getProperty("app.proxy.secret")).hasToString("${PROXY_SECRET:}");
            assertThat(local.getProperty("app.proxy.required")).hasToString("false");
            assertThat(local.getProperty("app.proxy.secret")).isNull();
            // CORS: production allows the website only; local adds the Next.js dev server.
            assertThat(main.getProperty("app.cors.allowed-origins"))
                    .hasToString("${APP_CORS_ALLOWED_ORIGINS:https://db.nordencapital.ca}");
            assertThat(local.getProperty("app.cors.allowed-origins").toString()).endsWith(",http://localhost:3000");
        }
    }
}
