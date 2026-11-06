package ca.nordencapital.masterdb;

import io.zonky.test.db.postgres.embedded.EmbeddedPostgres;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import jakarta.servlet.Filter;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Boots the whole application against a real PostgreSQL 16 started in-process,
 * so Flyway and Hibernate validation run for real with no Docker and no server.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureMockMvc
@Import(MasterdbBackendApplicationTests.FailingFilter.class)
class MasterdbBackendApplicationTests {

    // Started once per test JVM and stopped by its own shutdown hook. Closing it
    // in @AfterAll would pull the database out from under the cached Spring
    // context, which only shuts down later.
    private static EmbeddedPostgres postgres;

    @DynamicPropertySource
    static void database(DynamicPropertyRegistry registry) throws IOException {
        if (postgres == null) {
            postgres = EmbeddedPostgres.builder().start();
        }
        registry.add("spring.datasource.url", () -> postgres.getJdbcUrl("postgres", "postgres"));
        registry.add("spring.datasource.username", () -> "postgres");
        registry.add("spring.datasource.password", () -> "postgres");
    }

    @Autowired
    JdbcTemplate jdbc;

    @Autowired
    MockMvc mvc;

    @LocalServerPort
    int port;

    @Test
    void contextLoadsAgainstPostgres16() {
        String version = jdbc.queryForObject("show server_version", String.class);
        assertThat(version).startsWith("16.");
    }

    @Test
    void openApiJsonListsTheApi() throws Exception {
        mvc.perform(get("/api/v3/api-docs"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.info.title").value("MasterDB API"))
                .andExpect(jsonPath("$.paths['/api/v1/status']").exists())
                .andExpect(jsonPath("$.paths['/api/docs']").doesNotExist());
    }

    @Test
    void openApiDocumentsTheProblemDetailErrorResponse() throws Exception {
        mvc.perform(get("/api/v3/api-docs"))
                .andExpect(jsonPath("$.components.schemas.ProblemDetail.properties.code.enum").isArray())
                .andExpect(jsonPath("$.components.schemas.ProblemDetail.properties.requestId").exists())
                .andExpect(jsonPath("$.components.schemas.FieldViolation").exists())
                .andExpect(jsonPath("$.paths['/api/v1/status'].get.responses.default.content['application/problem+json']"
                        + ".schema['$ref']").value("#/components/schemas/ProblemDetail"));
    }

    /** Through real Tomcat, not MockMvc: unknown routes and container-level errors are problem+json too. */
    @Test
    void realServerAnswersErrorsAsProblemJson() throws Exception {
        HttpClient http = HttpClient.newHttpClient();

        HttpResponse<String> unknown = http.send(HttpRequest.newBuilder(URI.create(base() + "/api/v1/nope?email=a@b.c"))
                .header("Accept", "text/html").header("X-Request-Id", "it-404").build(),
                HttpResponse.BodyHandlers.ofString());
        assertThat(unknown.statusCode()).isEqualTo(404);
        assertThat(unknown.headers().firstValue("Content-Type")).hasValueSatisfying(
                ct -> assertThat(ct).startsWith("application/problem+json"));
        assertThat(unknown.headers().firstValue("X-Request-Id")).hasValue("it-404");
        assertThat(unknown.body()).contains("\"code\":\"NOT_FOUND\"", "\"requestId\":\"it-404\"",
                "\"instance\":\"/api/v1/nope\"").doesNotContain("a@b.c");

        // An exception escaping a servlet filter never reaches the controller advice:
        // the container forwards to /error, which must answer in the same format.
        HttpResponse<String> failed = http.send(HttpRequest.newBuilder(URI.create(base() + FailingFilter.PATH))
                .header("X-Request-Id", "it-500").build(), HttpResponse.BodyHandlers.ofString());
        assertThat(failed.statusCode()).isEqualTo(500);
        assertThat(failed.headers().firstValue("Content-Type")).hasValueSatisfying(
                ct -> assertThat(ct).startsWith("application/problem+json"));
        assertThat(failed.body()).contains("\"code\":\"INTERNAL_ERROR\"", "\"requestId\":\"it-500\"",
                "\"instance\":\"" + FailingFilter.PATH + "\"").doesNotContain("hunter2");
    }

    /** Test-only filter that blows up on one path, to reach the real /error forward. */
    @TestConfiguration
    static class FailingFilter {
        static final String PATH = "/api/v1/test-filter-failure";

        @Bean
        FilterRegistrationBean<Filter> failingFilter() {
            FilterRegistrationBean<Filter> bean = new FilterRegistrationBean<>((request, response, chain) -> {
                throw new IllegalStateException("password=hunter2");
            });
            bean.addUrlPatterns(PATH);
            return bean;
        }
    }

    private String base() {
        return "http://localhost:" + port;
    }

    @Test
    void swaggerUiIsServedAtApiDocsWithItsAssets() throws Exception {
        mvc.perform(get("/api/docs"))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("/api/v3/api-docs/swagger-config")));
        mvc.perform(get("/api/v3/api-docs/swagger-config")).andExpect(status().isOk());
        mvc.perform(get("/swagger-ui/swagger-ui-bundle.js")).andExpect(status().isOk());
    }
}
