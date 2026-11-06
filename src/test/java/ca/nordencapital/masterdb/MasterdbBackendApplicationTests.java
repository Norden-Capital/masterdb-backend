package ca.nordencapital.masterdb;

import ca.nordencapital.testsupport.TestDatabase;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import jakarta.servlet.Filter;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Boots the whole application against a real PostgreSQL 16 started in-process,
 * so Flyway and Hibernate validation run for real with no Docker and no server.
 * The API docs have their own tests in config/ApiDocs*Test.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@Import(MasterdbBackendApplicationTests.FailingFilter.class)
class MasterdbBackendApplicationTests {

    @DynamicPropertySource
    static void database(DynamicPropertyRegistry registry) {
        TestDatabase.register(registry);
    }

    @Autowired
    JdbcTemplate jdbc;

    @LocalServerPort
    int port;

    @Test
    void contextLoadsAgainstPostgres16() {
        String version = jdbc.queryForObject("show server_version", String.class);
        assertThat(version).startsWith("16.");
    }

    /**
     * Through real Tomcat, not MockMvc: refusals and container-level errors are
     * problem+json too. An unknown route without a session is 401 (everything
     * outside the open list needs a sign-in, known route or not); signed in, it
     * is 404 (AuthFlowTest).
     */
    @Test
    void realServerAnswersErrorsAsProblemJson() throws Exception {
        HttpClient http = HttpClient.newHttpClient();

        HttpResponse<String> unknown = http.send(HttpRequest.newBuilder(URI.create(base() + "/api/v1/nope?email=a@b.c"))
                .header("Accept", "text/html").header("X-Request-Id", "it-401").build(),
                HttpResponse.BodyHandlers.ofString());
        assertThat(unknown.statusCode()).isEqualTo(401);
        assertThat(unknown.headers().firstValue("Content-Type")).hasValueSatisfying(
                ct -> assertThat(ct).startsWith("application/problem+json"));
        assertThat(unknown.headers().firstValue("X-Request-Id")).hasValue("it-401");
        assertThat(unknown.body()).contains("\"code\":\"UNAUTHENTICATED\"", "\"requestId\":\"it-401\"",
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
            // Before Spring Security (order -100), which would refuse the anonymous call first.
            bean.setOrder(-1000);
            return bean;
        }
    }

    private String base() {
        return "http://localhost:" + port;
    }
}
