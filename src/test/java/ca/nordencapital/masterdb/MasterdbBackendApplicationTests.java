package ca.nordencapital.masterdb;

import io.zonky.test.db.postgres.embedded.EmbeddedPostgres;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import java.io.IOException;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Boots the whole application against a real PostgreSQL 16 started in-process,
 * so Flyway and Hibernate validation run for real with no Docker and no server.
 */
@SpringBootTest
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

    @Test
    void contextLoadsAgainstPostgres16() {
        String version = jdbc.queryForObject("show server_version", String.class);
        assertThat(version).startsWith("16.");
    }
}
