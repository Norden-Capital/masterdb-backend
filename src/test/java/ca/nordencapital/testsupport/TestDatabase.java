package ca.nordencapital.testsupport;

import io.zonky.test.db.postgres.embedded.EmbeddedPostgres;
import org.springframework.test.context.DynamicPropertyRegistry;

import java.io.IOException;
import java.io.UncheckedIOException;

/**
 * One in-process PostgreSQL 16 for every @SpringBootTest in the JVM, so test
 * classes with different properties (separate Spring contexts) share it.
 * Call {@link #register} from a @DynamicPropertySource method.
 */
public final class TestDatabase {

    // Started on first use and stopped by its own shutdown hook. Closing it
    // in @AfterAll would pull the database out from under a cached Spring
    // context, which only shuts down later.
    private static EmbeddedPostgres postgres;

    private TestDatabase() {
    }

    public static synchronized void register(DynamicPropertyRegistry registry) {
        String url = jdbcUrl();
        registry.add("spring.datasource.url", () -> url);
        registry.add("spring.datasource.username", () -> "postgres");
        registry.add("spring.datasource.password", () -> "postgres");
    }

    /** The same database as command-line arguments, for tests that start the application themselves. */
    public static synchronized String[] args() {
        return new String[] {
                "--spring.datasource.url=" + jdbcUrl(),
                "--spring.datasource.username=postgres",
                "--spring.datasource.password=postgres",
        };
    }

    private static synchronized String jdbcUrl() {
        if (postgres == null) {
            try {
                postgres = EmbeddedPostgres.builder().start();
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
        }
        return postgres.getJdbcUrl("postgres", "postgres");
    }
}
