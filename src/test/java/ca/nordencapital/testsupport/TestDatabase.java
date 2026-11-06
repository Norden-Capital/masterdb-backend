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
        if (postgres == null) {
            try {
                postgres = EmbeddedPostgres.builder().start();
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
        }
        registry.add("spring.datasource.url", () -> postgres.getJdbcUrl("postgres", "postgres"));
        registry.add("spring.datasource.username", () -> "postgres");
        registry.add("spring.datasource.password", () -> "postgres");
    }
}
