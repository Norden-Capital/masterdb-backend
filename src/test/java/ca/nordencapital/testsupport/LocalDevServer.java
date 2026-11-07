package ca.nordencapital.testsupport;

import ca.nordencapital.masterdb.MasterdbBackendApplication;
import io.zonky.test.db.postgres.embedded.EmbeddedPostgres;
import org.springframework.boot.SpringApplication;

import java.util.ArrayList;
import java.util.List;

/**
 * Runs the backend on this PC without Docker: an embedded PostgreSQL 16 (the
 * one the tests use, empty at every start) plus the app with the `local`
 * profile on http://localhost:8080. For trying the frontend against a real
 * backend (`next dev` with BACKEND_URL=http://localhost:8080).
 *
 * <pre>
 * ./mvnw -q test-compile dependency:build-classpath -Dmdep.outputFile=target/cp.txt -Dmdep.includeScope=test
 * java -cp "target/test-classes;target/classes;$(cat target/cp.txt)" ca.nordencapital.testsupport.LocalDevServer
 * </pre>
 *
 * Extra arguments are passed to Spring (e.g. --BOOTSTRAP_OWNER_EMAIL=...).
 * Test-only: never packaged in the jar.
 */
public final class LocalDevServer {

    private LocalDevServer() {
    }

    public static void main(String[] args) throws Exception {
        EmbeddedPostgres postgres = EmbeddedPostgres.builder().start();
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            try {
                postgres.close();
            } catch (Exception ignored) {
                // shutting down anyway
            }
        }));
        List<String> all = new ArrayList<>(List.of(
                "--spring.profiles.active=local",
                "--spring.datasource.url=" + postgres.getJdbcUrl("postgres", "postgres"),
                "--spring.datasource.username=postgres",
                "--spring.datasource.password=postgres"));
        all.addAll(List.of(args));
        SpringApplication.run(MasterdbBackendApplication.class, all.toArray(String[]::new));
    }
}
