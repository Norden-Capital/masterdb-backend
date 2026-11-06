package ca.nordencapital.masterdb.auth.bootstrap;

import ca.nordencapital.masterdb.MasterdbBackendApplication;
import ca.nordencapital.masterdb.auth.bootstrap.OwnerBootstrap.Outcome;
import ca.nordencapital.masterdb.auth.user.User;
import ca.nordencapital.masterdb.auth.user.UserRepository;
import ca.nordencapital.masterdb.auth.user.UserStatus;
import ca.nordencapital.testsupport.TestDatabase;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.env.YamlPropertySourceLoader;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.core.env.PropertySource;
import org.springframework.core.io.ClassPathResource;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.transaction.PlatformTransactionManager;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The first Owner: created once on an empty database, never otherwise, and
 * the password never reaches a log.
 */
@SpringBootTest
@ExtendWith(OutputCaptureExtension.class)
class OwnerBootstrapTest {

    /** Test values only. */
    static final String EMAIL = "Owner.Test@NordenCapital.example";
    static final String PASSWORD = "Test-only owner pass 7f3k!";
    static final String NAME = "Test Owner";

    @DynamicPropertySource
    static void database(DynamicPropertyRegistry registry) {
        TestDatabase.register(registry);
    }

    @Autowired
    UserRepository users;

    @Autowired
    PasswordEncoder passwordEncoder;

    @Autowired
    JdbcTemplate jdbc;

    @Autowired
    PlatformTransactionManager transactionManager;

    /** The database is shared by every test class: start and leave it empty. */
    @BeforeEach
    @AfterEach
    void emptyUsers() {
        jdbc.update("delete from users");
    }

    OwnerBootstrap bootstrap() {
        return new OwnerBootstrap(users, passwordEncoder, jdbc, transactionManager, "", "", "");
    }

    @Test
    void createsOneActiveOwnerWithAHashedPassword(CapturedOutput output) {
        assertThat(bootstrap().bootstrap(EMAIL, PASSWORD, NAME)).isEqualTo(Outcome.CREATED);

        assertThat(users.count()).isEqualTo(1);
        User owner = users.findByEmail(EMAIL).orElseThrow();
        assertThat(owner.getEmail()).isEqualTo("owner.test@nordencapital.example");
        assertThat(owner.getFullName()).isEqualTo(NAME);
        assertThat(owner.isOwner()).isTrue();
        assertThat(owner.getStatus()).isEqualTo(UserStatus.ACTIVE);

        // Stored hashed, and the encoder recognises it.
        String stored = jdbc.queryForObject("select password_hash from users", String.class);
        assertThat(stored).startsWith("{bcrypt}$2a$12$").doesNotContain(PASSWORD);
        assertThat(passwordEncoder.matches(PASSWORD, stored)).isTrue();
        assertThat(passwordEncoder.matches("wrong-password-123", stored)).isFalse();

        // The log names the account masked, never the password or the full address.
        assertThat(output).contains("owner created: o***@nordencapital.example (id " + owner.getPublicId() + ")")
                .doesNotContain(PASSWORD)
                .doesNotContainIgnoringCase("owner.test@");
    }

    @Test
    void runsOnceThenSkips(CapturedOutput output) {
        assertThat(bootstrap().bootstrap(EMAIL, PASSWORD, NAME)).isEqualTo(Outcome.CREATED);
        String hash = jdbc.queryForObject("select password_hash from users", String.class);

        // A restart with the secrets still set, or with different ones: nothing changes.
        assertThat(bootstrap().bootstrap(EMAIL, PASSWORD, NAME)).isEqualTo(Outcome.SKIPPED_USERS_EXIST);
        assertThat(bootstrap().bootstrap("other@example.com", "another-long-password", "X"))
                .isEqualTo(Outcome.SKIPPED_USERS_EXIST);
        assertThat(users.count()).isEqualTo(1);
        assertThat(jdbc.queryForObject("select password_hash from users", String.class)).isEqualTo(hash);
        assertThat(output).contains("bootstrap skipped: users exist").doesNotContain(PASSWORD);
    }

    @Test
    void skippedWhenAnyUserExistsEvenIfNotTheOwner(CapturedOutput output) {
        users.saveAndFlush(User.newInvited("someone@example.com", "Someone"));

        assertThat(bootstrap().bootstrap(EMAIL, PASSWORD, NAME)).isEqualTo(Outcome.SKIPPED_USERS_EXIST);
        assertThat(users.existsByOwnerTrue()).isFalse();
        // Only that line: no names, no addresses.
        String lines = bootstrapLines(output);
        assertThat(lines).contains("bootstrap skipped: users exist").doesNotContain("someone", "owner.test");
    }

    @Test
    void notConfiguredMeansNoAccountAndAWarning(CapturedOutput output) {
        assertThat(bootstrap().bootstrap("", "", "")).isEqualTo(Outcome.SKIPPED_NOT_CONFIGURED);
        assertThat(bootstrap().bootstrap(null, null, null)).isEqualTo(Outcome.SKIPPED_NOT_CONFIGURED);
        assertThat(bootstrap().bootstrap(EMAIL, "  ", NAME)).isEqualTo(Outcome.SKIPPED_NOT_CONFIGURED);
        assertThat(bootstrap().bootstrap("", PASSWORD, NAME)).isEqualTo(Outcome.SKIPPED_NOT_CONFIGURED);

        assertThat(users.count()).isZero();
        assertThat(output).contains("WARN")
                .contains("BOOTSTRAP_OWNER_EMAIL and BOOTSTRAP_OWNER_PASSWORD are not set, so no owner was created")
                .contains("BOOTSTRAP_OWNER_PASSWORD is not set")
                .contains("BOOTSTRAP_OWNER_EMAIL is not set")
                .doesNotContain(PASSWORD);
    }

    @Test
    void shortPasswordIsRejected(CapturedOutput output) {
        String shortPassword = "Short-pw-13ch";
        assertThat(shortPassword).hasSize(13);

        assertThat(bootstrap().bootstrap(EMAIL, shortPassword, NAME)).isEqualTo(Outcome.REJECTED_INVALID);
        assertThat(users.count()).isZero();
        assertThat(output).contains("ERROR").contains("shorter than 14 characters").doesNotContain(shortPassword);

        // Exactly 14 is enough.
        assertThat(bootstrap().bootstrap(EMAIL, shortPassword + "x", NAME)).isEqualTo(Outcome.CREATED);
    }

    @Test
    void otherBadValuesAreRejectedWithoutEchoingThem(CapturedOutput output) {
        assertThat(bootstrap().bootstrap("not-an-email", PASSWORD, NAME)).isEqualTo(Outcome.REJECTED_INVALID);
        assertThat(bootstrap().bootstrap(EMAIL, "é".repeat(37), NAME)).as("74 bytes")
                .isEqualTo(Outcome.REJECTED_INVALID);
        assertThat(bootstrap().bootstrap(EMAIL, PASSWORD, "n".repeat(201))).isEqualTo(Outcome.REJECTED_INVALID);
        assertThat(users.count()).isZero();
        assertThat(output).contains("BOOTSTRAP_OWNER_EMAIL is not a valid email address")
                .contains("longer than 72 bytes")
                .contains("BOOTSTRAP_OWNER_NAME is longer than 200")
                .doesNotContain("not-an-email").doesNotContain(PASSWORD);
    }

    @Test
    void blankNameFallsBackToOwner() {
        assertThat(bootstrap().bootstrap(EMAIL, PASSWORD, "  ")).isEqualTo(Outcome.CREATED);
        assertThat(users.findByEmail(EMAIL).orElseThrow().getFullName()).isEqualTo("Owner");
    }

    /** Two instances starting at the same moment: exactly one Owner. */
    @Test
    void concurrentStartsCreateOneOwner() throws Exception {
        int instances = 4;
        ExecutorService pool = Executors.newFixedThreadPool(instances);
        try {
            CountDownLatch start = new CountDownLatch(1);
            List<Future<Outcome>> results = new ArrayList<>();
            for (int i = 0; i < instances; i++) {
                Callable<Outcome> task = () -> {
                    start.await();
                    return bootstrap().bootstrap(EMAIL, PASSWORD, NAME);
                };
                results.add(pool.submit(task));
            }
            start.countDown();
            List<Outcome> outcomes = new ArrayList<>();
            for (Future<Outcome> result : results) {
                outcomes.add(result.get());
            }
            assertThat(outcomes).containsOnlyOnce(Outcome.CREATED)
                    .filteredOn(o -> o != Outcome.CREATED).containsOnly(Outcome.SKIPPED_USERS_EXIST);
            assertThat(users.count()).isEqualTo(1);
        } finally {
            pool.shutdownNow();
        }
    }

    /**
     * The real wiring: the BOOTSTRAP_OWNER_* variables reach the runner at
     * startup, and nothing the startup prints (SQL, config, Hibernate)
     * contains the password.
     */
    @Test
    void applicationStartupCreatesTheOwnerFromTheEnvironmentVariables(CapturedOutput output) {
        List<String> args = new ArrayList<>(List.of(TestDatabase.args()));
        // Same names as the server's environment; command-line args fill the
        // same ${BOOTSTRAP_OWNER_...} placeholders in application.yml.
        args.add("--BOOTSTRAP_OWNER_EMAIL=" + EMAIL);
        args.add("--BOOTSTRAP_OWNER_PASSWORD=" + PASSWORD);
        args.add("--BOOTSTRAP_OWNER_NAME=" + NAME);
        args.add("--logging.level.org.hibernate.SQL=debug");
        args.add("--logging.level.org.springframework.boot.context.config=trace");
        args.add("--server.port=0");

        try (ConfigurableApplicationContext ignored = new SpringApplicationBuilder(MasterdbBackendApplication.class)
                .web(WebApplicationType.SERVLET).run(args.toArray(String[]::new))) {
            assertThat(users.count()).isEqualTo(1);
            assertThat(users.findByEmail(EMAIL).orElseThrow().isOwner()).isTrue();
        }
        assertThat(output).contains("owner created: o***@nordencapital.example").doesNotContain(PASSWORD);
    }

    /** The jar has no default for any of them: unset = no account. */
    @Test
    void noDefaultsInConfiguration() throws Exception {
        PropertySource<?> main = new YamlPropertySourceLoader()
                .load("main", new ClassPathResource("application.yml")).getFirst();
        assertThat(main.getProperty("app.bootstrap.owner.email")).hasToString("${BOOTSTRAP_OWNER_EMAIL:}");
        assertThat(main.getProperty("app.bootstrap.owner.password")).hasToString("${BOOTSTRAP_OWNER_PASSWORD:}");
        assertThat(main.getProperty("app.bootstrap.owner.name")).hasToString("${BOOTSTRAP_OWNER_NAME:}");
    }

    private static String bootstrapLines(CapturedOutput output) {
        return String.join("\n", output.getAll().lines().filter(l -> l.contains("OwnerBootstrap")).toList());
    }
}
