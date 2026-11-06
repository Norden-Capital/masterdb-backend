package ca.nordencapital.masterdb.auth.bootstrap;

import ca.nordencapital.masterdb.auth.password.PasswordConfig;
import ca.nordencapital.masterdb.auth.user.Emails;
import ca.nordencapital.masterdb.auth.user.User;
import ca.nordencapital.masterdb.auth.user.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import java.nio.charset.StandardCharsets;

/**
 * Creates the first account, the Owner, on an empty database. Nothing else.
 *
 * <p>Rules, each closing a way this goes wrong elsewhere:
 * <ul>
 *   <li><b>Only when there are no users at all</b>, not "when this email is
 *       missing": once anybody exists this does nothing, forever, so deleting
 *       or renaming the account is never undone by a restart. The only log
 *       line is then {@value #SKIPPED_USERS_EXIST}.</li>
 *   <li><b>The password comes from the environment</b>
 *       ({@code BOOTSTRAP_OWNER_PASSWORD}, a GitHub secret). There is no
 *       default: unset means no account and a WARN line. A database nobody can
 *       sign in to is recoverable; a known password in a public repository
 *       is not.</li>
 *   <li><b>Checked before use</b>: a plausible email, a password of at least
 *       {@value #MIN_PASSWORD_LENGTH} characters (and at most BCrypt's 72
 *       bytes). A bad value means no account and an ERROR line.</li>
 *   <li><b>Never logged</b>: not the password, not even its length; the email
 *       only masked ({@code j***@domain}).</li>
 *   <li><b>One transaction, one instance at a time</b>: a Postgres advisory
 *       lock serialises two instances starting together, so the second one
 *       sees the first one's Owner and skips. The single-owner and unique-email
 *       indexes back this up.</li>
 * </ul>
 *
 * <p>The Owner gets no 2FA here; 2FA is mandatory, so the first sign-in will go
 * straight to enrolment (2FA task).
 */
@Component
public class OwnerBootstrap implements ApplicationRunner {

    static final int MIN_PASSWORD_LENGTH = 14;
    static final int MAX_NAME_LENGTH = 200;
    static final String DEFAULT_NAME = "Owner";
    static final String SKIPPED_USERS_EXIST = "bootstrap skipped: users exist";

    /** pg_advisory_xact_lock key for this job only ("MDBOWNER" in ASCII). */
    private static final long LOCK_KEY = 0x4D44424F574E4552L;

    private static final Logger log = LoggerFactory.getLogger(OwnerBootstrap.class);

    /** What happened, for the tests. */
    public enum Outcome { CREATED, SKIPPED_USERS_EXIST, SKIPPED_NOT_CONFIGURED, REJECTED_INVALID }

    private final UserRepository users;
    private final PasswordEncoder passwordEncoder;
    private final JdbcTemplate jdbc;
    private final TransactionTemplate transaction;

    // No defaults: blank = not configured. Never a fallback password.
    private final String email;
    private final String password;
    private final String name;

    public OwnerBootstrap(UserRepository users, PasswordEncoder passwordEncoder, JdbcTemplate jdbc,
            PlatformTransactionManager transactionManager,
            @Value("${app.bootstrap.owner.email:}") String email,
            @Value("${app.bootstrap.owner.password:}") String password,
            @Value("${app.bootstrap.owner.name:}") String name) {
        this.users = users;
        this.passwordEncoder = passwordEncoder;
        this.jdbc = jdbc;
        this.transaction = new TransactionTemplate(transactionManager);
        this.email = email;
        this.password = password;
        this.name = name;
    }

    @Override
    public void run(ApplicationArguments args) {
        bootstrap(email, password, name);
    }

    /** The whole job with the given values. Public for the tests; the app calls it once, at startup. */
    public Outcome bootstrap(String email, String password, String name) {
        try {
            return transaction.execute(status -> {
                jdbc.query("select pg_advisory_xact_lock(?)", rs -> { }, LOCK_KEY);
                if (users.count() > 0) {
                    log.info(SKIPPED_USERS_EXIST);
                    return Outcome.SKIPPED_USERS_EXIST;
                }
                return createOwner(email, password, name);
            });
        } catch (DataIntegrityViolationException e) {
            // Only reachable if another writer got past the lock (a hand-made
            // row, say). The indexes refused the second Owner: nothing to do.
            log.info(SKIPPED_USERS_EXIST);
            return Outcome.SKIPPED_USERS_EXIST;
        }
    }

    private Outcome createOwner(String email, String password, String name) {
        boolean noEmail = email == null || email.isBlank();
        boolean noPassword = password == null || password.isBlank();
        if (noEmail || noPassword) {
            String missing = noEmail && noPassword ? "BOOTSTRAP_OWNER_EMAIL and BOOTSTRAP_OWNER_PASSWORD are"
                    : noEmail ? "BOOTSTRAP_OWNER_EMAIL is" : "BOOTSTRAP_OWNER_PASSWORD is";
            log.warn("owner bootstrap: the database has no users and {} not set, so no owner was created "
                    + "and nobody can sign in. Set both (GitHub secrets) and deploy again.", missing);
            return Outcome.SKIPPED_NOT_CONFIGURED;
        }

        // The messages say what is wrong, never what the value was.
        if (!Emails.isValid(email)) {
            log.error("owner bootstrap: BOOTSTRAP_OWNER_EMAIL is not a valid email address. No owner created.");
            return Outcome.REJECTED_INVALID;
        }
        if (password.length() < MIN_PASSWORD_LENGTH) {
            log.error("owner bootstrap: BOOTSTRAP_OWNER_PASSWORD is shorter than {} characters. No owner created.",
                    MIN_PASSWORD_LENGTH);
            return Outcome.REJECTED_INVALID;
        }
        if (password.getBytes(StandardCharsets.UTF_8).length > PasswordConfig.MAX_BYTES) {
            log.error("owner bootstrap: BOOTSTRAP_OWNER_PASSWORD is longer than {} bytes, more than BCrypt can use. "
                    + "No owner created.", PasswordConfig.MAX_BYTES);
            return Outcome.REJECTED_INVALID;
        }
        String fullName = name == null || name.isBlank() ? DEFAULT_NAME : name.trim();
        if (fullName.length() > MAX_NAME_LENGTH) {
            log.error("owner bootstrap: BOOTSTRAP_OWNER_NAME is longer than {} characters. No owner created.",
                    MAX_NAME_LENGTH);
            return Outcome.REJECTED_INVALID;
        }

        User owner = users.saveAndFlush(User.newOwner(email, fullName, passwordEncoder.encode(password)));
        log.info("owner created: {} (id {}). BOOTSTRAP_OWNER_PASSWORD is no longer needed and can be deleted "
                + "from the GitHub secrets.", Emails.mask(owner.getEmail()), owner.getPublicId());
        return Outcome.CREATED;
    }
}
