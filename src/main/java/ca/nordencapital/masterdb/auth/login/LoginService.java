package ca.nordencapital.masterdb.auth.login;

import ca.nordencapital.masterdb.activity.ActivityAction;
import ca.nordencapital.masterdb.activity.ActivityLog;
import ca.nordencapital.masterdb.activity.ActivityLog.Party;
import ca.nordencapital.masterdb.auth.AuthProperties;
import ca.nordencapital.masterdb.auth.password.PasswordConfig;
import ca.nordencapital.masterdb.auth.twofactor.TwoFactorService;
import ca.nordencapital.masterdb.auth.user.Emails;
import ca.nordencapital.masterdb.auth.user.User;
import ca.nordencapital.masterdb.auth.user.UserRepository;
import ca.nordencapital.masterdb.auth.user.UserStatus;
import ca.nordencapital.masterdb.web.request.RequestIdFilter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

/**
 * Checks an email and password and, when they are right, opens the 2FA step
 * (TwoFactorService). The session starts only after the code.
 *
 * <p><b>No user enumeration.</b> An unknown email, a wrong password, and an
 * invited or disabled account all end in the same {@link LoginResult.InvalidCredentials}.
 * Each of them runs one BCrypt comparison (against a dummy hash when there is
 * no usable one), so the answer also takes about the same time. Made-up emails
 * are even locked out like real ones ({@link UnknownAccountAttempts}).
 *
 * <p><b>Lockout.</b> {@code app.auth.lockout.max-attempts} (5) failures in a
 * row lock the account for {@code duration} (15 min, {@code users.locked_until}).
 * While locked, the password is not checked at all, so the answer cannot tell
 * whether it was right. A success resets the count; so does the end of a lock.
 *
 * <p><b>Audit.</b> Every outcome is logged at INFO with the masked email, the
 * client address and the request id. Never the password or the token.
 */
@Service
public class LoginService {

    private static final Logger log = LoggerFactory.getLogger(LoginService.class);

    private final UserRepository users;
    private final PasswordEncoder passwordEncoder;
    private final TwoFactorService twoFactor;
    private final AuthProperties.Lockout lockout;
    private final Clock clock;
    private final UnknownAccountAttempts unknownAccounts;
    private final ActivityLog activity;
    /** A real BCrypt hash of a random value, so "no account" costs the same as "wrong password". */
    private final String dummyHash;

    public LoginService(UserRepository users, PasswordEncoder passwordEncoder, TwoFactorService twoFactor,
            AuthProperties properties, Clock clock, ActivityLog activity) {
        this.activity = activity;
        this.users = users;
        this.passwordEncoder = passwordEncoder;
        this.twoFactor = twoFactor;
        this.lockout = properties.lockout();
        this.clock = clock;
        this.unknownAccounts = new UnknownAccountAttempts(lockout.maxAttempts(), lockout.duration());
        this.dummyHash = passwordEncoder.encode(UUID.randomUUID().toString());
    }

    @Transactional
    public LoginResult login(String email, String password, String ip, String userAgent) {
        Instant now = clock.instant();
        String normalized = Emails.normalize(email);
        String masked = Emails.mask(normalized);

        Optional<User> found = users.findByEmailForUpdate(normalized);
        if (found.isEmpty()) {
            return unknownAccount(normalized, password, masked, ip, now);
        }
        User user = found.get();

        if (user.getLockedUntil() != null) {
            if (now.isBefore(user.getLockedUntil())) {
                log.info("login refused, account locked: {} until={} ip={} requestId={}", masked,
                        user.getLockedUntil(), ip, requestId());
                activity.record(ActivityAction.LOGIN_FAILED, null, Party.of(user), Map.of("reason", "account_locked"));
                return new LoginResult.Locked(user.getLockedUntil());
            }
            // The lock is over: a fresh set of attempts.
            user.setLockedUntil(null);
            user.setFailedLoginAttempts(0);
        }

        boolean passwordRight = matches(password, user.getPasswordHash());
        if (passwordRight && user.getStatus() == UserStatus.ACTIVE) {
            if (passwordEncoder.upgradeEncoding(user.getPasswordHash())) {
                user.setPasswordHash(passwordEncoder.encode(password));
            }
            // The failure count is NOT reset here: only a full sign-in (code
            // included) resets it, so the password alone cannot buy unlimited
            // code guesses.
            TwoFactorService.Started challenge = twoFactor.start(user, ip, userAgent);
            log.info("password ok, 2fa {}: {} user={} ip={} requestId={}",
                    challenge.purpose() == ca.nordencapital.masterdb.auth.twofactor.LoginChallenge.Purpose.SETUP
                            ? "setup required" : "required",
                    masked, user.getPublicId(), ip, requestId());
            return new LoginResult.SecondFactorRequired(challenge);
        }

        int failures = user.getFailedLoginAttempts() + 1;
        user.setFailedLoginAttempts(failures);
        String reason = user.getStatus() != UserStatus.ACTIVE
                ? "account " + user.getStatus().name().toLowerCase()
                : "wrong password";
        if (failures >= lockout.maxAttempts()) {
            Instant until = now.plus(lockout.duration());
            user.setLockedUntil(until);
            log.info("login failed ({}), account locked: {} attempts={} until={} ip={} requestId={}", reason, masked,
                    failures, until, ip, requestId());
            activity.record(ActivityAction.LOGIN_FAILED, null, Party.of(user), Map.of("reason", code(reason)));
            activity.record(ActivityAction.ACCOUNT_LOCKED, null, Party.of(user),
                    Map.of("attempts", failures, "until", until.toString()));
            return new LoginResult.Locked(until);
        }
        log.info("login failed ({}): {} attempts={} ip={} requestId={}", reason, masked, failures, ip, requestId());
        activity.record(ActivityAction.LOGIN_FAILED, null, Party.of(user),
                Map.of("reason", code(reason), "attempts", failures));
        return new LoginResult.InvalidCredentials();
    }

    /** Tests only: forget the in-memory counts for made-up emails. */
    void clearUnknownAccountAttempts() {
        unknownAccounts.clear();
    }

    private LoginResult unknownAccount(String email, String password, String masked, String ip, Instant now) {
        Instant lockedUntil = unknownAccounts.lockedUntil(email, now);
        if (lockedUntil != null) {
            log.info("login refused, account locked: {} until={} ip={} requestId={}", masked, lockedUntil, ip,
                    requestId());
            activity.record(ActivityAction.LOGIN_FAILED, null, Party.label(masked),
                    Map.of("reason", "unknown_account_locked"));
            return new LoginResult.Locked(lockedUntil);
        }
        matches(password, null); // same cost as a real check
        lockedUntil = unknownAccounts.recordFailure(email, now);
        if (lockedUntil != null) {
            log.info("login failed (unknown account), locked: {} until={} ip={} requestId={}", masked, lockedUntil,
                    ip, requestId());
            activity.record(ActivityAction.LOGIN_FAILED, null, Party.label(masked), Map.of("reason", "unknown_account"));
            return new LoginResult.Locked(lockedUntil);
        }
        log.info("login failed (unknown account): {} ip={} requestId={}", masked, ip, requestId());
        activity.record(ActivityAction.LOGIN_FAILED, null, Party.label(masked), Map.of("reason", "unknown_account"));
        return new LoginResult.InvalidCredentials();
    }

    /**
     * One BCrypt comparison, always: against the dummy hash when there is no
     * stored one. Over-long passwords (BCrypt reads 72 bytes at most) are
     * compared as a dummy and never match.
     */
    private boolean matches(String password, String hash) {
        boolean usable = password != null
                && password.getBytes(StandardCharsets.UTF_8).length <= PasswordConfig.MAX_BYTES;
        if (!usable) {
            passwordEncoder.matches("x", dummyHash);
            return false;
        }
        if (hash == null) {
            passwordEncoder.matches(password, dummyHash);
            return false;
        }
        return passwordEncoder.matches(password, hash);
    }

    /** "account disabled" → "account_disabled", for the activity log. */
    private static String code(String reason) {
        return reason.replace(' ', '_');
    }

    private static String requestId() {
        return MDC.get(RequestIdFilter.MDC_KEY);
    }
}
