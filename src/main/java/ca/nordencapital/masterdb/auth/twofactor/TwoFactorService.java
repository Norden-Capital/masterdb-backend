package ca.nordencapital.masterdb.auth.twofactor;

import ca.nordencapital.masterdb.activity.ActivityAction;
import ca.nordencapital.masterdb.activity.ActivityLog;
import ca.nordencapital.masterdb.activity.ActivityLog.Party;
import ca.nordencapital.masterdb.auth.AuthProperties;
import ca.nordencapital.masterdb.auth.session.SessionService;
import ca.nordencapital.masterdb.auth.session.SessionService.IssuedSession;
import ca.nordencapital.masterdb.auth.session.SessionTokens;
import ca.nordencapital.masterdb.auth.user.Emails;
import ca.nordencapital.masterdb.auth.user.User;
import ca.nordencapital.masterdb.auth.user.UserStatus;
import ca.nordencapital.masterdb.crypto.SecretCipher;
import ca.nordencapital.masterdb.web.request.RequestIdFilter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.OptionalLong;

/**
 * The second sign-in step: TOTP, mandatory for everyone.
 *
 * <p>After the password, {@link #start} opens a {@link LoginChallenge} (token
 * in the md_preauth cookie, 10 minutes, 5 attempts). An enrolled user then
 * sends a code ({@link #verify}): an authenticator code (±1 step of drift,
 * each step accepted once) or one of their recovery codes. A user without 2FA
 * enrols instead ({@link #beginSetup}, {@link #confirmSetup}) and gets ten
 * recovery codes, shown once. Only then is a session started.
 *
 * <p>Wrong codes count against the same per-account lockout as wrong
 * passwords, so knowing the password does not allow unlimited code guessing.
 * Like LoginService, failures are returned, not thrown, so their bookkeeping
 * is committed.
 */
@Service
public class TwoFactorService {

    public static final int RECOVERY_CODE_COUNT = 10;
    private static final char[] RECOVERY_ALPHABET = "abcdefghjkmnpqrstuvwxyz23456789".toCharArray();
    private static final Logger log = LoggerFactory.getLogger(TwoFactorService.class);

    private final LoginChallengeRepository challenges;
    private final RecoveryCodeRepository recoveryCodes;
    private final SessionService sessions;
    private final SecretCipher cipher;
    private final AuthProperties.TwoFactor settings;
    private final AuthProperties.Lockout lockout;
    private final Clock clock;
    private final SecureRandom random = new SecureRandom();
    private final ActivityLog activity;

    public TwoFactorService(LoginChallengeRepository challenges, RecoveryCodeRepository recoveryCodes,
            SessionService sessions, SecretCipher cipher, AuthProperties properties, Clock clock,
            ActivityLog activity) {
        this.activity = activity;
        this.challenges = challenges;
        this.recoveryCodes = recoveryCodes;
        this.sessions = sessions;
        this.cipher = cipher;
        this.settings = properties.twoFactor();
        this.lockout = properties.lockout();
        this.clock = clock;
    }

    // ---- results -------------------------------------------------------------------

    public record Started(String token, LoginChallenge.Purpose purpose, Instant expiresAt) {
        @Override
        public String toString() {
            return "Started[" + purpose + "]";
        }
    }

    public record SetupInfo(String secret, String otpauthUri, String issuer, String account) {
        @Override
        public String toString() {
            return "SetupInfo[" + Emails.mask(account) + "]";
        }
    }

    public sealed interface CodeResult {
        /** Signed in. {@code recoveryCodes} is set only right after enrolment: show once. */
        record Authenticated(User user, IssuedSession session, List<String> recoveryCodes) implements CodeResult {
            @Override
            public String toString() {
                return "Authenticated[" + user + "]";
            }
        }

        record InvalidCode() implements CodeResult {
        }

        /** No usable challenge: missing, expired, used up, or for the other step. Sign in again. */
        record ChallengeInvalid() implements CodeResult {
        }

        record Locked(Instant until) implements CodeResult {
        }
    }

    // ---- the flow -------------------------------------------------------------------

    /** After a correct password: VERIFY for an enrolled user, SETUP for one who must enrol. */
    @Transactional
    public Started start(User user, String ip, String userAgent) {
        Instant now = clock.instant();
        LoginChallenge.Purpose purpose = user.isTwoFactorEnabled()
                ? LoginChallenge.Purpose.VERIFY : LoginChallenge.Purpose.SETUP;
        String token = SessionTokens.generate();
        Instant expires = now.plus(settings.challengeTtl());
        challenges.save(LoginChallenge.start(user, SessionTokens.hash(token), purpose, now, expires,
                truncate(ip, 45), truncate(userAgent, 255)));
        return new Started(token, purpose, expires);
    }

    /** A fresh secret for the SETUP challenge (calling again replaces it). Empty if the challenge is not usable. */
    @Transactional
    public Optional<SetupInfo> beginSetup(String token) {
        Optional<LoginChallenge> found = usable(token, LoginChallenge.Purpose.SETUP);
        if (found.isEmpty()) {
            return Optional.empty();
        }
        LoginChallenge challenge = found.get();
        User user = challenge.getUser();
        byte[] secret = new byte[Totp.SECRET_BYTES];
        random.nextBytes(secret);
        challenge.setPendingSecretEnc(cipher.encrypt(secret, context(user)));
        String base32 = Totp.base32(secret);
        return Optional.of(new SetupInfo(base32, Totp.otpauthUri(settings.issuer(), user.getEmail(), base32),
                settings.issuer(), user.getEmail()));
    }

    /** First code from the new authenticator: enrols, makes recovery codes, signs in. */
    @Transactional
    public CodeResult confirmSetup(String token, String code, String ip, String userAgent) {
        Optional<LoginChallenge> found = usable(token, LoginChallenge.Purpose.SETUP);
        if (found.isEmpty() || found.get().getPendingSecretEnc() == null) {
            return new CodeResult.ChallengeInvalid();
        }
        LoginChallenge challenge = found.get();
        User user = challenge.getUser();
        Instant now = clock.instant();
        Optional<CodeResult> refused = refuseLocked(user, challenge, now);
        if (refused.isPresent()) {
            return refused.get();
        }
        byte[] secret = cipher.decrypt(challenge.getPendingSecretEnc(), context(user));
        OptionalLong step = Totp.verify(secret, code, now, Long.MIN_VALUE);
        if (step.isEmpty()) {
            return wrongCode(user, challenge, now, "2fa setup code wrong");
        }
        user.enableTwoFactor(cipher.encrypt(secret, context(user)), now, step.getAsLong());
        List<String> codes = replaceRecoveryCodes(user, now);
        challenge.consume(now);
        log.info("2fa enrolled: {} user={} requestId={}", Emails.mask(user.getEmail()), user.getPublicId(),
                requestId());
        activity.record(ActivityAction.TWO_FACTOR_ENROLLED, Party.of(user), Party.of(user));
        return signIn(user, ip, userAgent, now, codes);
    }

    /** The code of an enrolled user: authenticator code or recovery code. */
    @Transactional
    public CodeResult verify(String token, String code, String ip, String userAgent) {
        Optional<LoginChallenge> found = usable(token, LoginChallenge.Purpose.VERIFY);
        if (found.isEmpty()) {
            return new CodeResult.ChallengeInvalid();
        }
        LoginChallenge challenge = found.get();
        User user = challenge.getUser();
        Instant now = clock.instant();
        Optional<CodeResult> refused = refuseLocked(user, challenge, now);
        if (refused.isPresent()) {
            return refused.get();
        }
        if (!user.isTwoFactorEnabled()) {
            challenge.consume(now); // reset in between: sign in again to enrol
            return new CodeResult.ChallengeInvalid();
        }
        String input = code == null ? "" : code.trim();
        if (input.replaceAll("\\s", "").matches("\\d{" + Totp.DIGITS + "}")) {
            byte[] secret = cipher.decrypt(user.getTotpSecretEnc(), context(user));
            long last = user.getTotpLastUsedStep() == null ? Long.MIN_VALUE : user.getTotpLastUsedStep();
            OptionalLong step = Totp.verify(secret, input, now, last);
            if (step.isEmpty()) {
                return wrongCode(user, challenge, now, "2fa code wrong or reused");
            }
            user.setTotpLastUsedStep(step.getAsLong());
        } else {
            Optional<RecoveryCode> recovery = recoveryCodes.findByUserIdAndCodeHashAndUsedAtIsNull(user.getId(),
                    cipher.keyedHash(normalizeRecoveryCode(input)));
            if (recovery.isEmpty()) {
                return wrongCode(user, challenge, now, "recovery code wrong or used");
            }
            recovery.get().use(now);
            activity.record(ActivityAction.RECOVERY_CODE_USED, Party.of(user), Party.of(user),
                    java.util.Map.of("remaining", recoveryCodes.countByUserIdAndUsedAtIsNull(user.getId()) - 1));
            log.info("recovery code used: {} user={} remaining={} requestId={}", Emails.mask(user.getEmail()),
                    user.getPublicId(), recoveryCodes.countByUserIdAndUsedAtIsNull(user.getId()) - 1, requestId());
        }
        challenge.consume(now);
        return signIn(user, ip, userAgent, now, null);
    }

    // ---- account management (M1.5) ----------------------------------------------------------

    /** New recovery codes for a signed-in user; the old ones stop working. Show once. */
    @Transactional
    public List<String> regenerateRecoveryCodes(User user) {
        return replaceRecoveryCodes(user, clock.instant());
    }

    /** An admin's reset: the user must enrol again at their next sign-in. */
    @Transactional
    public void reset(User user) {
        user.resetTwoFactor();
        recoveryCodes.deleteAllForUser(user.getId());
        challenges.consumeAllForUser(user.getId(), clock.instant());
    }

    /** Ends any sign-in half-way through (disable, password change or reset). */
    @Transactional
    public void endChallenges(User user) {
        challenges.consumeAllForUser(user.getId(), clock.instant());
    }

    public long remainingRecoveryCodes(User user) {
        return recoveryCodes.countByUserIdAndUsedAtIsNull(user.getId());
    }

    /** Checks a current authenticator code for a signed-in user (re-confirmation of a sensitive action). */
    @Transactional
    public boolean checkCurrentCode(User user, String code) {
        if (!user.isTwoFactorEnabled()) {
            return false;
        }
        byte[] secret = cipher.decrypt(user.getTotpSecretEnc(), context(user));
        long last = user.getTotpLastUsedStep() == null ? Long.MIN_VALUE : user.getTotpLastUsedStep();
        OptionalLong step = Totp.verify(secret, code, clock.instant(), last);
        step.ifPresent(user::setTotpLastUsedStep);
        return step.isPresent();
    }

    // ---- helpers --------------------------------------------------------------------

    private Optional<LoginChallenge> usable(String token, LoginChallenge.Purpose purpose) {
        if (!SessionTokens.isWellFormed(token)) {
            return Optional.empty();
        }
        return challenges.findForUpdate(SessionTokens.hash(token))
                .filter(c -> c.getPurpose() == purpose)
                .filter(c -> c.isUsable(clock.instant(), settings.maxAttempts()))
                .filter(c -> c.getUser().getStatus() == UserStatus.ACTIVE);
    }

    private Optional<CodeResult> refuseLocked(User user, LoginChallenge challenge, Instant now) {
        if (user.getLockedUntil() != null && now.isBefore(user.getLockedUntil())) {
            challenge.consume(now);
            return Optional.of(new CodeResult.Locked(user.getLockedUntil()));
        }
        return Optional.empty();
    }

    private CodeResult wrongCode(User user, LoginChallenge challenge, Instant now, String reason) {
        boolean challengeOver = challenge.recordFailure(settings.maxAttempts());
        int failures = user.getFailedLoginAttempts() + 1;
        user.setFailedLoginAttempts(failures);
        String masked = Emails.mask(user.getEmail());
        if (failures >= lockout.maxAttempts()) {
            Instant until = now.plus(lockout.duration());
            user.setLockedUntil(until);
            challenge.consume(now);
            log.info("login failed ({}), account locked: {} attempts={} until={} requestId={}", reason, masked,
                    failures, until, requestId());
            activity.record(ActivityAction.LOGIN_FAILED, null, Party.of(user), java.util.Map.of("reason", "2fa_code"));
            activity.record(ActivityAction.ACCOUNT_LOCKED, null, Party.of(user),
                    java.util.Map.of("attempts", failures, "until", until.toString()));
            return new CodeResult.Locked(until);
        }
        if (challengeOver) {
            challenge.consume(now);
        }
        log.info("login failed ({}): {} attempts={} requestId={}", reason, masked, failures, requestId());
        activity.record(ActivityAction.LOGIN_FAILED, null, Party.of(user),
                java.util.Map.of("reason", "2fa_code", "attempts", failures));
        return new CodeResult.InvalidCode();
    }

    private CodeResult signIn(User user, String ip, String userAgent, Instant now, List<String> codes) {
        user.setFailedLoginAttempts(0);
        user.setLockedUntil(null);
        user.setLastLoginAt(now);
        IssuedSession session = sessions.start(user, ip, userAgent);
        log.info("login succeeded: {} user={} session={} ip={} requestId={}", Emails.mask(user.getEmail()),
                user.getPublicId(), session.publicId(), ip, requestId());
        activity.record(ActivityAction.LOGIN_SUCCEEDED, Party.of(user), Party.of(user),
                java.util.Map.of("session", session.publicId().toString()));
        return new CodeResult.Authenticated(user, session, codes);
    }

    private List<String> replaceRecoveryCodes(User user, Instant now) {
        recoveryCodes.deleteAllForUser(user.getId());
        List<String> codes = new ArrayList<>(RECOVERY_CODE_COUNT);
        for (int i = 0; i < RECOVERY_CODE_COUNT; i++) {
            StringBuilder code = new StringBuilder(11);
            for (int c = 0; c < 10; c++) {
                if (c == 5) {
                    code.append('-');
                }
                code.append(RECOVERY_ALPHABET[random.nextInt(RECOVERY_ALPHABET.length)]);
            }
            codes.add(code.toString());
            recoveryCodes.save(new RecoveryCode(user.getId(), cipher.keyedHash(normalizeRecoveryCode(code.toString())),
                    now));
        }
        return codes;
    }

    static String normalizeRecoveryCode(String input) {
        return input.toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9]", "");
    }

    private static String context(User user) {
        return "totp:" + user.getId();
    }

    private static String truncate(String value, int max) {
        if (value == null || value.isBlank()) {
            return null;
        }
        String v = value.strip();
        return v.length() <= max ? v : v.substring(0, max);
    }

    private static String requestId() {
        return MDC.get(RequestIdFilter.MDC_KEY);
    }
}
