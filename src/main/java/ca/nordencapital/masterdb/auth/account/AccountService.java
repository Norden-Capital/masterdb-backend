package ca.nordencapital.masterdb.auth.account;

import ca.nordencapital.masterdb.activity.ActivityAction;
import ca.nordencapital.masterdb.activity.ActivityLog;
import ca.nordencapital.masterdb.activity.ActivityLog.Party;
import ca.nordencapital.masterdb.auth.AuthProperties;
import ca.nordencapital.masterdb.auth.password.PasswordConfig;
import ca.nordencapital.masterdb.auth.password.PasswordPolicy;
import ca.nordencapital.masterdb.auth.session.AuthPrincipal;
import ca.nordencapital.masterdb.auth.session.SessionService;
import ca.nordencapital.masterdb.auth.session.SessionService.SessionView;
import ca.nordencapital.masterdb.auth.twofactor.TwoFactorService;
import ca.nordencapital.masterdb.auth.user.Emails;
import ca.nordencapital.masterdb.auth.user.User;
import ca.nordencapital.masterdb.auth.user.UserRepository;
import ca.nordencapital.masterdb.web.error.ApiException;
import ca.nordencapital.masterdb.web.error.ErrorCode;
import ca.nordencapital.masterdb.web.error.NotFoundException;
import ca.nordencapital.masterdb.web.request.RequestIdFilter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.annotation.Propagation;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/** The signed-in user's own account: password, sessions, recovery codes. */
@Service
public class AccountService {

    private static final Logger log = LoggerFactory.getLogger(AccountService.class);

    private final UserRepository users;
    private final PasswordEncoder encoder;
    private final SessionService sessions;
    private final TwoFactorService twoFactor;
    private final AuthProperties.Lockout lockout;
    private final Clock clock;
    private final ActivityLog activity;

    public AccountService(UserRepository users, PasswordEncoder encoder, SessionService sessions,
            TwoFactorService twoFactor, AuthProperties properties, Clock clock, ActivityLog activity) {
        this.activity = activity;
        this.users = users;
        this.encoder = encoder;
        this.sessions = sessions;
        this.twoFactor = twoFactor;
        this.lockout = properties.lockout();
        this.clock = clock;
    }

    public record TwoFactorStatus(boolean enabled, Instant enabledAt, long recoveryCodesRemaining) {
    }

    /** 400 {@code CURRENT_PASSWORD_INCORRECT}. */
    public static final class CurrentPasswordIncorrect extends ApiException {
        CurrentPasswordIncorrect() {
            super(HttpStatus.BAD_REQUEST, ErrorCode.CURRENT_PASSWORD_INCORRECT, "Your current password is incorrect.",
                    null);
        }
    }

    /** 400 {@code INVALID_TWO_FACTOR_CODE} (in-session re-check: 400, not 401, the session is fine). */
    public static final class CodeIncorrect extends ApiException {
        CodeIncorrect() {
            super(HttpStatus.BAD_REQUEST, ErrorCode.INVALID_TWO_FACTOR_CODE,
                    "The code is incorrect or was already used.", null);
        }
    }

    /**
     * Changes the password after re-checking the current one; every other
     * session ends. A wrong current password counts towards the account lock;
     * reaching it ends every session (whoever holds this one must sign in again).
     */
    @Transactional(noRollbackFor = CurrentPasswordIncorrect.class)
    public void changePassword(AuthPrincipal me, String current, String next) {
        User user = lock(me);
        boolean right = current != null
                && current.getBytes(StandardCharsets.UTF_8).length <= PasswordConfig.MAX_BYTES
                && user.getPasswordHash() != null && encoder.matches(current, user.getPasswordHash());
        if (!right) {
            int failures = user.getFailedLoginAttempts() + 1;
            user.setFailedLoginAttempts(failures);
            if (failures >= lockout.maxAttempts()) {
                user.setLockedUntil(clock.instant().plus(lockout.duration()));
                sessions.revokeAll(user.getId());
                activity.record(ActivityAction.ACCOUNT_LOCKED, Party.of(user), Party.of(user),
                        Map.of("reason", "current_password_wrong", "attempts", failures));
                log.info("password change refused, account locked, sessions ended: {} user={} requestId={}",
                        Emails.mask(user.getEmail()), user.getPublicId(), requestId());
            } else {
                log.info("password change refused (current password wrong): {} user={} attempts={} requestId={}",
                        Emails.mask(user.getEmail()), user.getPublicId(), failures, requestId());
            }
            throw new CurrentPasswordIncorrect();
        }
        PasswordPolicy.check("newPassword", next, user.getEmail());
        user.setPasswordHash(encoder.encode(next));
        user.setFailedLoginAttempts(0);
        int ended = sessions.revokeOthers(user.getId(), me.sessionId());
        twoFactor.endChallenges(user);
        log.info("password changed: {} user={} otherSessionsEnded={} requestId={}", Emails.mask(user.getEmail()),
                user.getPublicId(), ended, requestId());
        activity.record(ActivityAction.PASSWORD_CHANGED, Party.of(user), Party.of(user),
                Map.of("otherSessionsEnded", ended));
    }

    public List<SessionView> sessions(AuthPrincipal me) {
        return sessions.open(me.userId(), me.sessionId());
    }

    @Transactional
    public void revokeSession(AuthPrincipal me, UUID sessionId) {
        if (!sessions.revoke(me.userId(), sessionId)) {
            throw new NotFoundException("This session was not found.");
        }
        log.info("session revoked: {} user={} session={} by=self requestId={}", Emails.mask(me.email()),
                me.userPublicId(), sessionId, requestId());
        activity.record(ActivityAction.SESSION_REVOKED, Party.of(me), Party.of(me), Map.of("session", sessionId.toString()));
    }

    @Transactional
    public int revokeOtherSessions(AuthPrincipal me) {
        int ended = sessions.revokeOthers(me.userId(), me.sessionId());
        log.info("other sessions revoked: {} user={} count={} requestId={}", Emails.mask(me.email()),
                me.userPublicId(), ended, requestId());
        activity.record(ActivityAction.SESSIONS_REVOKED, Party.of(me), Party.of(me),
                Map.of("count", ended, "scope", "others"));
        return ended;
    }

    /** "Log out everywhere", this browser included. */
    @Transactional
    public int logoutEverywhere(AuthPrincipal me) {
        int ended = sessions.revokeAll(me.userId());
        log.info("logout everywhere: {} user={} count={} requestId={}", Emails.mask(me.email()), me.userPublicId(),
                ended, requestId());
        activity.record(ActivityAction.SESSIONS_REVOKED, Party.of(me), Party.of(me),
                Map.of("count", ended, "scope", "everywhere"));
        return ended;
    }

    @Transactional(readOnly = true)
    public TwoFactorStatus twoFactorStatus(AuthPrincipal me) {
        User user = users.findById(me.userId()).orElseThrow();
        return new TwoFactorStatus(user.isTwoFactorEnabled(), user.getTotpEnabledAt(),
                twoFactor.remainingRecoveryCodes(user));
    }

    /** New recovery codes, after a current authenticator code. The old ones stop working. */
    @Transactional
    public List<String> regenerateRecoveryCodes(AuthPrincipal me, String code) {
        User user = lock(me);
        if (!twoFactor.checkCurrentCode(user, code)) {
            throw new CodeIncorrect();
        }
        List<String> codes = twoFactor.regenerateRecoveryCodes(user);
        log.info("recovery codes regenerated: {} user={} requestId={}", Emails.mask(user.getEmail()),
                user.getPublicId(), requestId());
        activity.record(ActivityAction.RECOVERY_CODES_REGENERATED, Party.of(user), Party.of(user));
        return codes;
    }

    @Transactional(propagation = Propagation.MANDATORY)
    User lock(AuthPrincipal me) {
        return users.findByPublicIdForUpdate(me.userPublicId()).orElseThrow();
    }

    private static String requestId() {
        return MDC.get(RequestIdFilter.MDC_KEY);
    }
}
