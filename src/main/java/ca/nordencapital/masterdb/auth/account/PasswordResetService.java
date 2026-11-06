package ca.nordencapital.masterdb.auth.account;

import ca.nordencapital.masterdb.activity.ActivityAction;
import ca.nordencapital.masterdb.activity.ActivityLog;
import ca.nordencapital.masterdb.activity.ActivityLog.Party;
import ca.nordencapital.masterdb.auth.password.PasswordPolicy;
import ca.nordencapital.masterdb.auth.session.SessionService;
import ca.nordencapital.masterdb.auth.token.AccountToken;
import ca.nordencapital.masterdb.auth.token.AccountTokenRepository;
import ca.nordencapital.masterdb.auth.token.AccountTokenService;
import ca.nordencapital.masterdb.auth.twofactor.TwoFactorService;
import ca.nordencapital.masterdb.auth.user.Emails;
import ca.nordencapital.masterdb.auth.user.User;
import ca.nordencapital.masterdb.auth.user.UserRepository;
import ca.nordencapital.masterdb.auth.user.UserStatus;
import ca.nordencapital.masterdb.mail.AccountMails;
import ca.nordencapital.masterdb.web.request.RequestIdFilter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.task.TaskExecutor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;

/**
 * Forgot / reset password (M1.6).
 *
 * <p><b>No user enumeration:</b> "forgot" answers the same whether the email
 * has an account or not, and the email is sent after the transaction, off the
 * request thread ({@code app.mail.async}), so the answer takes about the same
 * time either way. Only ACTIVE accounts get a link; at most one email a minute
 * per account, so the form cannot flood someone's inbox.
 *
 * <p>The link (token after {@code #}) works once, for 30 minutes
 * ({@code app.auth.reset-ttl}). A reset ends every session and any half-done
 * sign-in, lifts a lock, and does not sign in: the person then signs in with
 * the new password and their 2FA code, which a reset never bypasses.
 */
@Service
public class PasswordResetService {

    static final Duration MIN_INTERVAL = Duration.ofMinutes(1);
    private static final Logger log = LoggerFactory.getLogger(PasswordResetService.class);

    private final UserRepository users;
    private final AccountTokenService tokens;
    private final AccountTokenRepository tokenRows;
    private final AccountMails mails;
    private final PasswordEncoder encoder;
    private final SessionService sessions;
    private final TwoFactorService twoFactor;
    private final TaskExecutor executor;
    private final boolean async;
    private final Duration ttl;
    private final Clock clock;
    private final ActivityLog activity;

    public PasswordResetService(UserRepository users, AccountTokenService tokens, AccountTokenRepository tokenRows,
            AccountMails mails, PasswordEncoder encoder, SessionService sessions, TwoFactorService twoFactor,
            @Qualifier("applicationTaskExecutor") TaskExecutor executor, @Value("${app.mail.async:true}") boolean async,
            @Value("${app.auth.reset-ttl:30m}") Duration ttl, Clock clock, ActivityLog activity) {
        this.activity = activity;
        this.users = users;
        this.tokens = tokens;
        this.tokenRows = tokenRows;
        this.mails = mails;
        this.encoder = encoder;
        this.sessions = sessions;
        this.twoFactor = twoFactor;
        this.executor = executor;
        this.async = async;
        this.ttl = ttl;
        this.clock = clock;
    }

    @Transactional
    public void forgot(String email, String ip) {
        String masked = Emails.mask(email);
        Optional<User> found = Emails.isValid(email) ? users.findByEmailForUpdate(email) : Optional.empty();
        if (found.isEmpty() || found.get().getStatus() != UserStatus.ACTIVE) {
            log.info("password reset requested, no active account: {} ip={} requestId={}", masked, ip, requestId());
            return;
        }
        User user = found.get();
        Instant now = clock.instant();
        boolean recent = tokenRows.findOpen(java.util.List.of(user.getId()), AccountToken.Purpose.PASSWORD_RESET)
                .stream().anyMatch(t -> now.isBefore(t.getCreatedAt().plus(MIN_INTERVAL)));
        if (recent) {
            log.info("password reset requested again within a minute, no email: {} ip={} requestId={}", masked, ip,
                    requestId());
            return;
        }
        AccountTokenService.Issued issued = tokens.issue(user, AccountToken.Purpose.PASSWORD_RESET, ttl, null);
        String to = user.getEmail();
        String name = user.getFullName();
        log.info("password reset link issued: {} user={} ip={} requestId={}", masked, user.getPublicId(), ip,
                requestId());
        activity.record(ActivityAction.PASSWORD_RESET_REQUESTED, null, Party.of(user),
                java.util.Map.of("expiresAt", issued.expiresAt().toString()));
        Runnable send = () -> mails.sendPasswordReset(to, name, issued.token(), issued.expiresAt(), now);
        afterCommit(async ? () -> executor.execute(send) : send);
    }

    /** What the reset page shows: when the link expires. */
    @Transactional
    public Instant check(String token) {
        return usable(token).getExpiresAt();
    }

    @Transactional
    public void reset(String token, String password, String ip) {
        AccountToken reset = usable(token);
        User user = reset.getUser();
        PasswordPolicy.check("password", password, user.getEmail());
        user.setPasswordHash(encoder.encode(password));
        user.setFailedLoginAttempts(0);
        user.setLockedUntil(null);
        tokens.consume(reset);
        int ended = sessions.revokeAll(user.getId());
        twoFactor.endChallenges(user);
        log.info("password reset: {} user={} sessionsEnded={} ip={} requestId={}", Emails.mask(user.getEmail()),
                user.getPublicId(), ended, ip, requestId());
        activity.record(ActivityAction.PASSWORD_RESET, Party.of(user), Party.of(user),
                java.util.Map.of("sessionsEnded", ended));
    }

    private AccountToken usable(String token) {
        return tokens.findUsable(token, AccountToken.Purpose.PASSWORD_RESET)
                .filter(t -> t.getUser().getStatus() == UserStatus.ACTIVE)
                .orElseThrow(LinkInvalidException::new);
    }

    private static void afterCommit(Runnable action) {
        if (TransactionSynchronizationManager.isSynchronizationActive()) {
            TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
                @Override
                public void afterCommit() {
                    action.run();
                }
            });
        } else {
            action.run();
        }
    }

    private static String requestId() {
        return MDC.get(RequestIdFilter.MDC_KEY);
    }
}
