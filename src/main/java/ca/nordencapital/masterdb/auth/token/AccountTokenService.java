package ca.nordencapital.masterdb.auth.token;

import ca.nordencapital.masterdb.auth.session.SessionTokens;
import ca.nordencapital.masterdb.auth.user.User;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * Issues and redeems one-time emailed links. A new link of the same purpose
 * withdraws the user's older open ones, so only the latest email works.
 */
@Service
public class AccountTokenService {

    private final AccountTokenRepository tokens;
    private final Clock clock;

    public AccountTokenService(AccountTokenRepository tokens, Clock clock) {
        this.tokens = tokens;
        this.clock = clock;
    }

    /** The raw token goes into the email only; it is never stored or logged. */
    public record Issued(String token, Instant expiresAt) {
        @Override
        public String toString() {
            return "Issued[" + expiresAt + "]";
        }
    }

    @Transactional(propagation = Propagation.MANDATORY)
    public Issued issue(User user, AccountToken.Purpose purpose, Duration ttl, Long createdBy) {
        Instant now = clock.instant();
        tokens.revokeOpen(user.getId(), purpose, now);
        String token = SessionTokens.generate();
        AccountToken saved = tokens.save(AccountToken.issue(user, purpose, SessionTokens.hash(token), now,
                now.plus(ttl), createdBy));
        return new Issued(token, saved.getExpiresAt());
    }

    /** The usable token (row locked), or empty for unknown, used, withdrawn or expired ones. */
    @Transactional(propagation = Propagation.MANDATORY)
    public Optional<AccountToken> findUsable(String token, AccountToken.Purpose purpose) {
        if (!SessionTokens.isWellFormed(token)) {
            return Optional.empty();
        }
        Instant now = clock.instant();
        return tokens.findForUpdate(SessionTokens.hash(token))
                .filter(t -> t.getPurpose() == purpose)
                .filter(t -> t.isUsable(now));
    }

    @Transactional(propagation = Propagation.MANDATORY)
    public void consume(AccountToken token) {
        Instant now = clock.instant();
        token.use(now);
        tokens.revokeOpen(token.getUser().getId(), token.getPurpose(), now);
    }

    @Transactional(propagation = Propagation.MANDATORY)
    public void revokeOpen(User user, AccountToken.Purpose purpose) {
        tokens.revokeOpen(user.getId(), purpose, clock.instant());
    }

    /** When each user's open invite expires (users without one are absent). */
    @Transactional(readOnly = true)
    public Map<Long, Instant> openInviteExpiry(List<Long> userIds) {
        if (userIds.isEmpty()) {
            return Map.of();
        }
        return tokens.findOpen(userIds, AccountToken.Purpose.INVITE).stream()
                .collect(Collectors.toMap(t -> t.getUser().getId(), AccountToken::getExpiresAt, (a, b) -> a.isAfter(b) ? a : b));
    }
}
