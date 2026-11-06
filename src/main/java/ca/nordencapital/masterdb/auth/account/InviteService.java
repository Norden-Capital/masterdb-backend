package ca.nordencapital.masterdb.auth.account;

import ca.nordencapital.masterdb.auth.password.PasswordPolicy;
import ca.nordencapital.masterdb.auth.token.AccountToken;
import ca.nordencapital.masterdb.auth.token.AccountTokenService;
import ca.nordencapital.masterdb.auth.twofactor.TwoFactorService;
import ca.nordencapital.masterdb.auth.user.Emails;
import ca.nordencapital.masterdb.auth.user.User;
import ca.nordencapital.masterdb.auth.user.UserStatus;
import ca.nordencapital.masterdb.web.error.BadRequestException;
import ca.nordencapital.masterdb.web.request.RequestIdFilter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;

/**
 * Accepting an invitation (no session yet): the link's token proves who it
 * is. The person sets their name and password, the account becomes ACTIVE,
 * and the 2FA enrolment step starts right away (same as a first login).
 */
@Service
public class InviteService {

    private static final Logger log = LoggerFactory.getLogger(InviteService.class);

    private final AccountTokenService tokens;
    private final PasswordEncoder encoder;
    private final TwoFactorService twoFactor;

    public InviteService(AccountTokenService tokens, PasswordEncoder encoder, TwoFactorService twoFactor) {
        this.tokens = tokens;
        this.encoder = encoder;
        this.twoFactor = twoFactor;
    }

    public record InviteInfo(String email, String fullName, Instant expiresAt) {
        @Override
        public String toString() {
            return "InviteInfo[" + Emails.mask(email) + "]";
        }
    }

    /** What the accept page shows before the form is sent. */
    @Transactional
    public InviteInfo check(String token) {
        AccountToken invite = usable(token);
        User user = invite.getUser();
        String name = user.getFullName().equals(user.getEmail()) ? null : user.getFullName();
        return new InviteInfo(user.getEmail(), name, invite.getExpiresAt());
    }

    @Transactional
    public TwoFactorService.Started accept(String token, String fullName, String password, String ip,
            String userAgent) {
        AccountToken invite = usable(token);
        User user = invite.getUser();
        if (fullName == null || fullName.isBlank() || fullName.strip().length() > 200) {
            throw BadRequestException.validation("fullName", "must be 1 to 200 characters");
        }
        PasswordPolicy.check("password", password, user.getEmail());
        user.setFullName(fullName.strip());
        user.setPasswordHash(encoder.encode(password));
        user.setStatus(UserStatus.ACTIVE);
        tokens.consume(invite);
        log.info("invite accepted: {} user={} ip={} requestId={}", Emails.mask(user.getEmail()), user.getPublicId(),
                ip, MDC.get(RequestIdFilter.MDC_KEY));
        return twoFactor.start(user, ip, userAgent);
    }

    private AccountToken usable(String token) {
        return tokens.findUsable(token, AccountToken.Purpose.INVITE)
                .filter(t -> t.getUser().getStatus() == UserStatus.INVITED)
                .orElseThrow(LinkInvalidException::new);
    }
}
