package ca.nordencapital.masterdb.auth.admin;

import ca.nordencapital.masterdb.auth.permission.ForbiddenException;
import ca.nordencapital.masterdb.auth.permission.Permission;
import ca.nordencapital.masterdb.auth.permission.PermissionService;
import ca.nordencapital.masterdb.auth.session.AuthPrincipal;
import ca.nordencapital.masterdb.auth.session.SessionService;
import ca.nordencapital.masterdb.auth.session.SessionService.SessionView;
import ca.nordencapital.masterdb.auth.token.AccountToken;
import ca.nordencapital.masterdb.auth.token.AccountTokenService;
import ca.nordencapital.masterdb.auth.twofactor.TwoFactorService;
import ca.nordencapital.masterdb.auth.user.Emails;
import ca.nordencapital.masterdb.auth.user.User;
import ca.nordencapital.masterdb.auth.user.UserRepository;
import ca.nordencapital.masterdb.auth.user.UserStatus;
import ca.nordencapital.masterdb.mail.AccountMails;
import ca.nordencapital.masterdb.web.error.BadRequestException;
import ca.nordencapital.masterdb.web.error.ConflictException;
import ca.nordencapital.masterdb.web.error.NotFoundException;
import ca.nordencapital.masterdb.web.request.RequestIdFilter;
import jakarta.persistence.criteria.Predicate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;
import java.util.UUID;

/**
 * Managing other people's accounts (M1.5). The controller checks the USERS
 * permission; this class adds the rules no permission can lift:
 *
 * <ul>
 *   <li>The Owner is never the target of an admin action (disable, 2FA reset,
 *       permissions, sessions): 403. Nobody can lock the Owner out.</li>
 *   <li>Nobody acts on their own account here (409): that is the account page.</li>
 *   <li>A non-owner can only grant (or take away) permissions they hold
 *       themselves (403), so USERS:EDIT cannot be turned into "everything".</li>
 * </ul>
 */
@Service
public class UserAdminService {

    private static final Logger log = LoggerFactory.getLogger(UserAdminService.class);

    private final UserRepository users;
    private final PermissionService permissions;
    private final SessionService sessions;
    private final TwoFactorService twoFactor;
    private final AccountTokenService tokens;
    private final AccountMails mails;
    private final Duration inviteTtl;
    private final Clock clock;

    public UserAdminService(UserRepository users, PermissionService permissions, SessionService sessions,
            TwoFactorService twoFactor, AccountTokenService tokens, AccountMails mails,
            @Value("${app.auth.invite-ttl:72h}") Duration inviteTtl, Clock clock) {
        this.users = users;
        this.permissions = permissions;
        this.sessions = sessions;
        this.twoFactor = twoFactor;
        this.tokens = tokens;
        this.mails = mails;
        this.inviteTtl = inviteTtl;
        this.clock = clock;
    }

    // ---- views ----------------------------------------------------------------------

    public record UserItem(UUID publicId, String email, String fullName, UserStatus status, boolean isOwner,
            boolean twoFactorEnabled, boolean locked, Instant lastLoginAt, Instant createdAt,
            Instant inviteExpiresAt) {
    }

    public record UserDetail(UserItem user, List<String> permissions, long recoveryCodesRemaining,
            List<SessionView> sessions) {
    }

    // ---- reading --------------------------------------------------------------------

    @Transactional(readOnly = true)
    public Page<UserItem> list(Pageable pageable, String query, UserStatus status) {
        Specification<User> spec = (root, cq, cb) -> {
            List<Predicate> where = new ArrayList<>();
            if (status != null) {
                where.add(cb.equal(root.get("status"), status));
            }
            if (query != null && !query.isBlank()) {
                String like = "%" + query.trim().toLowerCase(Locale.ROOT).replace("\\", "\\\\").replace("%", "\\%")
                        .replace("_", "\\_") + "%";
                where.add(cb.or(cb.like(cb.lower(root.get("email")), like, '\\'),
                        cb.like(cb.lower(root.get("fullName")), like, '\\')));
            }
            return cb.and(where.toArray(Predicate[]::new));
        };
        Page<User> page = users.findAll(spec, pageable);
        Map<Long, Instant> invites = tokens.openInviteExpiry(page.getContent().stream().map(User::getId).toList());
        return page.map(u -> item(u, invites.get(u.getId())));
    }

    @Transactional(readOnly = true)
    public UserDetail detail(UUID publicId) {
        User user = find(publicId);
        Instant invite = tokens.openInviteExpiry(List.of(user.getId())).get(user.getId());
        return new UserDetail(item(user, invite),
                permissions.effective(user).stream().map(Permission::toString).toList(),
                twoFactor.remainingRecoveryCodes(user), sessions.open(user.getId(), null));
    }

    // ---- invites --------------------------------------------------------------------

    @Transactional
    public UserItem invite(AuthPrincipal caller, String email, String fullName, Set<Permission> grants) {
        if (!Emails.isValid(email)) {
            throw BadRequestException.validation("email", "must be a valid email address");
        }
        users.findByEmail(email).ifPresent(existing -> {
            throw new ConflictException(existing.getStatus() == UserStatus.INVITED
                    ? "This person is already invited. Resend the invitation instead."
                    : "This email already has an account.");
        });
        SortedSet<Permission> wanted = Permission.withImpliedView(grants);
        requireCanGrant(caller, wanted, Set.of());
        String name = fullName == null || fullName.isBlank() ? Emails.normalize(email) : fullName.strip();
        User user = users.save(User.newInvited(email, name));
        permissions.replace(user.getId(), wanted, caller.userId());
        AccountTokenService.Issued issued = tokens.issue(user, AccountToken.Purpose.INVITE, inviteTtl,
                caller.userId());
        mails.sendInvite(user.getEmail(), fullName, caller.fullName(), issued.token(), issued.expiresAt());
        log.info("user invited: {} user={} by={} permissions={} requestId={}", Emails.mask(user.getEmail()),
                user.getPublicId(), caller.userPublicId(), wanted.size(), requestId());
        return item(user, issued.expiresAt());
    }

    @Transactional
    public UserItem resendInvite(AuthPrincipal caller, UUID publicId) {
        User user = findForUpdate(publicId);
        if (user.getStatus() != UserStatus.INVITED) {
            throw new ConflictException("Only a pending invitation can be resent.");
        }
        AccountTokenService.Issued issued = tokens.issue(user, AccountToken.Purpose.INVITE, inviteTtl,
                caller.userId());
        mails.sendInvite(user.getEmail(), user.getFullName(), caller.fullName(), issued.token(),
                issued.expiresAt());
        log.info("invite resent: {} user={} by={} requestId={}", Emails.mask(user.getEmail()), user.getPublicId(),
                caller.userPublicId(), requestId());
        return item(user, issued.expiresAt());
    }

    /** Withdraws a pending invitation: the account, never used, is removed. */
    @Transactional
    public void cancelInvite(AuthPrincipal caller, UUID publicId) {
        User user = findForUpdate(publicId);
        if (user.getStatus() != UserStatus.INVITED) {
            throw new ConflictException("Only a pending invitation can be cancelled.");
        }
        requireCanGrant(caller, Set.of(), permissions.granted(user.getId()));
        log.info("invite cancelled: {} user={} by={} requestId={}", Emails.mask(user.getEmail()), user.getPublicId(),
                caller.userPublicId(), requestId());
        users.delete(user);
    }

    // ---- status, 2FA, permissions, sessions -----------------------------------------------

    @Transactional
    public UserItem disable(AuthPrincipal caller, UUID publicId) {
        User user = target(caller, publicId);
        if (user.getStatus() != UserStatus.ACTIVE) {
            throw new ConflictException(user.getStatus() == UserStatus.INVITED
                    ? "This person has not accepted the invitation yet. Cancel it instead."
                    : "This account is already disabled.");
        }
        user.setStatus(UserStatus.DISABLED);
        int ended = sessions.revokeAll(user.getId());
        twoFactor.endChallenges(user);
        log.info("user disabled: {} user={} by={} sessionsEnded={} requestId={}", Emails.mask(user.getEmail()),
                user.getPublicId(), caller.userPublicId(), ended, requestId());
        return item(user, null);
    }

    @Transactional
    public UserItem enable(AuthPrincipal caller, UUID publicId) {
        User user = target(caller, publicId);
        if (user.getStatus() != UserStatus.DISABLED) {
            throw new ConflictException("This account is not disabled.");
        }
        user.setStatus(user.getPasswordHash() == null ? UserStatus.INVITED : UserStatus.ACTIVE);
        user.setFailedLoginAttempts(0);
        user.setLockedUntil(null);
        log.info("user enabled: {} user={} by={} requestId={}", Emails.mask(user.getEmail()), user.getPublicId(),
                caller.userPublicId(), requestId());
        return item(user, null);
    }

    /** The user must enrol again at the next sign-in; their sessions end. */
    @Transactional
    public UserItem resetTwoFactor(AuthPrincipal caller, UUID publicId) {
        User user = target(caller, publicId);
        twoFactor.reset(user);
        int ended = sessions.revokeAll(user.getId());
        log.info("2fa reset: {} user={} by={} sessionsEnded={} requestId={}", Emails.mask(user.getEmail()),
                user.getPublicId(), caller.userPublicId(), ended, requestId());
        return item(user, null);
    }

    @Transactional
    public List<String> setPermissions(AuthPrincipal caller, UUID publicId, Set<Permission> grants) {
        User user = target(caller, publicId);
        SortedSet<Permission> current = permissions.granted(user.getId());
        SortedSet<Permission> wanted = Permission.withImpliedView(grants);
        requireCanGrant(caller, wanted, current);
        SortedSet<Permission> saved = permissions.replace(user.getId(), wanted, caller.userId());
        SortedSet<Permission> added = new TreeSet<>(saved);
        added.removeAll(current);
        SortedSet<Permission> removed = new TreeSet<>(current);
        removed.removeAll(saved);
        log.info("permissions changed: {} user={} by={} added={} removed={} requestId={}",
                Emails.mask(user.getEmail()), user.getPublicId(), caller.userPublicId(), added, removed, requestId());
        return saved.stream().map(Permission::toString).toList();
    }

    @Transactional(readOnly = true)
    public List<SessionView> sessionsOf(UUID publicId) {
        return sessions.open(find(publicId).getId(), null);
    }

    @Transactional
    public void revokeSession(AuthPrincipal caller, UUID publicId, UUID sessionId) {
        User user = target(caller, publicId);
        if (!sessions.revoke(user.getId(), sessionId)) {
            throw new NotFoundException("This session was not found.");
        }
        log.info("session revoked: {} user={} session={} by={} requestId={}", Emails.mask(user.getEmail()),
                user.getPublicId(), sessionId, caller.userPublicId(), requestId());
    }

    @Transactional
    public int revokeAllSessions(AuthPrincipal caller, UUID publicId) {
        User user = target(caller, publicId);
        int ended = sessions.revokeAll(user.getId());
        log.info("sessions revoked: {} user={} count={} by={} requestId={}", Emails.mask(user.getEmail()),
                user.getPublicId(), ended, caller.userPublicId(), requestId());
        return ended;
    }

    // ---- rules ----------------------------------------------------------------------

    /** The user an admin action may change: exists, is not the Owner, is not the caller. */
    private User target(AuthPrincipal caller, UUID publicId) {
        User user = findForUpdate(publicId);
        if (user.isOwner()) {
            throw new ForbiddenException("The Owner's account cannot be changed here.");
        }
        if (user.getId().equals(caller.userId())) {
            throw new ConflictException("Use your account page to change your own account.");
        }
        return user;
    }

    /** A non-owner may only hand out, or take away, permissions they hold themselves. */
    private static void requireCanGrant(AuthPrincipal caller, Set<Permission> wanted, Set<Permission> current) {
        Set<Permission> touched = new TreeSet<>(wanted);
        Set<Permission> removed = new TreeSet<>(current);
        removed.removeAll(wanted);
        touched.addAll(removed);
        if (!caller.canAll(touched)) {
            throw new ForbiddenException("You can only grant or remove permissions you have yourself.");
        }
    }

    private User find(UUID publicId) {
        return users.findByPublicId(publicId).orElseThrow(() -> new NotFoundException("This user was not found."));
    }

    private User findForUpdate(UUID publicId) {
        return users.findByPublicIdForUpdate(publicId)
                .orElseThrow(() -> new NotFoundException("This user was not found."));
    }

    private UserItem item(User u, Instant inviteExpiresAt) {
        Instant now = clock.instant();
        boolean locked = u.getLockedUntil() != null && now.isBefore(u.getLockedUntil());
        return new UserItem(u.getPublicId(), u.getEmail(), u.getFullName(), u.getStatus(), u.isOwner(),
                u.isTwoFactorEnabled(), locked, u.getLastLoginAt(), u.getCreatedAt(), inviteExpiresAt);
    }

    private static String requestId() {
        return MDC.get(RequestIdFilter.MDC_KEY);
    }
}
