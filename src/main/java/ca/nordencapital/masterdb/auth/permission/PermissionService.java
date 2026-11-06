package ca.nordencapital.masterdb.auth.permission;

import ca.nordencapital.masterdb.auth.user.User;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Instant;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;

/** Reads and replaces a user's grants. */
@Service
public class PermissionService {

    private final UserPermissionRepository grants;
    private final Clock clock;

    public PermissionService(UserPermissionRepository grants, Clock clock) {
        this.grants = grants;
        this.clock = clock;
    }

    /** What the user may do: everything for the Owner, otherwise their grants. */
    @Transactional(readOnly = true)
    public SortedSet<Permission> effective(User user) {
        return effective(user.getId(), user.isOwner());
    }

    @Transactional(readOnly = true)
    public SortedSet<Permission> effective(Long userId, boolean owner) {
        return owner ? Permission.all() : granted(userId);
    }

    /** The user's stored grants (for the Owner: none, it needs none). */
    @Transactional(readOnly = true)
    public SortedSet<Permission> granted(Long userId) {
        SortedSet<Permission> out = new TreeSet<>();
        grants.findByUserId(userId).forEach(g -> out.add(g.permission()));
        return out;
    }

    /**
     * Replaces all of a user's grants (VIEW implied by any other action is
     * added). Returns what was saved. Who may do this is the caller's check.
     */
    @Transactional
    public SortedSet<Permission> replace(Long userId, Set<Permission> wanted, Long grantedBy) {
        SortedSet<Permission> saved = Permission.withImpliedView(wanted);
        grants.deleteByUserId(userId);
        Instant now = clock.instant();
        saved.forEach(p -> grants.save(new UserPermission(userId, p, now, grantedBy)));
        return saved;
    }
}
