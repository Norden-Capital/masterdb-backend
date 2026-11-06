package ca.nordencapital.masterdb.auth.permission;

import java.util.Comparator;
import java.util.EnumSet;
import java.util.Objects;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;

/** One module × action pair, written {@code MODULE:ACTION} in the API ("CONTACTS:EXPORT"). */
public record Permission(Module module, Action action) implements Comparable<Permission> {

    private static final Comparator<Permission> ORDER =
            Comparator.comparing(Permission::module).thenComparing(Permission::action);

    public Permission {
        Objects.requireNonNull(module, "module");
        Objects.requireNonNull(action, "action");
        if (!module.supports(action)) {
            throw new IllegalArgumentException(module + " has no " + action + " action");
        }
    }

    /** Parses {@code MODULE:ACTION}; throws IllegalArgumentException for anything else. */
    public static Permission parse(String value) {
        if (value == null) {
            throw new IllegalArgumentException("permission is null");
        }
        int colon = value.indexOf(':');
        if (colon < 0) {
            throw new IllegalArgumentException("not MODULE:ACTION");
        }
        return new Permission(Module.valueOf(value.substring(0, colon).trim()),
                Action.valueOf(value.substring(colon + 1).trim()));
    }

    /** Every permission there is: what the Owner holds. */
    public static SortedSet<Permission> all() {
        SortedSet<Permission> all = new TreeSet<>();
        for (Module m : Module.values()) {
            for (Action a : m.actions()) {
                all.add(new Permission(m, a));
            }
        }
        return all;
    }

    /**
     * Any action on a module implies VIEW of it: nobody can edit or export what
     * they cannot see. Applied when grants are saved.
     */
    public static SortedSet<Permission> withImpliedView(Set<Permission> grants) {
        SortedSet<Permission> out = new TreeSet<>(grants);
        EnumSet<Module> touched = EnumSet.noneOf(Module.class);
        grants.forEach(p -> touched.add(p.module()));
        touched.forEach(m -> out.add(new Permission(m, Action.VIEW)));
        return out;
    }

    @Override
    public int compareTo(Permission other) {
        return ORDER.compare(this, other);
    }

    @Override
    public String toString() {
        return module.name() + ":" + action.name();
    }
}
