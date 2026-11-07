package ca.nordencapital.masterdb.auth.permission;

import java.util.EnumSet;
import java.util.List;
import java.util.SortedSet;
import java.util.TreeSet;

/**
 * Presets for the permissions editor: they fill the checkboxes, nothing more.
 * A user's grants are always the saved rows, never a link to a template.
 */
public final class PermissionTemplates {

    public record Template(String key, String label, String description, SortedSet<Permission> permissions) {
    }

    private static final EnumSet<Module> DATA = EnumSet.of(Module.CONTACTS, Module.VALIDATION, Module.SEGMENTS,
            Module.SUPPRESSION);

    private PermissionTemplates() {
    }

    public static List<Template> all() {
        return List.of(
                new Template("VIEWER", "Viewer", "Sees the data, changes nothing.", viewer()),
                new Template("OPERATOR", "Operator",
                        "Works with contacts, lists, validation and suppression; runs server checks.",
                        operator()),
                new Template("ADMIN", "Admin", "Everything, including users, backups and settings.",
                        Permission.all()));
    }

    private static SortedSet<Permission> viewer() {
        SortedSet<Permission> out = new TreeSet<>();
        out.add(new Permission(Module.DASHBOARD, Action.VIEW));
        DATA.forEach(m -> out.add(new Permission(m, Action.VIEW)));
        out.add(new Permission(Module.SERVERS, Action.VIEW));
        return out;
    }

    private static SortedSet<Permission> operator() {
        SortedSet<Permission> out = new TreeSet<>();
        out.add(new Permission(Module.DASHBOARD, Action.VIEW));
        DATA.forEach(m -> m.actions().forEach(a -> out.add(new Permission(m, a))));
        out.add(new Permission(Module.SERVERS, Action.VIEW));
        out.add(new Permission(Module.SERVERS, Action.RUN));
        return out;
    }
}
