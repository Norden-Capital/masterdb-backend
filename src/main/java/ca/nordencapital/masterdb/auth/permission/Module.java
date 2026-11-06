package ca.nordencapital.masterdb.auth.permission;

import java.util.EnumSet;
import java.util.Set;

import static ca.nordencapital.masterdb.auth.permission.Action.CREATE;
import static ca.nordencapital.masterdb.auth.permission.Action.DELETE;
import static ca.nordencapital.masterdb.auth.permission.Action.EDIT;
import static ca.nordencapital.masterdb.auth.permission.Action.EXPORT;
import static ca.nordencapital.masterdb.auth.permission.Action.RUN;
import static ca.nordencapital.masterdb.auth.permission.Action.VIEW;

/**
 * The parts of MasterDB a permission is about, each with the actions that make
 * sense for it. Stored by name (V4__user_permissions.sql checks the names):
 * add new ones, never rename.
 */
public enum Module {
    CONTACTS("Contacts", EnumSet.of(VIEW, CREATE, EDIT, DELETE, EXPORT)),
    VALIDATION("Validation", EnumSet.of(VIEW, RUN, EXPORT, DELETE)),
    VALIDATION_SERVERS("Validation servers", EnumSet.of(VIEW, CREATE, EDIT, DELETE, RUN)),
    SEGMENTS("Segments", EnumSet.of(VIEW, CREATE, EDIT, DELETE, EXPORT)),
    SUPPRESSION("Suppression", EnumSet.of(VIEW, CREATE, EDIT, DELETE, EXPORT)),
    USERS("Users", EnumSet.of(VIEW, CREATE, EDIT, DELETE)),
    ACTIVITY_LOG("Activity log", EnumSet.of(VIEW, EXPORT)),
    BACKUPS("Backups", EnumSet.of(VIEW, RUN, DELETE)),
    SETTINGS("Settings", EnumSet.of(VIEW, EDIT));

    private final String label;
    private final Set<Action> actions;

    Module(String label, Set<Action> actions) {
        this.label = label;
        this.actions = actions;
    }

    public String label() {
        return label;
    }

    public Set<Action> actions() {
        return EnumSet.copyOf(actions);
    }

    public boolean supports(Action action) {
        return actions.contains(action);
    }
}
