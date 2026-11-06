package ca.nordencapital.masterdb.auth.permission;

/** What a permission allows on a {@link Module}. Stored by name: add, never rename. */
public enum Action {
    VIEW("View"),
    CREATE("Create"),
    EDIT("Edit"),
    DELETE("Delete"),
    EXPORT("Export"),
    RUN("Run");

    private final String label;

    Action(String label) {
        this.label = label;
    }

    public String label() {
        return label;
    }
}
