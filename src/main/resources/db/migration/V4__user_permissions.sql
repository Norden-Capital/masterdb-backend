-- ─────────────────────────────────────────────────────────────────────────────
-- Custom permissions (M1.4): per-user grants on module × action.
--
-- The Owner needs no rows: it may do everything. Everyone else may do exactly
-- what is granted here. Names match the Java enums Module and Action; which
-- actions a module has is decided in Module.java (the catalogue endpoint).
-- Any action on a module implies VIEW of it; the application saves that row too.
-- ─────────────────────────────────────────────────────────────────────────────

CREATE TABLE user_permissions (
    user_id     BIGINT       NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    module      VARCHAR(30)  NOT NULL,
    action      VARCHAR(20)  NOT NULL,
    granted_at  TIMESTAMPTZ  NOT NULL DEFAULT now(),
    -- Who granted it; NULL once that account is deleted.
    granted_by  BIGINT       REFERENCES users (id) ON DELETE SET NULL,
    CONSTRAINT pk_user_permissions PRIMARY KEY (user_id, module, action),
    CONSTRAINT chk_user_permissions_module CHECK (module IN ('CONTACTS', 'VALIDATION', 'VALIDATION_SERVERS',
        'SEGMENTS', 'SUPPRESSION', 'USERS', 'ACTIVITY_LOG', 'BACKUPS', 'SETTINGS')),
    CONSTRAINT chk_user_permissions_action CHECK (action IN ('VIEW', 'CREATE', 'EDIT', 'DELETE', 'EXPORT', 'RUN'))
);
