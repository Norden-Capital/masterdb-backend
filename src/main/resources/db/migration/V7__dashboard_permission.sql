-- ─────────────────────────────────────────────────────────────────────────────
-- Dashboard permission (M2.4): DASHBOARD:VIEW, for the counts on the start page.
--
-- Until now the start page showed no data, so everybody could open it. People
-- who already have an account keep seeing it: they get DASHBOARD:VIEW here.
-- New people get it through the permission templates or the editor, like any
-- other permission. The Owner needs no row.
-- ─────────────────────────────────────────────────────────────────────────────

ALTER TABLE user_permissions DROP CONSTRAINT chk_user_permissions_module;
ALTER TABLE user_permissions ADD CONSTRAINT chk_user_permissions_module CHECK (module IN ('DASHBOARD', 'CONTACTS',
    'VALIDATION', 'VALIDATION_SERVERS', 'SEGMENTS', 'SUPPRESSION', 'USERS', 'ACTIVITY_LOG', 'BACKUPS', 'SETTINGS'));

INSERT INTO user_permissions (user_id, module, action)
SELECT id, 'DASHBOARD', 'VIEW' FROM users WHERE NOT is_owner
ON CONFLICT DO NOTHING;
