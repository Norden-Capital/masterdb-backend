-- ─────────────────────────────────────────────────────────────────────────────
-- DNS management, job 1: the DNS permission module and the Namecheap account.
--
-- DNS gets VIEW, CREATE, EDIT, DELETE and RUN (Module.java). Nobody gets it
-- automatically: the Owner needs no row, everyone else is granted it in the
-- permissions editor.
--
-- One Namecheap account only: the table holds at most one row (id = 1).
-- The API key is stored encrypted by SecretCipher (ENCRYPTION_KEY, context
-- "namecheap:api-key"); it is write-only and never leaves the server.
-- ─────────────────────────────────────────────────────────────────────────────

ALTER TABLE user_permissions DROP CONSTRAINT chk_user_permissions_module;
ALTER TABLE user_permissions ADD CONSTRAINT chk_user_permissions_module CHECK (module IN ('DASHBOARD', 'CONTACTS',
    'VALIDATION', 'VALIDATION_SERVERS', 'SEGMENTS', 'SUPPRESSION', 'USERS', 'ACTIVITY_LOG', 'BACKUPS', 'SETTINGS',
    'DNS'));

CREATE TABLE namecheap_account (
    id                 SMALLINT     PRIMARY KEY DEFAULT 1,
    api_user           VARCHAR(64)  NOT NULL,
    username           VARCHAR(64)  NOT NULL,
    -- SecretCipher output: "v1:" + base64(IV + ciphertext + tag).
    api_key_enc        TEXT         NOT NULL,
    created_at         TIMESTAMPTZ  NOT NULL,
    updated_at         TIMESTAMPTZ  NOT NULL,
    -- Last "Test connection": when, whether it worked, and the message shown.
    last_test_at       TIMESTAMPTZ,
    last_test_ok       BOOLEAN,
    last_test_message  VARCHAR(300),
    CONSTRAINT chk_namecheap_account_single CHECK (id = 1),
    CONSTRAINT chk_namecheap_account_key CHECK (api_key_enc LIKE 'v1:%')
);
