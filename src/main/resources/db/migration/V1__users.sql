-- ─────────────────────────────────────────────────────────────────────────────
-- People who can sign in to MasterDB.
--
-- Only the accounts themselves. Two-factor, permissions, invites, sessions and
-- the activity log each get their own migration with their own task, and hang
-- off users.id. Permissions will be per-user grants on modules x actions in a
-- separate table (user_id, module, action); the Owner needs no grants, it sees
-- everything (is_owner below).
-- ─────────────────────────────────────────────────────────────────────────────

CREATE TABLE users (
    -- Internal key for foreign keys and joins. Never leaves the server: it
    -- would tell anyone how many accounts exist and invite trying the next one.
    id                    BIGINT       GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    -- The only id the API ever shows (addresses, JSON). Random, so it says
    -- nothing and cannot be guessed. The application sets it; the default
    -- covers rows written by hand in SQL.
    public_id             UUID         NOT NULL DEFAULT gen_random_uuid(),

    -- Login identity. The application always stores it trimmed and lowercased
    -- (User.normalizeEmail); the unique index below is on lower(email), so even
    -- a row written by hand as "Jane@X.com" cannot sit next to "jane@x.com".
    -- Plain text + lower() rather than the citext extension: no extension to
    -- install, and Hibernate's schema validation knows varchar but not citext.
    -- 254 = the longest address SMTP can carry.
    email                 VARCHAR(254) NOT NULL,

    full_name             VARCHAR(200) NOT NULL,

    -- "{bcrypt}$2a$12$..." (DelegatingPasswordEncoder: the prefix names the
    -- algorithm, so a stronger one can be added later without a migration).
    -- NULL only for an invited person who has not chosen a password yet.
    password_hash         VARCHAR(255),

    status                VARCHAR(20)  NOT NULL DEFAULT 'INVITED',

    -- The Owner sees and may do everything, with no grants needed. At most one
    -- (index below), enforced by the database rather than trusted to the code.
    is_owner              BOOLEAN      NOT NULL DEFAULT FALSE,

    -- Login protection (used by the login task).
    failed_login_attempts INTEGER      NOT NULL DEFAULT 0,
    locked_until          TIMESTAMPTZ,
    last_login_at         TIMESTAMPTZ,

    created_at            TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at            TIMESTAMPTZ  NOT NULL DEFAULT now(),

    CONSTRAINT uq_users_public_id UNIQUE (public_id),
    CONSTRAINT chk_users_status
        CHECK (status IN ('ACTIVE', 'INVITED', 'DISABLED')),
    -- An account that can sign in has a password. Invited (and invited, then
    -- disabled) accounts may not have one yet.
    CONSTRAINT chk_users_active_has_password
        CHECK (status <> 'ACTIVE' OR password_hash IS NOT NULL),
    -- The Owner can never be disabled or left half-invited: that would leave
    -- nobody able to manage the others.
    CONSTRAINT chk_users_owner_active
        CHECK (NOT is_owner OR status = 'ACTIVE'),
    CONSTRAINT chk_users_failed_login_attempts
        CHECK (failed_login_attempts >= 0)
);

-- One account per address, whatever its case.
CREATE UNIQUE INDEX uq_users_email_lower ON users (lower(email));

-- At most one Owner. A unique index on a constant, limited to the Owner's row,
-- admits one row and refuses a second.
CREATE UNIQUE INDEX uq_users_single_owner ON users ((TRUE)) WHERE is_owner;
