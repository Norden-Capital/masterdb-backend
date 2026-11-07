-- ─────────────────────────────────────────────────────────────────────────────
-- Server management, job 1: permissions, MasterDB's SSH key, and the servers.
--
-- Permissions: SERVERS and MTA, each VIEW, CREATE, EDIT, DELETE, RUN
-- (Module.java). The placeholder module VALIDATION_SERVERS (never used by an
-- endpoint) becomes SERVERS: existing grants move over unchanged.
--
-- ssh_identity: ONE ed25519 key pair for the whole app (at most one row).
-- The private key (OpenSSH format) is encrypted by SecretCipher with
-- ENCRYPTION_KEY (context "ssh:identity"); it never leaves the backend.
--
-- servers: VPSes reached over SSH with that key only (no passwords anywhere).
-- Host keys are pinned on first use: host_key_* is the trusted key; seen_*
-- is a key the server presented that waits for a decision (first connect,
-- or a CHANGED key that blocks the server until the Owner accepts it).
-- ─────────────────────────────────────────────────────────────────────────────

UPDATE user_permissions SET module = 'SERVERS' WHERE module = 'VALIDATION_SERVERS';

ALTER TABLE user_permissions DROP CONSTRAINT chk_user_permissions_module;
ALTER TABLE user_permissions ADD CONSTRAINT chk_user_permissions_module CHECK (module IN ('DASHBOARD', 'CONTACTS',
    'VALIDATION', 'SERVERS', 'MTA', 'SEGMENTS', 'SUPPRESSION', 'USERS', 'ACTIVITY_LOG', 'BACKUPS', 'SETTINGS',
    'DNS'));

CREATE TABLE ssh_identity (
    id               SMALLINT      PRIMARY KEY DEFAULT 1,
    -- "ssh-ed25519 AAAA... masterdb": what goes into authorized_keys.
    public_key       VARCHAR(500)  NOT NULL,
    fingerprint      VARCHAR(80)   NOT NULL,
    -- SecretCipher output: "v1:" + base64(IV + ciphertext + tag).
    private_key_enc  TEXT          NOT NULL,
    created_at       TIMESTAMPTZ   NOT NULL,
    CONSTRAINT chk_ssh_identity_single CHECK (id = 1),
    CONSTRAINT chk_ssh_identity_enc CHECK (private_key_enc LIKE 'v1:%')
);

CREATE TABLE servers (
    id                     BIGINT        GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    public_id              UUID          NOT NULL DEFAULT gen_random_uuid(),
    name                   VARCHAR(100)  NOT NULL,
    ip                     VARCHAR(15)   NOT NULL,
    ssh_port               INT           NOT NULL DEFAULT 22,
    ssh_user               VARCHAR(32)   NOT NULL DEFAULT 'root',
    expires_on             DATE          NOT NULL,
    notes                  VARCHAR(2000),
    -- One server per domain (it gives the domain its mail IP, job 3).
    domain_id              BIGINT        REFERENCES domains (id) ON DELETE SET NULL,
    -- NEW, KEY_PENDING, CONNECTED, AUTH_FAILED, UNREACHABLE, KEY_CHANGED
    connection_status      VARCHAR(20)   NOT NULL DEFAULT 'NEW',
    connection_message     VARCHAR(500),
    connection_checked_at  TIMESTAMPTZ,
    host_key_type          VARCHAR(40),
    host_key_fingerprint   VARCHAR(80),
    host_key               VARCHAR(4000),
    host_key_pinned_at     TIMESTAMPTZ,
    seen_key_type          VARCHAR(40),
    seen_key_fingerprint   VARCHAR(80),
    seen_key               VARCHAR(4000),
    seen_key_at            TIMESTAMPTZ,
    -- From /etc/os-release at the last successful connect.
    os_id                  VARCHAR(40),
    os_version             VARCHAR(40),
    os_name                VARCHAR(100),
    -- Root, or passwordless sudo: needed to install and control the MTA.
    privileged             BOOLEAN,
    created_at             TIMESTAMPTZ   NOT NULL,
    updated_at             TIMESTAMPTZ   NOT NULL,
    CONSTRAINT uq_servers_public_id UNIQUE (public_id),
    CONSTRAINT uq_servers_address UNIQUE (ip, ssh_port),
    CONSTRAINT chk_servers_port CHECK (ssh_port BETWEEN 1 AND 65535),
    CONSTRAINT chk_servers_status CHECK (connection_status IN ('NEW', 'KEY_PENDING', 'CONNECTED', 'AUTH_FAILED',
        'UNREACHABLE', 'KEY_CHANGED')),
    CONSTRAINT chk_servers_pin CHECK ((host_key IS NULL) = (host_key_fingerprint IS NULL))
);

CREATE UNIQUE INDEX uq_servers_domain ON servers (domain_id) WHERE domain_id IS NOT NULL;
CREATE INDEX idx_servers_expires ON servers (expires_on);
