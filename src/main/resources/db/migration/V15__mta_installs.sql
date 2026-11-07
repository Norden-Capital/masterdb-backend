-- ─────────────────────────────────────────────────────────────────────────────
-- Server management, job 4: MTA install jobs.
--
-- Installing the mail server (Postfix, Dovecot, OpenDKIM; Roundcube webmail
-- optional) on a server is a background job stored here, so it survives a
-- closed page; a backend restart marks a running job INTERRUPTED and it can
-- be run again (every step is safe to repeat). One active job per server.
-- The log is the commands' output with secrets scrubbed, capped (the newest
-- part is kept). The DKIM key is made ON the server; only its PUBLIC key is
-- read back (dkim_public_key) and handed to the domain's DNS settings.
-- ─────────────────────────────────────────────────────────────────────────────

CREATE TABLE mta_installs (
    id               BIGINT        GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    public_id        UUID          NOT NULL DEFAULT gen_random_uuid(),
    server_id        BIGINT        NOT NULL REFERENCES servers (id) ON DELETE CASCADE,
    domain_id        BIGINT        REFERENCES domains (id) ON DELETE SET NULL,
    domain_name      VARCHAR(253)  NOT NULL,
    helo_host        VARCHAR(253)  NOT NULL,
    webmail          BOOLEAN       NOT NULL DEFAULT FALSE,
    webmail_login    VARCHAR(32),
    -- QUEUED, RUNNING, SUCCEEDED, FAILED, INTERRUPTED
    status           VARCHAR(12)   NOT NULL,
    steps_total      INT           NOT NULL,
    steps_done       INT           NOT NULL DEFAULT 0,
    current_step     VARCHAR(40),
    error            VARCHAR(1000),
    log              TEXT          NOT NULL DEFAULT '',
    dkim_selector    VARCHAR(63)   NOT NULL DEFAULT 'mail',
    dkim_public_key  TEXT,
    actor_public_id  UUID,
    actor_label      VARCHAR(254),
    created_at       TIMESTAMPTZ   NOT NULL,
    started_at       TIMESTAMPTZ,
    finished_at      TIMESTAMPTZ,
    updated_at       TIMESTAMPTZ   NOT NULL,
    CONSTRAINT uq_mta_installs_public_id UNIQUE (public_id),
    CONSTRAINT chk_mta_installs_status CHECK (status IN ('QUEUED', 'RUNNING', 'SUCCEEDED', 'FAILED', 'INTERRUPTED')),
    CONSTRAINT chk_mta_installs_steps CHECK (steps_done >= 0 AND steps_done <= steps_total),
    CONSTRAINT chk_mta_installs_dkim CHECK (dkim_public_key IS NULL OR dkim_public_key ~ '^[A-Za-z0-9+/=]+$')
);

-- At most one active install per server.
CREATE UNIQUE INDEX uq_mta_installs_active ON mta_installs (server_id) WHERE status IN ('QUEUED', 'RUNNING');
CREATE INDEX idx_mta_installs_server ON mta_installs (server_id, created_at DESC);

-- The server's MTA once an install succeeded (MTA list, MTA manager).
ALTER TABLE servers
    ADD COLUMN mta_installed_at  TIMESTAMPTZ,
    ADD COLUMN mta_domain        VARCHAR(253),
    ADD COLUMN mta_webmail       BOOLEAN;
