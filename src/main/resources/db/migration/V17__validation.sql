-- ─────────────────────────────────────────────────────────────────────────────
-- Validation, job 1: single email checks and their history, and the pacing
-- per email provider (below).
--
-- One row per check made from the "Email validation" page: the address, the
-- server it went through (with the greeting name and sender it used), the
-- category (the 6 categories of the spec), the reason in plain words, the
-- provider's own reply and the SMTP conversation (no message is ever sent:
-- it stops before DATA). Kept 90 days (app.validation.check-retention).
-- ─────────────────────────────────────────────────────────────────────────────

CREATE TABLE validation_checks (
    id               BIGINT        GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    public_id        UUID          NOT NULL DEFAULT gen_random_uuid(),
    email            VARCHAR(254)  NOT NULL,
    domain           VARCHAR(253)  NOT NULL,
    server_id        BIGINT        REFERENCES servers (id) ON DELETE SET NULL,
    server_name      VARCHAR(100)  NOT NULL,
    server_ip        VARCHAR(15)   NOT NULL,
    helo_host        VARCHAR(253)  NOT NULL,
    mail_from        VARCHAR(254)  NOT NULL,
    category         VARCHAR(12)   NOT NULL,
    smtp_code        INT           NOT NULL DEFAULT 0,
    mx_host          VARCHAR(253)  NOT NULL DEFAULT '',
    reason           VARCHAR(500)  NOT NULL,
    reply            VARCHAR(500)  NOT NULL DEFAULT '',
    transcript       TEXT          NOT NULL DEFAULT '',
    duration_ms      INT           NOT NULL,
    actor_public_id  UUID,
    actor_label      VARCHAR(254),
    created_at       TIMESTAMPTZ   NOT NULL,
    CONSTRAINT uq_validation_checks_public_id UNIQUE (public_id),
    CONSTRAINT chk_validation_checks_category CHECK (category IN
        ('VALID', 'BOUNCE', 'SOFT_BOUNCE', 'REJECT', 'CATCH_ALL', 'UNKNOWN'))
);

CREATE INDEX idx_validation_checks_created ON validation_checks (created_at DESC);
CREATE INDEX idx_validation_checks_email ON validation_checks (lower(email));

-- ─────────────────────────────────────────────────────────────────────────────
-- Pacing per email provider (spec addition 6), saved here so it survives a
-- restart. A provider is recognised by the end of its mail server's name;
-- every other mail server is paced on its own with the OTHER row's numbers.
--   gap_ms             wait between two checks of one server at this provider
--   global_gap_ms      wait between two checks at this provider, all servers together
--   rate_cooldown_s    pause after a "slow down" answer (doubles each time, up to max)
--   block_cooldown_s   pause after a "you are blocked" answer (doubles each time, up to max)
-- ─────────────────────────────────────────────────────────────────────────────

CREATE TABLE validation_providers (
    key               VARCHAR(20)   PRIMARY KEY,
    label             VARCHAR(80)   NOT NULL,
    mx_suffixes       VARCHAR(500)  NOT NULL DEFAULT '',
    gap_ms            INT           NOT NULL,
    global_gap_ms     INT           NOT NULL,
    rate_cooldown_s   INT           NOT NULL,
    block_cooldown_s  INT           NOT NULL,
    max_cooldown_s    INT           NOT NULL,
    sort_order        INT           NOT NULL,
    updated_at        TIMESTAMPTZ   NOT NULL DEFAULT now(),
    CONSTRAINT chk_validation_providers_numbers CHECK (gap_ms BETWEEN 0 AND 600000
        AND global_gap_ms BETWEEN 0 AND 600000 AND rate_cooldown_s BETWEEN 0 AND 86400
        AND block_cooldown_s BETWEEN 0 AND 86400 AND max_cooldown_s BETWEEN 0 AND 86400)
);

-- The old app's numbers (ValidationPacer): Google 5 s, Microsoft 7 s, Yahoo 9 s, others 3 s;
-- cooldown 2 min after a rate limit, 30 min after a block, doubling, at most 1 hour.
INSERT INTO validation_providers (key, label, mx_suffixes, gap_ms, global_gap_ms, rate_cooldown_s,
                                  block_cooldown_s, max_cooldown_s, sort_order) VALUES
    ('GOOGLE', 'Gmail / Google Workspace', '.google.com,.googlemail.com,.gmail.com', 5000, 1666, 120, 1800, 3600, 1),
    ('MICROSOFT', 'Outlook / Microsoft 365', '.protection.outlook.com,.outlook.com', 7000, 2333, 120, 1800, 3600, 2),
    ('YAHOO', 'Yahoo / AOL', '.yahoodns.net,.yahoo.com', 9000, 3000, 120, 1800, 3600, 3),
    ('OTHER', 'Other mail servers (each on its own)', '', 3000, 1000, 120, 1800, 3600, 4);

-- A provider cooling down for one server, after a "slow down" or "blocked" answer.
-- provider = a key above, or 'OTHER:' + the mail server's name.
CREATE TABLE validation_cooldowns (
    server_id       BIGINT        NOT NULL REFERENCES servers (id) ON DELETE CASCADE,
    provider        VARCHAR(280)  NOT NULL,
    failures        INT           NOT NULL DEFAULT 0,
    cooldown_until  TIMESTAMPTZ,
    reason          VARCHAR(500),
    updated_at      TIMESTAMPTZ   NOT NULL,
    PRIMARY KEY (server_id, provider),
    CONSTRAINT chk_validation_cooldowns_failures CHECK (failures BETWEEN 0 AND 5)
);
