-- ─────────────────────────────────────────────────────────────────────────────
-- Validation, job 2: bulk validation jobs.
--
-- A job validates a set of addresses (pasted for now; a list from List
-- management later) through one or more servers, in the background: closing
-- the page changes nothing and a backend restart resumes it. Each address is
-- one row in validation_job_emails; category NULL = still to check.
--
-- The counters on the job always add up to its size (check constraint):
-- pending + the six categories = total. "Retry unknown" moves the unknown rows
-- back to pending in the same job, so a retried address is never counted twice.
-- ─────────────────────────────────────────────────────────────────────────────

CREATE TABLE validation_jobs (
    id               BIGINT        GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    public_id        UUID          NOT NULL DEFAULT gen_random_uuid(),
    name             VARCHAR(120)  NOT NULL,
    -- PASTE now; LIST once List management exists.
    source           VARCHAR(10)   NOT NULL DEFAULT 'PASTE',
    -- RUNNING, STOPPED (by a user, or no server could be reached), COMPLETED
    status           VARCHAR(12)   NOT NULL,
    total            INT           NOT NULL,
    pending          INT           NOT NULL,
    valid            INT           NOT NULL DEFAULT 0,
    bounce           INT           NOT NULL DEFAULT 0,
    soft_bounce      INT           NOT NULL DEFAULT 0,
    reject           INT           NOT NULL DEFAULT 0,
    catch_all        INT           NOT NULL DEFAULT 0,
    unknown          INT           NOT NULL DEFAULT 0,
    -- Import report: lines dropped before the job started.
    duplicates       INT           NOT NULL DEFAULT 0,
    invalid          INT           NOT NULL DEFAULT 0,
    retries          INT           NOT NULL DEFAULT 0,
    -- Why it waits or stopped, in plain words (NULL while all is well).
    message          VARCHAR(500),
    actor_public_id  UUID,
    actor_label      VARCHAR(254),
    created_at       TIMESTAMPTZ   NOT NULL,
    started_at       TIMESTAMPTZ   NOT NULL,
    finished_at      TIMESTAMPTZ,
    updated_at       TIMESTAMPTZ   NOT NULL,
    CONSTRAINT uq_validation_jobs_public_id UNIQUE (public_id),
    CONSTRAINT chk_validation_jobs_status CHECK (status IN ('RUNNING', 'STOPPED', 'COMPLETED')),
    CONSTRAINT chk_validation_jobs_source CHECK (source IN ('PASTE', 'LIST')),
    CONSTRAINT chk_validation_jobs_counts CHECK (pending >= 0 AND valid >= 0 AND bounce >= 0 AND soft_bounce >= 0
        AND reject >= 0 AND catch_all >= 0 AND unknown >= 0
        AND pending + valid + bounce + soft_bounce + reject + catch_all + unknown = total)
);

CREATE INDEX idx_validation_jobs_created ON validation_jobs (created_at DESC);

-- The servers a job rotates between.
CREATE TABLE validation_job_servers (
    job_id     BIGINT  NOT NULL REFERENCES validation_jobs (id) ON DELETE CASCADE,
    server_id  BIGINT  NOT NULL REFERENCES servers (id) ON DELETE CASCADE,
    PRIMARY KEY (job_id, server_id)
);

CREATE TABLE validation_job_emails (
    id           BIGINT        GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    job_id       BIGINT        NOT NULL REFERENCES validation_jobs (id) ON DELETE CASCADE,
    seq          INT           NOT NULL,
    email        VARCHAR(254)  NOT NULL,
    -- NULL = still to check.
    category     VARCHAR(12),
    smtp_code    INT,
    mx_host      VARCHAR(253),
    reason       VARCHAR(500),
    reply        VARCHAR(500),
    server_id    BIGINT        REFERENCES servers (id) ON DELETE SET NULL,
    server_name  VARCHAR(100),
    checked_at   TIMESTAMPTZ,
    attempts     INT           NOT NULL DEFAULT 0,
    -- GOOGLE, MICROSOFT, YAHOO or OTHER:<mail server>, once known (pacing).
    provider     VARCHAR(280),
    -- The server working on it right now (NULL = free).
    claimed_by   BIGINT,
    CONSTRAINT chk_validation_job_emails_category CHECK (category IS NULL OR category IN
        ('VALID', 'BOUNCE', 'SOFT_BOUNCE', 'REJECT', 'CATCH_ALL', 'UNKNOWN'))
);

CREATE UNIQUE INDEX uq_validation_job_emails ON validation_job_emails (job_id, lower(email));
CREATE INDEX idx_validation_job_emails_todo ON validation_job_emails (job_id, seq) WHERE category IS NULL;
CREATE INDEX idx_validation_job_emails_category ON validation_job_emails (job_id, category, seq);
CREATE INDEX idx_validation_job_emails_email ON validation_job_emails (lower(email), checked_at DESC);
