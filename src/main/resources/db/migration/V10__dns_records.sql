-- ─────────────────────────────────────────────────────────────────────────────
-- DNS management, job 3: managed records and snapshots.
--
-- Per domain, what the managed records should say (ported from the old app's
-- MTA plan: A @/mail/webmail + SPF from the mail IP, MX mail.<domain>, DKIM at
-- <selector>._domainkey, DMARC, optional BIMI). The DKIM key is a PUBLIC key,
-- pasted by the user; it is not a secret. Job 4's health check reads the same
-- columns, so manual domains may have them too.
--
-- Namecheap's setHosts replaces every record of a domain. Before each write
-- (and each restore) the records Namecheap had are saved here, so they can be
-- put back.
-- ─────────────────────────────────────────────────────────────────────────────

ALTER TABLE domains
    ADD COLUMN mail_ip               VARCHAR(15),
    ADD COLUMN dkim_selector         VARCHAR(63)  NOT NULL DEFAULT 'mail',
    ADD COLUMN dkim_public_key       TEXT,
    ADD COLUMN dmarc_policy          VARCHAR(12)  NOT NULL DEFAULT 'quarantine',
    ADD COLUMN bimi_logo_url         VARCHAR(500),
    ADD COLUMN bimi_certificate_url  VARCHAR(500),
    ADD COLUMN dns_settings_updated_at TIMESTAMPTZ,
    ADD CONSTRAINT chk_domains_dmarc CHECK (dmarc_policy IN ('none', 'quarantine', 'reject')),
    ADD CONSTRAINT chk_domains_dkim_key CHECK (dkim_public_key IS NULL OR dkim_public_key ~ '^[A-Za-z0-9+/=]+$');

CREATE TABLE dns_snapshots (
    id            BIGINT        GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    public_id     UUID          NOT NULL DEFAULT gen_random_uuid(),
    domain_id     BIGINT        NOT NULL REFERENCES domains (id) ON DELETE CASCADE,
    created_at    TIMESTAMPTZ   NOT NULL,
    -- Who wrote; labels, no FK (like the activity log), so entries outlive accounts.
    actor_public_id UUID,
    actor_label   VARCHAR(254),
    reason        VARCHAR(20)   NOT NULL,
    -- Namecheap's EmailType at the time (MX, MXE, FWD, OX, GMAIL...): sent back on restore.
    email_type    VARCHAR(20)   NOT NULL,
    record_count  INT           NOT NULL,
    -- [{"name","type","address","mxPref","ttl","flag","tag"}, ...] exactly as getHosts returned them.
    hosts         JSONB         NOT NULL,
    CONSTRAINT uq_dns_snapshots_public_id UNIQUE (public_id),
    CONSTRAINT chk_dns_snapshots_reason CHECK (reason IN ('BEFORE_SETUP', 'BEFORE_RESTORE')),
    CONSTRAINT chk_dns_snapshots_count CHECK (record_count >= 0)
);

CREATE INDEX idx_dns_snapshots_domain ON dns_snapshots (domain_id, created_at DESC);
