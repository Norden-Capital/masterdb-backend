-- ─────────────────────────────────────────────────────────────────────────────
-- DNS management, job 2: domains.
--
-- A domain is added by hand (MANUAL) or imported from the Namecheap account
-- (NAMECHEAP). Names are stored normalised by the app: lowercase ASCII
-- (punycode for IDN), no trailing dot, so the unique constraint is exact.
-- The nc_* columns are Namecheap's metadata from namecheap.domains.getList,
-- refreshed on each import; MANUAL domains leave them empty.
-- ─────────────────────────────────────────────────────────────────────────────

CREATE TABLE domains (
    id                     BIGINT        GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    public_id              UUID          NOT NULL DEFAULT gen_random_uuid(),
    name                   VARCHAR(253)  NOT NULL,
    source                 VARCHAR(20)   NOT NULL,
    nc_created             DATE,
    nc_expires             DATE,
    nc_expired             BOOLEAN,
    nc_locked              BOOLEAN,
    nc_auto_renew          BOOLEAN,
    -- Namecheap's IsOurDNS: records can only be written when the domain uses Namecheap DNS.
    nc_uses_namecheap_dns  BOOLEAN,
    nc_synced_at           TIMESTAMPTZ,
    -- Result of the last DNS health check (job 4): OK, PROBLEM, ERROR; NULL = never checked.
    health_status          VARCHAR(20),
    health_checked_at      TIMESTAMPTZ,
    created_at             TIMESTAMPTZ   NOT NULL DEFAULT now(),
    updated_at             TIMESTAMPTZ   NOT NULL DEFAULT now(),
    CONSTRAINT uq_domains_public_id UNIQUE (public_id),
    CONSTRAINT uq_domains_name UNIQUE (name),
    CONSTRAINT chk_domains_name CHECK (name = lower(name) AND name NOT LIKE '%.' AND length(name) >= 4),
    CONSTRAINT chk_domains_source CHECK (source IN ('MANUAL', 'NAMECHEAP')),
    CONSTRAINT chk_domains_health CHECK (health_status IN ('OK', 'PROBLEM', 'ERROR'))
);

CREATE INDEX idx_domains_expires ON domains (nc_expires);
CREATE INDEX idx_domains_created ON domains (created_at DESC);
