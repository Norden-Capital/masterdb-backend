-- ─────────────────────────────────────────────────────────────────────────────
-- DNS management, job 4: DNS health per domain (every domain, manual too).
--
-- One row per domain and record kind (A, MX, SPF, DKIM, DMARC, BIMI, PTR) with
-- the last result, replaced on each check. domains.health_status (V9) holds
-- the overall result for the list filter: PROBLEM if any record has one,
-- else ERROR if a lookup failed, else OK. NOT_CHECKED rows (DKIM without a
-- known selector, BIMI not set up, PTR until servers are linked) don't count.
-- ─────────────────────────────────────────────────────────────────────────────

CREATE TABLE domain_health_checks (
    domain_id   BIGINT        NOT NULL REFERENCES domains (id) ON DELETE CASCADE,
    record      VARCHAR(10)   NOT NULL,
    status      VARCHAR(12)   NOT NULL,
    detail      VARCHAR(500)  NOT NULL,
    expected    VARCHAR(2000),
    found       VARCHAR(4000),
    checked_at  TIMESTAMPTZ   NOT NULL,
    CONSTRAINT pk_domain_health_checks PRIMARY KEY (domain_id, record),
    CONSTRAINT chk_domain_health_record CHECK (record IN ('A', 'MX', 'SPF', 'DKIM', 'DMARC', 'BIMI', 'PTR')),
    CONSTRAINT chk_domain_health_status CHECK (status IN ('OK', 'PROBLEM', 'ERROR', 'NOT_CHECKED'))
);
