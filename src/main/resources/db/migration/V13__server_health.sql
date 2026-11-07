-- ─────────────────────────────────────────────────────────────────────────────
-- Server management, job 2: server health.
--
-- One row per server and check with the last result, replaced on each check:
--   SSH     MasterDB's key logs in (over SSH)
--   PORT25  the VPS can open an SMTP connection to a big mail provider (over SSH)
--   PTR     reverse DNS of the IP is the linked domain's mail host (backend)
--   DNSBL   the IP is on no common blocklist (backend; refusals are not "clean")
--   EXPIRY  the VPS plan does not end within 14 days
-- servers.health_status is the overall result for the list: PROBLEM, else
-- ERROR (a check couldn't tell), else WARNING, else OK.
-- ─────────────────────────────────────────────────────────────────────────────

ALTER TABLE servers
    ADD COLUMN health_status      VARCHAR(12),
    ADD COLUMN health_checked_at  TIMESTAMPTZ,
    ADD CONSTRAINT chk_servers_health CHECK (health_status IN ('OK', 'WARNING', 'PROBLEM', 'ERROR'));

CREATE TABLE server_health_checks (
    server_id   BIGINT        NOT NULL REFERENCES servers (id) ON DELETE CASCADE,
    check_name  VARCHAR(10)   NOT NULL,
    status      VARCHAR(12)   NOT NULL,
    detail      VARCHAR(1000) NOT NULL,
    found       VARCHAR(2000),
    checked_at  TIMESTAMPTZ   NOT NULL,
    CONSTRAINT pk_server_health_checks PRIMARY KEY (server_id, check_name),
    CONSTRAINT chk_server_health_name CHECK (check_name IN ('SSH', 'PORT25', 'PTR', 'DNSBL', 'EXPIRY')),
    CONSTRAINT chk_server_health_status CHECK (status IN ('OK', 'WARNING', 'PROBLEM', 'ERROR', 'NOT_CHECKED'))
);
