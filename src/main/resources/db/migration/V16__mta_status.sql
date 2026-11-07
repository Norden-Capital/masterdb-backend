-- ─────────────────────────────────────────────────────────────────────────────
-- Server management, job 5: MTA list and manager.
--
-- The last status read from a server's MTA over SSH, for the MTA list:
-- {"services":[{"name":"postfix","state":"active"},...],
--  "versions":{"postfix":"3.8.6",...}, "queue":3}
-- mta_status_message says why the last read failed (null when it worked).
-- ─────────────────────────────────────────────────────────────────────────────

ALTER TABLE servers
    ADD COLUMN mta_status          JSONB,
    ADD COLUMN mta_checked_at      TIMESTAMPTZ,
    ADD COLUMN mta_status_message  VARCHAR(500);
