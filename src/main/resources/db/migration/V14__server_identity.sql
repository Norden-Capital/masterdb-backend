-- ─────────────────────────────────────────────────────────────────────────────
-- Server management, job 3: domain <-> server link and probe identity.
--
-- A server linked to a domain (servers.domain_id, V12) gives that domain its
-- mail server IP: the managed records (A, SPF) and the DNS health checks use
-- the server's IP instead of domains.mail_ip, and the DNS module's PTR check
-- expects the server's IP to resolve to its HELO host.
--
-- The probe identity is what Validation will greet and send as: HELO host and
-- MAIL FROM, both on the linked domain (spec addition 3: an empty sender was
-- blocked by Shaw). Defaults when a domain is linked: mail.<domain> and
-- postmaster@<domain>.
-- ─────────────────────────────────────────────────────────────────────────────

ALTER TABLE servers
    ADD COLUMN helo_host  VARCHAR(253),
    ADD COLUMN mail_from  VARCHAR(254),
    -- A deleted domain sets domain_id to NULL (V12) and leaves these behind; the app
    -- shows them only while a domain is linked and resets them on the next link.
    ADD CONSTRAINT chk_servers_identity CHECK (domain_id IS NULL OR (helo_host IS NOT NULL AND mail_from IS NOT NULL));

UPDATE servers s SET helo_host = 'mail.' || d.name, mail_from = 'postmaster@' || d.name
FROM domains d WHERE d.id = s.domain_id;
