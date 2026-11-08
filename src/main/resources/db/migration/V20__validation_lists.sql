-- ─────────────────────────────────────────────────────────────────────────────
-- List management, job 4: bulk validation on lists. A job can start from a
-- list (or one of its parts) instead of a paste: its addresses are copied from
-- list_members inside the database (no 50,000 limit, nothing goes through the
-- website), each with the member it came from, so exports can put the list's
-- own columns next to the result.
-- ─────────────────────────────────────────────────────────────────────────────

ALTER TABLE validation_jobs ADD COLUMN list_id BIGINT REFERENCES lists (id) ON DELETE SET NULL;
ALTER TABLE validation_jobs ADD COLUMN list_part INT;
CREATE INDEX idx_validation_jobs_list ON validation_jobs (list_id) WHERE list_id IS NOT NULL;

-- The list member a job address came from (no foreign key: a job's results
-- outlive the list; ids are never reused).
ALTER TABLE validation_job_emails ADD COLUMN member_id BIGINT;
CREATE INDEX idx_validation_job_emails_member ON validation_job_emails (member_id, checked_at DESC)
    WHERE member_id IS NOT NULL;
-- Big jobs: the live page's "checked per server" and "per minute" without a full scan.
CREATE INDEX idx_validation_job_emails_server ON validation_job_emails (job_id, server_id)
    WHERE category IS NOT NULL;
CREATE INDEX idx_validation_job_emails_checked ON validation_job_emails (job_id, checked_at)
    WHERE checked_at IS NOT NULL;

-- A job on a list starts as PREPARING while its addresses are copied from the
-- list in the background (a million rows take a while), then runs.
ALTER TABLE validation_jobs DROP CONSTRAINT chk_validation_jobs_status;
ALTER TABLE validation_jobs ADD CONSTRAINT chk_validation_jobs_status CHECK (status IN ('PREPARING', 'RUNNING',
    'STOPPED', 'COMPLETED'));
