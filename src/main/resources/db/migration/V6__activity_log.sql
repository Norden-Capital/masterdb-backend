-- ─────────────────────────────────────────────────────────────────────────────
-- Activity log (M1.8): who did what to whom, from where, when.
--
-- Append-only. No foreign keys on purpose: entries outlive the accounts they
-- mention, so people are kept as public id + email (label). For a sign-in
-- attempt on an email with no account, the label is masked (j***@x.com), so
-- arbitrary input never lands here in clear. `details` is small JSON with no
-- secrets: never a password, token, code or hash. Kept one year
-- (app.activity.retention), deleted daily.
-- ─────────────────────────────────────────────────────────────────────────────

CREATE TABLE activity_log (
    id                 BIGINT        GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    occurred_at        TIMESTAMPTZ   NOT NULL DEFAULT now(),
    action             VARCHAR(50)   NOT NULL,
    actor_public_id    UUID,
    actor_label        VARCHAR(254),
    target_public_id   UUID,
    target_label       VARCHAR(254),
    ip                 VARCHAR(45),
    user_agent         VARCHAR(255),
    request_id         VARCHAR(64),
    details            JSONB         NOT NULL DEFAULT '{}'::jsonb,
    CONSTRAINT chk_activity_log_details_small CHECK (octet_length(details::text) <= 4000)
);

CREATE INDEX idx_activity_log_time ON activity_log (occurred_at DESC);
CREATE INDEX idx_activity_log_action_time ON activity_log (action, occurred_at DESC);
CREATE INDEX idx_activity_log_actor_time ON activity_log (actor_public_id, occurred_at DESC);
CREATE INDEX idx_activity_log_target_time ON activity_log (target_public_id, occurred_at DESC);
