-- ─────────────────────────────────────────────────────────────────────────────
-- One-time links sent by email (M1.5 invites, M1.6 password resets).
--
-- The link carries a random 256-bit token after '#', so it never reaches a
-- server log; only its SHA-256 is stored. Single use (used_at), expires
-- (expires_at), and can be withdrawn (revoked_at: invite cancelled or resent,
-- a newer reset requested).
-- ─────────────────────────────────────────────────────────────────────────────

CREATE TABLE account_tokens (
    id          BIGINT       GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id     BIGINT       NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    purpose     VARCHAR(20)  NOT NULL,
    token_hash  VARCHAR(64)  NOT NULL,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT now(),
    expires_at  TIMESTAMPTZ  NOT NULL,
    used_at     TIMESTAMPTZ,
    revoked_at  TIMESTAMPTZ,
    -- Who sent it (the inviter); NULL for a self-service reset.
    created_by  BIGINT       REFERENCES users (id) ON DELETE SET NULL,
    CONSTRAINT uq_account_tokens_hash UNIQUE (token_hash),
    CONSTRAINT chk_account_tokens_purpose CHECK (purpose IN ('INVITE', 'PASSWORD_RESET')),
    CONSTRAINT chk_account_tokens_expiry CHECK (expires_at > created_at)
);
CREATE INDEX idx_account_tokens_user_open ON account_tokens (user_id, purpose)
    WHERE used_at IS NULL AND revoked_at IS NULL;
