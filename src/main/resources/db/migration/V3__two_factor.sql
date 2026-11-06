-- ─────────────────────────────────────────────────────────────────────────────
-- Two-factor sign-in (M1.3): TOTP, mandatory for everyone.
--
-- Login is two steps. The password opens a short-lived login_challenges row
-- (its token in the HttpOnly cookie md_preauth); the authenticator code (or a
-- recovery code) closes it and only then is a user_sessions row created. A
-- user without 2FA gets a SETUP challenge instead and must enrol first.
-- ─────────────────────────────────────────────────────────────────────────────

-- The authenticator secret, AES-256-GCM encrypted with ENCRYPTION_KEY
-- ("v1:" + base64), bound to the user id. NULL = not enrolled yet.
ALTER TABLE users ADD COLUMN totp_secret_enc     VARCHAR(200);
ALTER TABLE users ADD COLUMN totp_enabled_at     TIMESTAMPTZ;
-- The 30-second step of the last accepted code: a code is accepted once.
ALTER TABLE users ADD COLUMN totp_last_used_step BIGINT;
ALTER TABLE users ADD CONSTRAINT chk_users_totp_enrolled
    CHECK ((totp_secret_enc IS NULL) = (totp_enabled_at IS NULL));

-- Ten one-time codes for a lost phone, shown once. Stored as a keyed hash
-- (HMAC with a key derived from ENCRYPTION_KEY), never in clear.
CREATE TABLE recovery_codes (
    id          BIGINT       GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id     BIGINT       NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    code_hash   VARCHAR(64)  NOT NULL,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT now(),
    used_at     TIMESTAMPTZ,
    CONSTRAINT uq_recovery_codes_hash UNIQUE (code_hash)
);
CREATE INDEX idx_recovery_codes_user ON recovery_codes (user_id);

-- The state between "password right" and "code right". Short-lived (10 min),
-- a few attempts, single use. Only the token's SHA-256 is stored.
CREATE TABLE login_challenges (
    id                  BIGINT       GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id             BIGINT       NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    token_hash          VARCHAR(64)  NOT NULL,
    -- VERIFY: enrolled, asks for a code. SETUP: must enrol first.
    purpose             VARCHAR(10)  NOT NULL,
    -- SETUP only: the secret being enrolled, encrypted like totp_secret_enc.
    pending_secret_enc  VARCHAR(200),
    attempts            INTEGER      NOT NULL DEFAULT 0,
    created_at          TIMESTAMPTZ  NOT NULL DEFAULT now(),
    expires_at          TIMESTAMPTZ  NOT NULL,
    used_at             TIMESTAMPTZ,
    ip                  VARCHAR(45),
    user_agent          VARCHAR(255),
    CONSTRAINT uq_login_challenges_token_hash UNIQUE (token_hash),
    CONSTRAINT chk_login_challenges_purpose CHECK (purpose IN ('VERIFY', 'SETUP')),
    CONSTRAINT chk_login_challenges_attempts CHECK (attempts >= 0)
);
CREATE INDEX idx_login_challenges_user ON login_challenges (user_id);
