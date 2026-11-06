-- ─────────────────────────────────────────────────────────────────────────────
-- Sign-in sessions: one row per successful login (M1.2).
--
-- The browser holds an opaque random token in the HttpOnly cookie md_session.
-- Only its SHA-256 is stored here, so a copy of this table (a backup, a leak)
-- cannot be replayed as a cookie. Every API request looks its row up, so
-- setting revoked_at ends that sign-in at once ("log out", later "log out
-- everywhere" and the active-sessions page).
--
-- A session is usable while: revoked_at IS NULL, now < expires_at (absolute
-- limit, 7 days by default) and now < last_seen_at + idle timeout (12 h by
-- default). The timeouts are application settings (app.auth.session.*), not
-- stored per row, except the absolute end.
-- ─────────────────────────────────────────────────────────────────────────────

CREATE TABLE user_sessions (
    -- Internal key, never leaves the server.
    id            BIGINT       GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    -- The id the active-sessions page will show and act on.
    public_id     UUID         NOT NULL DEFAULT gen_random_uuid(),

    user_id       BIGINT       NOT NULL REFERENCES users (id) ON DELETE CASCADE,

    -- Lowercase hex SHA-256 of the cookie's token. Never the token itself.
    token_hash    VARCHAR(64)  NOT NULL,

    created_at    TIMESTAMPTZ  NOT NULL DEFAULT now(),
    -- Moved forward while the session is used (at most about once a minute).
    last_seen_at  TIMESTAMPTZ  NOT NULL DEFAULT now(),
    -- Absolute end: no use extends it.
    expires_at    TIMESTAMPTZ  NOT NULL,
    -- Set by logout (and later by "log out everywhere" / an admin).
    revoked_at    TIMESTAMPTZ,

    -- Where the login came from: the visitor's address as forwarded by the
    -- website (X-Client-IP, trusted only with a valid proxy secret), and the
    -- browser's User-Agent, cut to 255 characters.
    ip            VARCHAR(45),
    user_agent    VARCHAR(255),

    CONSTRAINT uq_user_sessions_public_id UNIQUE (public_id),
    CONSTRAINT uq_user_sessions_token_hash UNIQUE (token_hash),
    CONSTRAINT chk_user_sessions_token_hash CHECK (token_hash ~ '^[0-9a-f]{64}$'),
    CONSTRAINT chk_user_sessions_expiry CHECK (expires_at > created_at)
);

-- A person's open sessions (active-sessions page, "log out everywhere").
CREATE INDEX idx_user_sessions_user_open ON user_sessions (user_id) WHERE revoked_at IS NULL;
