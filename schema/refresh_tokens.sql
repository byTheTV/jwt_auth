CREATE TABLE refresh_tokens (
    id UUID PRIMARY KEY,
    user_id TEXT NOT NULL,
    access_token_jti TEXT UNIQUE NOT NULL,
    refresh_token_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    used BOOLEAN NOT NULL DEFAULT FALSE
);