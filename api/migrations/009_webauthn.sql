-- Migration 009: passkeys (WebAuthn) as a second factor.
-- create_all() adds the table at start-up, also to existing databases; this file is for reference
-- and for databases managed by hand.
CREATE TABLE IF NOT EXISTS webauthn_credentials (
    id              VARCHAR(36)  NOT NULL PRIMARY KEY,
    user_id         VARCHAR(36)  NOT NULL,
    credential_id   TEXT         NOT NULL,
    credential_hash VARCHAR(64)  NOT NULL UNIQUE,
    public_key      TEXT         NOT NULL,
    sign_count      BIGINT       NOT NULL DEFAULT 0,
    transports      VARCHAR(255) NULL,
    name            VARCHAR(64)  NOT NULL,
    created_at      DATETIME     NOT NULL,
    last_used_at    DATETIME     NULL
);
CREATE INDEX ix_webauthn_credentials_user_id ON webauthn_credentials (user_id);
