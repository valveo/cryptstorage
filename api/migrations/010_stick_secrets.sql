-- Migration 010: the server's half of the USB stick's key.
-- create_all() adds the table at start-up, also to existing databases; this file is for reference
-- and for databases managed by hand.
CREATE TABLE IF NOT EXISTS stick_secrets (
    id           VARCHAR(36) NOT NULL PRIMARY KEY,
    user_id      VARCHAR(36) NOT NULL,
    secret_enc   TEXT        NOT NULL,
    name         VARCHAR(64) NOT NULL,
    created_at   DATETIME    NOT NULL,
    last_used_at DATETIME    NULL
);
CREATE INDEX ix_stick_secrets_user_id ON stick_secrets (user_id);
