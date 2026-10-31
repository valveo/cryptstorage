-- Migration 001: refresh_tokens, security_events, email_verified
-- Run once against the production MariaDB database.
-- SQLAlchemy init_db() handles this automatically in development (SQLite).

CREATE TABLE IF NOT EXISTS refresh_tokens (
    id          VARCHAR(36)  PRIMARY KEY,
    token_hash  VARCHAR(64)  NOT NULL UNIQUE,
    user_id     VARCHAR(36)  NOT NULL,
    family_id   VARCHAR(36)  NOT NULL,
    revoked     BOOLEAN      NOT NULL DEFAULT FALSE,
    created_at  DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at  DATETIME     NOT NULL,
    replaced_by VARCHAR(36)  NULL,
    INDEX idx_rt_user   (user_id),
    INDEX idx_rt_family (family_id)
);

CREATE TABLE IF NOT EXISTS security_events (
    id         VARCHAR(36)   PRIMARY KEY,
    user_id    VARCHAR(36)   NULL,
    event_type VARCHAR(64)   NOT NULL,
    detail     VARCHAR(1024) NULL,
    ip_address VARCHAR(45)   NULL,
    created_at DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_se_user  (user_id),
    INDEX idx_se_event (event_type),
    INDEX idx_se_time  (created_at)
);

ALTER TABLE users ADD COLUMN IF NOT EXISTS
    email_verified BOOLEAN NOT NULL DEFAULT FALSE;
