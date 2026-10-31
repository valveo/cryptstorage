-- Migration 009: one synchronisation at a time per volume (docs/design-features.md section 5.1).
-- create_all() adds the table at start-up, also to existing databases; this file is for reference
-- and for databases managed by hand.
CREATE TABLE IF NOT EXISTS sync_locks (
    user_id     VARCHAR(36) NOT NULL,
    volume      VARCHAR(64) NOT NULL,
    holder      VARCHAR(64) NOT NULL,
    holder_name VARCHAR(64) NULL,
    expires_at  DATETIME    NOT NULL,
    PRIMARY KEY (user_id, volume)
);
