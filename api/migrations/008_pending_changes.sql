-- Migration 008: delayed SSH key replacement and account deletion.
-- create_all() adds the table at start-up, also to existing databases; this file is for reference
-- and for databases managed by hand.
CREATE TABLE IF NOT EXISTS pending_changes (
    id             VARCHAR(36)  NOT NULL PRIMARY KEY,
    user_id        VARCHAR(36)  NOT NULL,
    kind           VARCHAR(16)  NOT NULL,
    ssh_public_key TEXT         NULL,
    cancel_hash    VARCHAR(64)  NOT NULL UNIQUE,
    state          VARCHAR(16)  NOT NULL DEFAULT 'pending',
    created_at     DATETIME     NOT NULL,
    due_at         DATETIME     NOT NULL,
    ip_address     VARCHAR(45)  NULL
);
CREATE INDEX ix_pending_changes_user_id ON pending_changes (user_id);
CREATE INDEX ix_pending_changes_due_at ON pending_changes (due_at);
