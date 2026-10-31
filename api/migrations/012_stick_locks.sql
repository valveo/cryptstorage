-- Migration 012: locked USB sticks, removed for good only after the change delay.
-- create_all() adds the table at start-up, also to existing databases; this file is for reference
-- and for databases managed by hand.
CREATE TABLE IF NOT EXISTS stick_locks (
    stick_id          VARCHAR(36) NOT NULL PRIMARY KEY,
    user_id           VARCHAR(36) NOT NULL,
    locked_at         DATETIME    NOT NULL,
    removal_change_id VARCHAR(36) NULL
);
CREATE INDEX ix_stick_locks_user_id ON stick_locks (user_id);
CREATE INDEX ix_stick_locks_removal_change_id ON stick_locks (removal_change_id);
