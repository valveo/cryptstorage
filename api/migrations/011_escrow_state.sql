-- Migration 011: escrow state per user and a hash-chained log of the escrow settings.
-- create_all() adds the tables at start-up, also to existing databases; this file is for reference
-- and for databases managed by hand.
CREATE TABLE IF NOT EXISTS escrow_seals (
    user_id         VARCHAR(36) NOT NULL PRIMARY KEY,
    key_fingerprint VARCHAR(64) NOT NULL,
    sealed_at       DATETIME    NOT NULL
);
CREATE TABLE IF NOT EXISTS config_log (
    seq                    INT         NOT NULL PRIMARY KEY,
    created_at             DATETIME    NOT NULL,
    recovery_policy        VARCHAR(16) NOT NULL,
    escrow_key_fingerprint VARCHAR(64) NULL,
    prev_hash              CHAR(64)    NOT NULL,
    entry_hash             CHAR(64)    NOT NULL
);
