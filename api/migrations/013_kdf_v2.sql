-- Migration 013: the per-server key derivation salt (kdf.py) and each account's key derivation version.
-- create_all() adds the tables at start-up, also to existing databases; this file is for reference
-- and for databases managed by hand. No row in user_kdf means version 1.
CREATE TABLE IF NOT EXISTS server_settings (
    name  VARCHAR(64)  NOT NULL PRIMARY KEY,
    value VARCHAR(255) NOT NULL
);
CREATE TABLE IF NOT EXISTS user_kdf (
    user_id    VARCHAR(36) NOT NULL PRIMARY KEY,
    version    INT         NOT NULL,
    updated_at DATETIME    NOT NULL
);
