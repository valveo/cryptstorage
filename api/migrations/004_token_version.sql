-- Migration 004: invalidate access tokens after a password change.
-- New installations get the column from create_all(); run this on existing databases.
ALTER TABLE users ADD COLUMN token_version INT NOT NULL DEFAULT 0;
