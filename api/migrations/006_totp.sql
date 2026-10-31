-- Migration 006: TOTP second factor.
-- New installations get the columns from create_all(); run this on existing databases.
ALTER TABLE users ADD COLUMN totp_secret_enc VARCHAR(255) NULL;
ALTER TABLE users ADD COLUMN totp_enabled BOOLEAN NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN totp_last_step BIGINT NULL;
ALTER TABLE users ADD COLUMN totp_backup_hashes TEXT NULL;
