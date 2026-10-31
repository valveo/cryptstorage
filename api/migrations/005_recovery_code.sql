-- Migration 005: recovery codes (a second wrapping of the master key).
-- New installations get the column from create_all(); run this on existing databases.
-- Existing users have none until they generate one (POST /users/me/recovery-code).
ALTER TABLE users ADD COLUMN recovery_encrypted_master_key VARCHAR(255) NULL;
