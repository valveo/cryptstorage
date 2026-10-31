-- Migration 003: quota_bytes must be 64-bit.
-- The default quota (10 GB = 10737418240) does not fit MariaDB's INT (max 2147483647).
-- New installations get BIGINT from create_all(); run this on existing MariaDB databases.
ALTER TABLE users MODIFY quota_bytes BIGINT NOT NULL DEFAULT 10737418240;
