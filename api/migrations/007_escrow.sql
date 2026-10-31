-- Migration 007: escrow blob for end-to-end encrypted mode.
ALTER TABLE users ADD COLUMN escrow_blob TEXT NULL;
