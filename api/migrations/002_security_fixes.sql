-- Migration 002: indexes for security queries, no schema changes needed
-- (refresh_tokens and security_events already created in migration 001)

-- Speed up theft detection query (family revocation)
CREATE INDEX IF NOT EXISTS idx_rt_family_revoked
    ON refresh_tokens (family_id, revoked);

-- Speed up active token lookup
CREATE INDEX IF NOT EXISTS idx_rt_active
    ON refresh_tokens (user_id, revoked, expires_at);

-- Speed up audit queries by event type + time
CREATE INDEX IF NOT EXISTS idx_se_event_time
    ON security_events (event_type, created_at);
