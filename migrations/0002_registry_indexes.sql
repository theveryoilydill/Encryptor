-- Registry performance indexes (0002) — review follow-ups
-- # Mr. AI Acting on s183173's Behalf
--
-- The rate-limiter cleanup and challenge expiry purges previously forced
-- full table scans (each scan counts against the D1 rows-read quota).

CREATE INDEX IF NOT EXISTS idx_registry_rate_reset_at ON registry_rate (reset_at);

CREATE INDEX IF NOT EXISTS idx_registry_challenges_expires_at ON registry_challenges (expires_at);
