-- Encryptor key registry — name index (0006)
-- # Mr. AI Acting on s183173's Behalf
--
-- Owner feedback: restore/sign-in must work with "fingerprint, email, or
-- name". Emails already had a dedicated exact-match index (registry_emails);
-- names get the same treatment so lookups stay O(log n) instead of scanning
-- armored blobs.
--
-- What counts as a "name": the display part of a self-reported User ID
-- ("Alice Example <alice@example.com>" → "alice example"), normalized by
-- src/lib/registry/keys.ts#extractNames (trimmed, whitespace-collapsed,
-- lowercased). Names are NOT unique — unlike emails there is no collision
-- policy; a name lookup may legitimately return several keys and the UI
-- already renders a picker for that case. No private material, ever.

CREATE TABLE IF NOT EXISTS registry_names (
    name TEXT NOT NULL,
    fingerprint TEXT NOT NULL REFERENCES registry_keys (fingerprint) ON DELETE CASCADE,
    PRIMARY KEY (name, fingerprint)
);

CREATE INDEX IF NOT EXISTS idx_registry_names_fingerprint ON registry_names (fingerprint);
