-- Encryptor key registry — D1 schema (0001)
-- # Mr. AI Acting on s183173's Behalf
--
-- Public-key registry only: this schema MUST never hold private key
-- material. The armored column stores the ASCII-armored PUBLIC key that
-- uploaders intentionally publish. Revocation tokens are stored as
-- SHA-256 hex digests — never plaintext. Rate-limit buckets are keyed by
-- a salted hash of the client IP so raw IPs are never persisted.

CREATE TABLE IF NOT EXISTS registry_keys (
    fingerprint TEXT PRIMARY KEY,           -- 40 uppercase hex chars, no 0x
    key_id TEXT NOT NULL,                   -- primary long key ID, 16 uppercase hex
    armored TEXT NOT NULL,                  -- ASCII-armored public key (canonicalized)
    revoked INTEGER NOT NULL DEFAULT 0,     -- 0 = active, 1 = revoked (permanent)
    revoked_at INTEGER,                     -- epoch seconds of revocation
    revoke_reason TEXT,                     -- short owner-supplied reason (sanitized)
    token_hash TEXT NOT NULL,               -- SHA-256 hex of the revocation token
    created_at INTEGER NOT NULL,            -- epoch seconds of first publish
    updated_at INTEGER NOT NULL             -- epoch seconds of last change
);

CREATE INDEX IF NOT EXISTS idx_registry_keys_key_id ON registry_keys (key_id);

-- Subkey key-ID index so lookups by any subkey ID resolve to the primary.
CREATE TABLE IF NOT EXISTS registry_subkeys (
    key_id TEXT PRIMARY KEY,                -- subkey long ID, 16 uppercase hex
    fingerprint TEXT NOT NULL REFERENCES registry_keys (fingerprint) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_registry_subkeys_fingerprint ON registry_subkeys (fingerprint);

-- Email index for exact-match lookups (VKS-style). Emails are lowercased
-- on insert; only self-reported User ID addresses are stored.
CREATE TABLE IF NOT EXISTS registry_emails (
    email TEXT NOT NULL,
    fingerprint TEXT NOT NULL REFERENCES registry_keys (fingerprint) ON DELETE CASCADE,
    PRIMARY KEY (email, fingerprint)
);

CREATE INDEX IF NOT EXISTS idx_registry_emails_fingerprint ON registry_emails (fingerprint);

-- One-time challenge nonces for key-signed revocation/replacement.
CREATE TABLE IF NOT EXISTS registry_challenges (
    nonce TEXT PRIMARY KEY,                 -- 64 hex chars from CSPRNG
    fingerprint TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_registry_challenges_fingerprint ON registry_challenges (fingerprint);

-- Fixed-window rate limiter. bucket = SHA-256(salt | action | ip | window)
-- so the same IP is unlinkable across windows and the raw IP is never stored.
CREATE TABLE IF NOT EXISTS registry_rate (
    bucket TEXT PRIMARY KEY,
    count INTEGER NOT NULL,
    reset_at INTEGER NOT NULL               -- epoch seconds when the window resets
);

-- Append-only audit trail (fingerprints + actions only — no IPs, no emails).
CREATE TABLE IF NOT EXISTS registry_audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    at INTEGER NOT NULL,
    action TEXT NOT NULL,                   -- publish | revoke-token | revoke-signed | revoke-admin | replace | challenge
    fingerprint TEXT,
    detail TEXT                             -- short non-sensitive note
);
