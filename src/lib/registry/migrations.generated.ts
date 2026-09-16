/**
 * GENERATED FILE — do not edit by hand.
 * Source of truth: migrations/*.sql via scripts/gen-migrations.mjs
 * Re-run `node scripts/gen-migrations.mjs` after adding a migration.
 *
 * Bundled so the worker can self-migrate a fresh D1 database on first
 * access (Workers Builds CI never runs wrangler d1 migrations apply).
 *
 * STATEMENT SPLIT CONSTRAINT (fallback path only): the SQL must not contain
 * a ";" inside string literals or comments — every current migration is
 * pure DDL and satisfies this. The primary path uses D1's native exec().
 *
 * # Mr. AI Acting on s183173's Behalf
 */
export const REGISTRY_MIGRATIONS: readonly { readonly id: string; readonly sql: string }[] = [
	{
		id: "0001_registry",
		sql: "-- Encryptor key registry — D1 schema (0001)\n-- # Mr. AI Acting on s183173's Behalf\n--\n-- Public-key registry only: this schema MUST never hold private key\n-- material. The armored column stores the ASCII-armored PUBLIC key that\n-- uploaders intentionally publish. Revocation tokens are stored as\n-- SHA-256 hex digests — never plaintext. Rate-limit buckets are keyed by\n-- a salted hash of the client IP so raw IPs are never persisted.\n\nCREATE TABLE IF NOT EXISTS registry_keys (\n    fingerprint TEXT PRIMARY KEY,           -- 40 uppercase hex chars, no 0x\n    key_id TEXT NOT NULL,                   -- primary long key ID, 16 uppercase hex\n    armored TEXT NOT NULL,                  -- ASCII-armored public key (canonicalized)\n    revoked INTEGER NOT NULL DEFAULT 0,     -- 0 = active, 1 = revoked (permanent)\n    revoked_at INTEGER,                     -- epoch seconds of revocation\n    revoke_reason TEXT,                     -- short owner-supplied reason (sanitized)\n    token_hash TEXT NOT NULL,               -- SHA-256 hex of the revocation token\n    created_at INTEGER NOT NULL,            -- epoch seconds of first publish\n    updated_at INTEGER NOT NULL             -- epoch seconds of last change\n);\n\nCREATE INDEX IF NOT EXISTS idx_registry_keys_key_id ON registry_keys (key_id);\n\n-- Subkey key-ID index so lookups by any subkey ID resolve to the primary.\nCREATE TABLE IF NOT EXISTS registry_subkeys (\n    key_id TEXT PRIMARY KEY,                -- subkey long ID, 16 uppercase hex\n    fingerprint TEXT NOT NULL REFERENCES registry_keys (fingerprint) ON DELETE CASCADE\n);\n\nCREATE INDEX IF NOT EXISTS idx_registry_subkeys_fingerprint ON registry_subkeys (fingerprint);\n\n-- Email index for exact-match lookups (VKS-style). Emails are lowercased\n-- on insert; only self-reported User ID addresses are stored.\nCREATE TABLE IF NOT EXISTS registry_emails (\n    email TEXT NOT NULL,\n    fingerprint TEXT NOT NULL REFERENCES registry_keys (fingerprint) ON DELETE CASCADE,\n    PRIMARY KEY (email, fingerprint)\n);\n\nCREATE INDEX IF NOT EXISTS idx_registry_emails_fingerprint ON registry_emails (fingerprint);\n\n-- One-time challenge nonces for key-signed revocation/replacement.\nCREATE TABLE IF NOT EXISTS registry_challenges (\n    nonce TEXT PRIMARY KEY,                 -- 64 hex chars from CSPRNG\n    fingerprint TEXT NOT NULL,\n    created_at INTEGER NOT NULL,\n    expires_at INTEGER NOT NULL\n);\n\nCREATE INDEX IF NOT EXISTS idx_registry_challenges_fingerprint ON registry_challenges (fingerprint);\n\n-- Fixed-window rate limiter. bucket = SHA-256(salt | action | ip | window)\n-- so the same IP is unlinkable across windows and the raw IP is never stored.\nCREATE TABLE IF NOT EXISTS registry_rate (\n    bucket TEXT PRIMARY KEY,\n    count INTEGER NOT NULL,\n    reset_at INTEGER NOT NULL               -- epoch seconds when the window resets\n);\n\n-- Append-only audit trail (fingerprints + actions only — no IPs, no emails).\nCREATE TABLE IF NOT EXISTS registry_audit (\n    id INTEGER PRIMARY KEY AUTOINCREMENT,\n    at INTEGER NOT NULL,\n    action TEXT NOT NULL,                   -- publish | revoke-token | revoke-signed | revoke-admin | replace | challenge\n    fingerprint TEXT,\n    detail TEXT                             -- short non-sensitive note\n);",
	},
	{
		id: "0002_registry_indexes",
		sql: "-- Registry performance indexes (0002) — review follow-ups\n-- # Mr. AI Acting on s183173's Behalf\n--\n-- The rate-limiter cleanup and challenge expiry purges previously forced\n-- full table scans (each scan counts against the D1 rows-read quota).\n\nCREATE INDEX IF NOT EXISTS idx_registry_rate_reset_at ON registry_rate (reset_at);\n\nCREATE INDEX IF NOT EXISTS idx_registry_challenges_expires_at ON registry_challenges (expires_at);",
	},
	{
		id: "0003_encrypted_private",
		sql: "-- Encryptor key registry — encrypted private key escrow (0003)\n-- # Mr. AI Acting on s183173's Behalf\n--\n-- Adds OPTIONAL encrypted private key escrow to the registry. The\n-- encrypted_private column stores an ASCII-armored private key whose\n-- secret packets are ALL passphrase-encrypted (enforced server-side in\n-- src/lib/registry/keys.ts — any decrypted packet is rejected before it\n-- can reach the database, so this column never holds usable key bytes).\n-- Security of the escrow rests on the owner's passphrase strength and\n-- OpenPGP's iterated S2K, exactly like an offline .asc backup.\n\nALTER TABLE registry_keys ADD COLUMN encrypted_private TEXT;\nALTER TABLE registry_keys ADD COLUMN private_updated_at INTEGER;",
	},
];
