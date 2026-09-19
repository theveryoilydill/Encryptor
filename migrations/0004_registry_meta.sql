-- Encryptor key registry — deployment metadata (0004)
-- # Mr. AI Acting on s183173's Behalf
--
-- Tiny key/value store for deployment-level secrets that the database can
-- own. First consumer: the registry's rate-limit/privacy SALT.
--
-- WHY: the salt used to live ONLY in the RE_SALT worker secret, and a
-- worker missing that secret failed CLOSED on every mutation (503) —
-- reported twice on PR #25 as "can't add keys" after a worker recreation
-- silently dropped its secrets. The salt is now provisioned on first boot:
-- the worker adopts RE_SALT when present, otherwise it generates a random
-- salt and persists it HERE. The value never changes afterwards (rate
-- buckets are per-window ephemeral, so nothing persistent depends on it),
-- which makes registry writes work on every deployment — production,
-- previews, and freshly recreated workers — with zero manual secrets.
--
-- Privacy note: a DB-stored salt means an attacker holding a DB dump can
-- test rate-bucket guesses offline (candidate IPs against bucket hashes).
-- The buckets are per-window (unlinkable across windows) and contain no
-- emails/keys — the residual leak is coarse "same IP in this window"
-- correlation only. Deployments that need the stronger guarantee set
-- RE_SALT as a secret on FIRST deploy; the env value is then adopted as
-- the stored salt and protected exactly as before.

CREATE TABLE IF NOT EXISTS registry_meta (
    key TEXT PRIMARY KEY,                   -- e.g. 'salt'
    value TEXT NOT NULL,                    -- value (salt: 64 hex chars)
    updated_at INTEGER NOT NULL             -- epoch seconds of last write
);
