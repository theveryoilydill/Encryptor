# Key Registry — Design & Research

> Status: implemented (see `/api/registry/*` + `src/lib/registry`).
> # Mr. AI Acting on s183173's Behalf

## Goal

A free, public key registry backed by Cloudflare D1 (SQLite) running inside
the existing Encryptor Worker deployment:

- **Public read** — any website or computer can look up published public
  keys (CORS `*`, cacheable, no auth).
- **Secure retraction** — a key owner can retract (revoke) a published key
  even if their machine or the private key is compromised.

## Research findings (SearXNG, Sept 2026)

- **VKS / Hagrid (keys.openpgp.org)** is the modern keyserver model: strict
  URL scheme (`/vks/v1/by-fingerprint|by-keyid|by-email`), JSON upload
  returning an opaque token, email-verified discovery, and aggressive rate
  limits (5 req/s by fingerprint, 1/min by email). Our API mirrors this
  shape (`lookup` by fingerprint/key-id/email, `publish` returning a token)
  without email verification (no email infrastructure on the free plan).
- **HKP compatibility** (draft-gallagher-openpgp-hkp) was considered; we
  ship a plain JSON API instead and keep the door open for an HKP
  compatibility layer later — tool compatibility is not needed for the
  Encryptor app itself.
- **Certificate poisoning** (SKS network attacks) drove keyserver design
  for a decade: modern keyservers parse and validate keys server-side,
  bound payload sizes, and avoid gossiping third-party material. We parse
  every uploaded key with OpenPGP.js server-side, cap armor at 64 KB,
  re-serialize to canonical armor, and reject anything unparseable.
- **Revocation practice** (OpenPGP CA docs, GnuPG guidance): revocation
  material should be published WIDELY and be available offline BEFORE it
  is needed. We support (a) an offline revocation token issued at publish
  time (works without the private key) and (b) key-signed challenge
  revocation (proof of possession). Revocation is permanent and the
  revoked record stays visible so revocations cannot be suppressed.
- **Key transparency** (CONIKS, Parakeet/WhatsApp, SEKEYS) is the
  state of the art for verifiable key directories; a full transparency
  log is out of scope for a free tier, but the append-only
  `registry_audit` table and permanent revocation semantics leave the
  door open (audit rows are fingerprints + actions only — no PII).
- **Token hygiene** (auth-token guidance): store SHA-256 hashes, compare
  in constant time. Revocation tokens have revoke-only power — they can
  never replace or read a key, so a leaked token can only cause a
  fail-safe denial, not impersonation.
- **D1 specifics**: all access uses `prepare().bind()` (D1's documented
  SQL-injection prevention); the free tier comfortably covers a key
  registry (5 GB storage, millions of row reads/day).
- **CVE-2025-47934** (OpenPGP.js inline-signature spoofing) is patched in
  openpgp ≥ 6.3.0; the repo is on ^6.3.1. Server-side verification uses
  cleartext messages (`readCleartextMessage` + `verify`), the unaffected
  path, and additionally requires the message text to exactly equal the
  canonical challenge string.

## Data model (migrations/0001_registry.sql)

| Table | Purpose |
|-------|---------|
| `registry_keys` | fingerprint (PK), key_id, canonical armored PUBLIC key, revoked flag + reason, token_hash (SHA-256), timestamps |
| `registry_subkeys` | subkey key-id → primary fingerprint (lookup by any subkey) |
| `registry_emails` | self-reported User ID emails → fingerprint (exact-match lookup) |
| `registry_challenges` | one-time nonces (10 min TTL) for possession proofs |
| `registry_rate` | fixed-window rate buckets keyed by SHA-256(salt\|action\|ip\|window) |
| `registry_audit` | append-only action log (fingerprint + action only, no IPs/emails) |

## API

| Route | Method | Auth | Notes |
|-------|--------|------|-------|
| `/api/registry/lookup?fingerprint=\|key_id=\|email=` | GET | none | CORS `*`, cached (60s browser / 300s edge), returns revoked records with status |
| `/api/registry/publish` | POST | rate-limited | parses server-side, rejects private material, returns one-time `revocationToken`; replacement requires signed challenge from the currently stored key |
| `/api/registry/challenge?fingerprint=` | GET | rate-limited | one-time nonce + exact canonical message to sign |
| `/api/registry/revoke` | POST | token OR signed challenge OR admin | permanent; token path works without the private key |

### Threat model coverage

- **Garbage / oversized uploads** → server-side parse + 64 KB cap + 100 KB body cap + JSON content-type enforcement (also blocks form-based CSRF).
- **Key replacement attack** → replacement requires a signature from the CURRENTLY stored key; the offline token cannot replace, only revoke (fail-safe).
- **DB dump leak** → only public keys + token hashes + hashed-IP rate buckets; no raw IPs, no plaintext tokens, no PII beyond self-published User IDs.
- **Replay** → challenges are single-use (atomic DELETE-consume before verify) with 10-minute expiry.
- **Timing attacks** → token/admin comparisons run on SHA-256 digests with a constant-time compare.
- **Rate abuse** → D1-backed fixed windows (publish 5/h, challenge 10/h, revoke 10/h per IP); lookups are cheap and edge-cached.
- **Revocation suppression** → revoked records stay visible (`revoked: true`), and re-publication of a revoked fingerprint is refused forever.
- **Admin compromise path** → `ADMIN_REVOKE_TOKEN` secret enables emergency revocation; set via `wrangler secret put`.

## Deployment (free tier, ~5 minutes)

```bash
npx wrangler d1 create encryptor-registry   # copy database_id into wrangler.json
npx wrangler d1 migrations apply encryptor-registry --remote
npx wrangler secret put RE_SALT             # long random string (rate-bucket privacy)
npx wrangler secret put ADMIN_REVOKE_TOKEN  # optional emergency override
bun run deploy
```

Local development works out of the box: `initOpenNextCloudflareForDev()`
proxies a local D1 into `next dev`; apply the migration with
`npx wrangler d1 migrations apply REGISTRY_DB --local`.

## Deliberate non-goals

- Email identity verification (needs email sending; VKS-style opt-in later).
- Third-party certification hosting (poisoning surface, no value here).
- HKP protocol compatibility layer (can be added on top of the same table).
