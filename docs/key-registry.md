# Key Registry — Design & Research

> Status: implemented (see `/api/registry/*` + `src/lib/registry`).
>
> # Mr. AI Acting on s183173's Behalf

## Goal

A free, public key registry backed by Cloudflare D1 (SQLite) running inside
the existing Encryptor Worker deployment:

- **Public read** — any website or computer can look up published public
  keys (CORS `*`, cacheable, no auth).
- **Secure retraction** — a key owner can retract (revoke) a published key
  even if their machine or the private key is compromised.
- **Encrypted private key escrow** (migration 0003) — an owner MAY store
  the passphrase-encrypted private key alongside their public record so
  the key can be restored on any device. The server rejects any private
  key that is not fully passphrase-encrypted, so the database never holds
  usable private key bytes — security rests on the owner's passphrase and
  OpenPGP's iterated S2K, exactly like an offline `.asc` backup.

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

| Table                 | Purpose                                                                                                                                              |
| --------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------- |
| `registry_keys`       | fingerprint (PK), key_id, canonical armored PUBLIC key, optional `encrypted_private` escrow, revoked flag + reason, token_hash (SHA-256), timestamps |
| `registry_subkeys`    | subkey key-id → primary fingerprint (lookup by any subkey)                                                                                           |
| `registry_emails`     | self-reported User ID emails → fingerprint (exact-match lookup)                                                                                      |
| `registry_challenges` | one-time nonces (10 min TTL) for possession proofs                                                                                                   |
| `registry_rate`       | fixed-window rate buckets keyed by SHA-256(salt\|action\|ip\|window)                                                                                 |
| `registry_audit`      | append-only action log (fingerprint + action only, no IPs/emails)                                                                                    |

## Encrypted private key escrow

The `encrypted_private` column stores an ASCII-armored private key whose
secret packets are ALL passphrase-encrypted. `parseEncryptedPrivateArmored`
(`src/lib/registry/keys.ts`) enforces, server-side and before any write:

1. the blob parses as an OpenPGP PRIVATE key;
2. its fingerprint equals the public record's fingerprint (identity
   binding — no decoy keys);
3. NO secret packet reports decrypted (checked per packet, so one
   unencrypted subkey rejects the whole upload);
4. the primary self-signature verifies; the blob is re-serialized to
   canonical armor and capped at 64 KB.

Escrow lifecycle:

- **Publish** — `POST /api/registry/publish` accepts an optional
  `encryptedPrivate` field (validated before the public half is written).
- **Restore** — `GET /api/registry/private-key?fingerprint=` returns the
  blob; the client decrypts it locally with the passphrase (which never
  leaves the browser).
- **Manage** — `POST /api/registry/private-key` stores or deletes the
  escrow, authorized by the same key-signed challenge as replacement
  (possession proof; nonce consumed atomically).
- **Replace** — an authorized replacement KEEPS the escrow unless the
  client sends `dropEncryptedPrivate: true` (a new escrow overwrites).
- **Revoke** — revocation permanently purges the escrow; a revoked record
  keeps only its public revocation information.

What escrow does NOT change: the public read API never returns private
material (lookup responses are unchanged); the escrow GET is same-origin
only (no CORS header), never cached, and rate limited 30/h/IP; the
passphrase is the sole decryptor — anyone who obtains the blob still
faces OpenPGP's S2K, and users should treat passphrase strength like an
offline backup's.

## API

| Route                                                | Method | Auth                               | Notes                                                                                                                                                                                                                                 |
| ---------------------------------------------------- | ------ | ---------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `/api/registry/lookup?fingerprint=\|key_id=\|email=` | GET    | none                               | CORS `*`, browser-cached 60s (edge caching NOT enabled by default on Workers — see hardening notes); params take priority fingerprint > key_id > email; rate limited 120/h/IP                                                         |
| `/api/registry/publish`                              | POST   | rate-limited                       | parses server-side, rejects private material in `armored`, optional `encryptedPrivate` escrow (must be passphrase-encrypted), returns one-time `revocationToken`; replacement requires signed challenge from the currently stored key |
| `/api/registry/challenge?fingerprint=`               | GET    | rate-limited                       | one-time nonce + exact canonical message to sign                                                                                                                                                                                      |
| `/api/registry/private-key?fingerprint=`             | GET    | rate-limited (30/h/IP)             | returns the escrowed ENCRYPTED private key (null when none); no CORS, no caching — never returns private material for revoked/unknown records beyond null                                                                             |
| `/api/registry/private-key`                          | POST   | key-signed challenge               | store (`encryptedPrivate`) or delete the escrow; nonce consumed atomically; revoked records refuse escrow writes                                                                                                                      |
| `/api/registry/revoke`                               | POST   | token OR signed challenge OR admin | permanent; token path works without the private key; purges the escrow                                                                                                                                                                |

Every registry route is rate limited per-IP with fixed windows. A denied
request returns **429** with an accurate `Retry-After` header (seconds until
the window rolls over) and a matching numeric `retryAfter` field in the JSON
body, so clients can back off precisely instead of polling. The browser
client (`formatRegistryError`) surfaces this as "resets in 42s" in the UI.

When the LIMITER itself is unavailable (D1 quota exhausted, transient
outage), fail-closed mutations (publish/challenge/revoke/private-key) return
**503** — `"Registry is temporarily unavailable — please try again shortly"`
with NO `Retry-After`, because the outage horizon is unknowable and a 429
would wrongly blame the client (this distinction lives in one place,
`enforceRateLimit` in `src/lib/registry/db.ts`, so it cannot drift
site-by-site). Public reads (lookup) keep failing OPEN and are simply
unthrottled for the duration of the outage.

### Verifying fingerprints aloud (PGP word list)

Lookup results can render the fingerprint as its **PGP words** (the
"biometric word list", Zimmermann/Juola 1995): 20 words, alternating between
the even- and odd-offset tables, with canonical capitalization preserved
(proper nouns like `Pluto` / `Istanbul` / `Dupont` stay capitalized). Read
the words to the key owner over a voice channel — the two alternating lists
detect transposed, duplicated, and skipped words, which defeats MitM key
substitution during out-of-band verification.

REST consumers get the same data opt-in: append **`&words=1`** (or `words=true`)
to any lookup call and each key gains a `words: string[20]` field.
Without the parameter the field is omitted entirely, keeping default
responses small.

### QR fingerprint exchange

The Keys tab renders a **QR code per fingerprint** encoding the standard
`openpgp4fpr:<FINGERPRINT>` URI (OpenKeychain/GnuPG convention). Scanning is
an out-of-band verification channel: the fingerprint travels camera-to-camera
instead of through the (possibly tampered) network path, so a MitM who swaps
keys in API responses cannot survive the comparison. The dialog also copies
the raw `openpgp4fpr:` URI.

### Scan-to-lookup (camera)

The **Scan** button next to lookup opens the device camera and feeds frames
to the browser's built-in `BarcodeDetector` API — no decoder is bundled and
**frames never leave the device**. A detected `openpgp4fpr:` QR (or bare
40-hex fingerprint) fills the lookup field and searches automatically.
Browsers without `BarcodeDetector` (Firefox/Safari) get an explicit note in
the dialog instead of a silently dead button.

### Registry watch (key-change detection)

Every successful lookup records a **sighting** locally (`localStorage`,
fingerprint → `{updatedAt, revoked, seenAt}`, capped at 200 entries). Later
lookups of the same fingerprint compare live state against the last
sighting:

- `updatedAt` increased → amber callout: **"Key material changed since your
  last lookup — re-verify out of band before trusting it."**
- flipped to `revoked` → red callout: **"Revoked since your last lookup —
  stop trusting this key."**

The server can only report the CURRENT state; noticing "different from what
I saw before" requires memory, which is exactly what the watch provides —
a key silently replaced by an attacker (via the authorized-challenge flow
with a stolen key) is flagged the next time a previous viewer looks it up.
All storage access is best-effort: private-mode/quota failures degrade to
"no change detection", never to broken lookups.

### Threat model coverage

- **Garbage / oversized uploads** → server-side parse + 64 KB cap + 100 KB body cap + JSON content-type enforcement (also blocks form-based CSRF); Content-Length is rejected BEFORE the body is buffered.
- **Structural key attacks** → publish verifies the primary self-signature and EVERY subkey binding signature (blocks foreign-subkey "squatting" that would hijack key-ID lookups), caps subkeys at 16 and emails at 10.
- **Key replacement attack** → replacement requires a signature from the CURRENTLY stored key; the challenge nonce is consumed atomically (scoped to the fingerprint) BEFORE verification; the replacement UPDATE is guarded by `AND revoked = 0` so a record cannot be mutated after a concurrent revocation; the offline token cannot replace, only revoke (fail-safe).
- **DB dump leak** → only public keys + token hashes + hashed-IP rate buckets; no raw IPs, no plaintext tokens, no PII beyond self-published User IDs. Rate buckets use a server-side salt that fails CLOSED in production if unset.
- **Replay** → challenges are single-use with 10-minute expiry, consumed before verification (failed verification attempts burn the nonce — fail-closed).
- **Timing attacks** → token/admin comparisons run on SHA-256 digests with a constant-time compare; challenge-signature validity is verified explicitly (every signature's `verified` promise), never inferred from array length.
- **Quota exhaustion (free tier)** → the D1 rate limiter is read-first: PER-IP OVER-LIMIT requests cost one indexed read and ZERO writes. Lookups are rate limited too (120/h/IP). If the limiter itself cannot reach D1 (quota exhaustion, transient errors), public reads fail OPEN while publish/challenge/revoke fail CLOSED — limiter failure degrades instead of 500-ing everything. Distributed abuse (many IPs under their per-IP limits) can still burn quota, so the free Cloudflare WAF rate-limiting rule for `/api/registry/*` is the real outer defense. Email lookups, key-ID lookups and results are bounded; one email can be claimed by at most 5 keys (revoked keys release their email claims); a sampled global storage guard caps total keys at 50,000. Request caps are enforced on UTF-16 length before buffering (Content-Length) and re-checked after.
- **Revocation suppression** → revoked records stay visible by FINGERPRINT lookup (`revoked: true`), and re-publication of a revoked fingerprint is refused forever. Revocation RELEASES the email and subkey indexes so revoked keys cannot squat scarce namespaces (email claims, 64-bit key IDs).
- **Index hygiene** → cleanup queries hit indexed columns (`reset_at`, `expires_at` — migration 0002) so purges never full-scan.
- **Admin compromise path** → `ADMIN_REVOKE_TOKEN` secret enables emergency revocation; set via `wrangler secret put`. An unconfigured deployment answers admin attempts with the generic 403 (never a 5xx or config disclosure).
- **Token lifetime** → the revocation token survives authorized replacements (the ORIGINAL publisher keeps the fail-safe). Rotate offline copies accordingly; token power is revoke-only.

### Production hardening recommendations (outside the app)

- Add a free Cloudflare WAF rate-limiting rule for `/api/registry/*` as the outer layer (the D1 limiter is the second line, per-IP only).
- Worker responses are not edge-cached by default; if lookup traffic becomes expensive, add Cache API caching for hot GETs or enable OpenNext cache instrumentation.
- Monitor D1 metrics (`rows_read`, `rows_written`) and set alerts; the storage guard caps keys at `LIMITS.registryStorageCapKeys`.
- Set `RE_SALT` (long random string) and optionally `ADMIN_REVOKE_TOKEN` via `wrangler secret put` — the registry fails closed (503) in production without `RE_SALT`.

## Deployment (free tier, ~5 minutes)

```bash
npx wrangler d1 create encryptor-registry   # copy database_id into wrangler.json
npx wrangler secret put RE_SALT             # long random string (rate-bucket privacy)
npx wrangler secret put ADMIN_REVOKE_TOKEN  # optional emergency override
npx wrangler secret put TURNSTILE_SECRET_KEY  # optional: enforce Turnstile on writes
bun run deploy
```

**Self-migrating schema** — you do NOT need to run `wrangler d1 migrations
apply` (remotely or in CI). The worker bundles the SQL from `migrations/`
(via the generated `src/lib/registry/migrations.generated.ts`) and applies
any missing version on first database access, tracked in the
`registry_schema_migrations` ledger table. A freshly created remote D1
database heals itself on the first request — `GET /api/registry/health`
reports `{ ok, schema.applied, schema.pending, turnstile }` and is the
fastest way to check a deployment. After adding a new migration file, run
`node scripts/gen-migrations.mjs` and commit the regenerated module
(Workers Builds CI never runs `wrangler d1 migrations apply`, which is why
publishes once failed with opaque 500s on an un-migrated database —
PR #25 review: "there are no writes to my database").

Local development works out of the box: `initOpenNextCloudflareForDev()`
proxies a local D1 into `next dev`; the self-migration covers it too
(`wrangler d1 migrations apply REGISTRY_DB --local` remains available and
idempotent for manual setups).

## Bot protection (Cloudflare Turnstile)

Registry WRITES — publishing a key and storing an escrowed private key —
are gated by Cloudflare Turnstile whenever the deployment has a
`TURNSTILE_SECRET_KEY` secret (delete/revoke stay signature- or
token-gated and are not captcha'd). Provisioning, both halves together:

```bash
npx wrangler secret put TURNSTILE_SECRET_KEY            # server half (Worker secret)
# client half: build-time env var in Workers Builds settings:
#   NEXT_PUBLIC_TURNSTILE_SITE_KEY = <your Turnstile site key>
```

- Secret configured + valid widget token → write proceeds.
- Secret configured + missing/invalid/expired token → 403 with a clear
  message; the UI remounts the widget to mint a fresh single-use token.
- Siteverify unreachable or secret invalid → writes fail CLOSED (503).
- Secret NOT configured (local dev, preview builds, seed scripts) →
  verification disabled; the UI shows a subtle "not configured" note.

`GET /api/registry/health` reports the active mode
(`turnstile: "enforced" | "disabled"`).

## Testing

The repository ships an end-to-end suite covering every route plus the
negative security cases (SQLi grammar probes, replay, forged signer,
cross-fingerprint nonce use, rate limiting, payload guards, and the full
encrypted-private escrow matrix: decrypted-key rejection, fingerprint
mismatch, public-as-private rejection, unauthorized store/delete, replace
keep/drop semantics, revocation purge):

```bash
npx wrangler d1 migrations apply REGISTRY_DB --local   # local D1 + schema
bun run dev                                            # terminal 1
bun run test:registry                                  # terminal 2 (73 checks)
```

`REGISTRY_TEST_BASE` overrides the target URL for preview deployments.

An example user can be seeded against any running target (publishes an
"Example User" key WITH escrow and writes `.example-user.json`, which is
gitignored, holding the passphrase + revocation token):

```bash
node scripts/seed-example-user.mjs [--show-secret]
```

## Deliberate non-goals

- Email identity verification (needs email sending; VKS-style opt-in later).
- Third-party certification hosting (poisoning surface, no value here).
- HKP protocol compatibility layer (can be added on top of the same table).
