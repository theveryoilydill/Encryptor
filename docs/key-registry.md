# Key Registry — Design & Research

> Status: implemented (see `/api/registry/*` + `src/lib/registry`). The UI
> surface is the **login gate** ("Login/Get your keys") — the Keys tab was
> removed in the PR #25 review round (see "UI surface" below).
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

## UI surface — the login gate

The Keys tab is GONE (PR #25 review round: "remove that new key tab", "keep
this minimal"). Signing in is now a full-page gate modeled on the owner's
mockup: **"Login/Get your keys"** with five big source buttons. The gate
shows whenever no private key is configured; every flow converges on the
same in-browser key configuration and never uploads a decrypted key or a
passphrase:

- **Encryptor Registry** — two segments:
  - _Restore my key_: fingerprint or email → registry lookup → fetch the
    escrowed blob → decrypt locally with the passphrase → configured.
  - _Publish a key_: paste a private key (decrypted pastes are encrypted
    locally first), optional escrow, Turnstile when enforced, and the
    one-time revocation token surfaced on the outcome card. Replacing an
    already-published fingerprint shows the same possession-proof panel
    (sign the challenge with the private key) as before.
- **Keybase registry** — Keybase username + password (PDPKA login through
  the app's proxies); the decrypted key is never stored, only metadata.
- **OpenPGP registry (needs private key)** / **Ubuntu Registry (needs
  private key)** — those keyservers host only PUBLIC keys, so signing in
  means pasting the matching private key, which is validated and kept
  locally.
- **Local keys** — generate a new pair in-browser (optional expiry, optional
  "also publish to the Encryptor registry" with escrow) or paste a locally
  managed key.

The old "Your key" dialog is now pure management (identity card, key
details, share QR, downloads, quantum seal, sign-out); the setup forms
moved to the gate. Removed with the Keys tab: my-keys bookkeeping and
backups, registry watch, QR/camera scanning, the Public API dialog, and the
admin console UI (see next section).

### Registry admin path (backend-only)

The `ADMIN_REVOKE_TOKEN` override still exists but has NO public UI any
more (owner: "don't put the admin thing publicly. I can do it in the
backend"). Operators revoke directly against the API:

```bash
curl -X POST https://<worker>/api/registry/revoke \
  -H 'Content-Type: application/json' \
  -d '{"fingerprint":"<40 HEX>","adminToken":"'$ADMIN_REVOKE_TOKEN'","reason":"abuse"}'
```

The token lives only in the operator's shell/environment — never in the
app, never persisted by it.

### Threat model coverage

- **Garbage / oversized uploads** → server-side parse + 64 KB cap + 100 KB body cap + JSON content-type enforcement (also blocks form-based CSRF); Content-Length is rejected BEFORE the body is buffered.
- **Structural key attacks** → publish verifies the primary self-signature and EVERY subkey binding signature (blocks foreign-subkey "squatting" that would hijack key-ID lookups), caps subkeys at 16 and emails at 10.
- **Key replacement attack** → replacement requires a signature from the CURRENTLY stored key; the challenge nonce is consumed atomically (scoped to the fingerprint) BEFORE verification; the replacement UPDATE is guarded by `AND revoked = 0` so a record cannot be mutated after a concurrent revocation; the offline token cannot replace, only revoke (fail-safe).
- **DB dump leak** → only public keys + token hashes + hashed-IP rate buckets; no raw IPs, no plaintext tokens, no PII beyond self-published User IDs. Rate buckets use a deployment salt that self-provisions on first boot
  (env `RE_SALT` when present, else a random CSPRNG value persisted in
  `registry_meta` — see migration 0004), so mutations never fail for want
  of a secret.
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
- Optionally set `RE_SALT` (long random string) and `ADMIN_REVOKE_TOKEN` via `wrangler secret put`. `RE_SALT` is only adopted on FIRST boot of a fresh database (it is then persisted in `registry_meta`); deployments without it auto-generate a salt, so writes work with zero secrets.

## Deployment permissions & database writes

Who can touch the registry database — the short version for repository owners:

| Actor                        | Can they write to YOUR D1?        | Why                                                                                                                                                                                                                |
| ---------------------------- | --------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| This repo's deployed Worker  | **Yes** (the only writer)         | The D1 binding lives in the owner's Cloudflare account; only deploys from THIS repository's branches build a Worker that holds it.                                                                                 |
| A fork / outside contributor | **No**                            | Their deploy would create/bind THEIR OWN D1 (or fail — they have neither the database_id nor your account). Pull requests from forks never gain access to your data.                                               |
| Outside users via the API    | **Only the designed write paths** | `publish` (rate-limited, canonical-parsed, challenge-gated for replacement), escrow store/delete (key-signed challenge), revoke (revocation token / signed challenge / admin token). Everything else is read-only. |
| Anonymous attackers          | **Destructive paths: no**         | Revocation without the token requires a signature from the key itself; the admin path requires `ADMIN_REVOKE_TOKEN` which lives only in the owner's Worker secrets.                                                |

Repository-side recommendations (GitHub, not Cloudflare):

- **Branch protection** on `main` and `develop` (require PR review + status checks) — since the Worker deploys branch heads, protecting the branches protects what gets deployed. The repo owner merging with admin privileges bypasses review only deliberately.
- **Outsiders cannot push branches to this repository** unless you add them as collaborators — for a public repo they fork instead. That is the correct default; nothing to fix.

## If registry writes fail (503 "Registry is temporarily unavailable")

`GET /api/registry/health` distinguishes the two known "reads work, mutations 503"
failure modes:

- ~~`saltConfigured: false`~~ — HISTORICAL (PR #25, twice): a worker recreated or
  re-linked without its `RE_SALT` secret used to fail CLOSED on every mutation
  (503) while lookups stayed healthy. Since migration 0004 the salt
  SELF-PROVISIONS on first boot (env `RE_SALT` when present, else a random
  CSPRNG value persisted in `registry_meta`) and never changes afterwards, so
  this failure mode cannot recur. `health.saltConfigured` stays in the payload
  (always `true` once the DB is reachable) for dashboard compatibility;
  `health.saltSource` reports `"env"` or `"generated"`.
- **`limiterWrite: false`** — D1 **writes** fail (daily write quota exhausted, or the
  database is full) while reads work. The fixed-window limiter performs one upsert
  per request, so a bot-scanned public `workers.dev` URL can burn the free tier's
  100k writes/day.

Symptom either way: lookups return 200, every mutation (`publish`, challenge,
revoke, escrow) returns 503.

Diagnosis checklist for the operator:

```bash
# 1. Confirm the outage shape from anywhere:
curl -s https://<worker>/api/registry/health | jq   # limiterWrite:false = writes down, reads fine

# 2. saltConfigured is ALWAYS true since migration 0004 (self-provisioned
#    salt) — if you still see mutation 503s, skip to step 3/5 (write quota or
#    limiter outage), or optionally pin a salt on a FRESH database:
npx wrangler secret put RE_SALT          # long random string (fresh DBs only)
npx wrangler secret put ADMIN_REVOKE_TOKEN   # optional backend admin revoke

# 3. In the Cloudflare dashboard → Workers & Pages → D1 → encryptor-registry:
#    check "Rows written / day" against the 100k free-tier limit, and storage size.

# 4. From a machine with wrangler auth to the account, free stale rate buckets
#    (they self-expire, but this reclaims space / confirms write access):
npx wrangler d1 execute encryptor-registry --remote \
  --command "DELETE FROM registry_rate WHERE reset_at < strftime('%s','now')"

# 5. Check Workers logs (observability is enabled) — the limiter logs the exact
#    D1 error on every failure, e.g. "exceeded daily limit" vs "database or disk is full".
```

Quota resets at **00:00 UTC**. If it re-exhausts within hours, reduce bot write burn:
enable a Cloudflare WAF rate-limiting rule on `/api/*`, provision Turnstile (writes
then require a human token), or keep the worker on a non-obvious route. The limiter
already minimizes writes: over-limit requests are rejected from a plain read with
zero writes, and public reads fail open without blocking when the limiter is down.

## Deployment (free tier, ~5 minutes)

```bash
npx wrangler d1 create encryptor-registry   # copy database_id into wrangler.json
npx wrangler secret put RE_SALT             # OPTIONAL (fresh DBs): pins the rate-bucket salt
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
reports `{ ok, schema.applied, schema.pending, turnstile, limiterWrite,
saltConfigured, saltSource }` and is the fastest way to check a deployment. After adding a new migration file, run
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

### Turnstile on preview/branch deployments ("can't add keys?")

Answer to the PR #25 review question: Turnstile was NOT why adds failed.
On the branch preview the server reported `turnstile: "disabled"` (no
`TURNSTILE_SECRET_KEY` on the worker) — the real cause was the missing
`RE_SALT`, which migration 0004 now self-heals (see the 503 runbook
above). Turnstile WILL, however, break publishes on a preview domain if
you provision only one half or forget the hostname allowlist:

- **Widget renders but every attempt fails** (`error 110200` — now shown
  in the UI instead of failing silently): the workers.dev preview hostname
  is not in the site key's allowlist. Fix: add the preview hostnames in
  the Cloudflare Turnstile widget config, or switch preview builds to the
  always-pass dummy pair (site `1x00000000000000000000AA`, secret
  `1x0000000000000000000000000000000AA`).
- **Enforced server-side but no widget in the page**: the build lacks
  `NEXT_PUBLIC_TURNSTILE_SITE_KEY`. The publish form shows an amber
  explainer instead of an impossible challenge; set the build env var or
  remove the worker secret.
- Health stays the one-URL diagnosis: `turnstile: "enforced"` + a publish
  403 with no widget = build/env mismatch; `enforced` + 503 = siteverify
  misconfiguration.

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
bun run test:registry                                  # terminal 2 (84 checks)
```

`REGISTRY_TEST_BASE` overrides the target URL for preview deployments. The
admin-override checks read `ADMIN_REVOKE_TOKEN` from the server's
`.dev.vars` (gitignored) in local dev; previews exercise the salt
self-provisioning path automatically (no secrets needed).

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
