# Encryptor

A **zero-knowledge, client-side PGP encryption app for the web**, designed to run
on Cloudflare's free `workers.dev` plan. Encrypt, decrypt, sign, and verify
OpenPGP messages entirely in your browser — your private key and passphrase
never leave your device.

## What it does

- **Encrypt & decrypt** OpenPGP (RFC 4880 / 9580) messages in the browser using
  [openpgp.js](https://openpgpjs.org/) v6 — modern AEAD-based symmetric
  encryption (AES-256 with the EAX AEAD mode, the openpgp.js v6 default, not the
  legacy SEIPD v1 / CFB stream mode of older OpenPGP). No plaintext or key
  material is sent to any server.
- **Sign & verify** messages with detached signatures and auto-verification of
  sender identity.
- **Attach files / images** — files are wrapped in a versioned JSON "envelope"
  before encryption, so a single encrypted blob can carry text plus attachments.
  Older clients that don't understand the envelope fall back to showing the raw
  decrypted text.
- **Generate key pairs** locally, or **import your own** ASCII-armored keys.
- **Optional Keybase login** — fetch your public key and (encrypted) private key
  bundle from Keybase. The Keybase-specific login flow uses Per-Device Public Key
  Authentication (PDPKA), with triplesec v3 key stretching and Ed25519 auth
  signatures, to authenticate to Keybase and retrieve your passphrase-encrypted
  private key bundle — which you then decrypt locally with *your* password.

## Why it runs on the `workers.dev` free plan

The core encryption app is a static Next.js site deployed to Cloudflare Workers via
[`@opennextjs/cloudflare`](https://opennext.js.org/) (see `wrangler.json` and
`open-next.config.ts`). The Worker serves the built assets bundle; it does **no
crypo work and stores no secrets server-side**. Because all crypto executes in the
user's browser, the Worker fits comfortably within the free-tier limits:

- **CPU/memory**: the Worker only serves static assets and proxies a handful of
  read-only Keybase API calls (to dodge browser CORS) — it never performs
  encryption, so it stays well under the free-tier compute budget.
- **No server-side state**: there is no required database for the core
  encrypt/decrypt/sign/verify experience.
- `wrangler.json` uses `compatibility_flags: ["nodejs_compat"]` and
  `compatibility_date: 2026-08-02`.

> **Free-tier scope note (read before you deploy the DB features):** The repo
> *also* contains a Prisma schema (`prisma/schema.prisma`) over **SQLite** with
> `User`/`Post` models and a `@prisma/client` usage in `src/lib/db.ts`. SQLite +
> `@prisma/client` over a `file:` datasource does **not** run on the Workers
> runtime — Workers have no filesystem. To enable any server-side persistence on
> the free plan, switch the datasource to **Cloudflare D1** and the Prisma
> driver adapter, or drop the DB entirely. The current `package.json` ships the
> Prisma deps but `wrangler.json` declares **no `d1_databases` binding** — so a
> plain `npm run deploy` deploys the static app and the DB code is inert.
> Treat the DB layer as opt-in scaffolding, not part of the free-tier image.

A separate, standalone worker lives in [`pgp-app/`](pgp-app) (`pgp-keybase-app`):
a React Router v8 SPA that proxies Keybase API calls server-side to avoid browser
CORS restrictions. Deploy it independently with the commands in
`pgp-app/wrangler.toml`.

## Quick start

Prerequisites: Node.js 20+, and one of Bun, pnpm, or npm (pick **one** — see
"Tooling hygiene" below; there are currently three lockfiles in the tree).

```bash
# Install (choose one toolchain)
bun install            # or: pnpm install / npm install

# Local dev server on http://localhost:3000
npm run dev

# Type-check, lint, format, test
npm run typecheck
npm run lint
npm run format:check
npm run test          # vitest unit tests
npm run test:e2e      # playwright end-to-end tests

# Build the Workers bundle and deploy to workers.dev
npm run build         # Next.js standalone build
npm run deploy        # opennextjs-cloudflare build && deploy
npm run preview       # opennextjs-cloudflare build && preview (local Workers)
```

The deploy target is the `encryptor` Worker defined in `wrangler.json`. Log in
with `npx wrangler login` before your first deploy.

## Security model

| Where it happens | What runs there |
|---|---|
| **Your browser** | All PGP key generation, encryption, decryption, signing, and verification. Passphrase prompts unlock a private key that lives only in JS memory for the duration of the operation. |
| **localStorage** | Only key *metadata* and the **passphrase-encrypted** armored private key (or Keybase account info) — never the decrypted key, never the passphrase. (`src/components/pgp/PgpApp.tsx`) |
| **The Worker** | Serves static assets and proxies a few read-only Keybase lookups. Never receives plaintext, private keys, or passphrases. |
| **Keybase** | Only contacted if you opt into Keybase login. The Worker forwards fixed read-only Keybase endpoints with your CSRF cookie; your Keybase password is stretched client-side into PDPKA auth signatures and never sent in cleartext. |

**Threat model & honest caveats:** this is an in-browser crypto tool. It defends
against a passive network observer and a server that doesn't want to look — it
does **not** defend against a compromised browser (malicious extension, injected
script, or a tampered CDN delivery of the JS bundle, i.e. the classic
"JavaScript crypto can't trust its own delivery" problem). For the highest
assurance, run it from a trusted local build, pin/verify the served bundle, and
use a hardware-backed key where possible. Web Crypto / openpgp.js gives you
audited primitives, but the page that loads them still has to be trustworthy.

See `AGENTS.md` for contributor notes and `worklog.md` / `FIX-NOTES.md` for the
running history of known issues and fixes.

## Stack

- Next.js 16 + React 19, TypeScript (strict), Tailwind CSS 4, shadcn/ui (Radix)
- openpgp.js v6 for all PGP primitives; `triplesec` v3 + `kbpgp` + `keybase-proofs`
  for the optional Keybase PDPKA login flow
- Vitest (unit) + Playwright (E2E)
- Lint/format: oxlint + oxfmt; OpenNext for Cloudflare → Workers

## License

None declared yet. Add a `LICENSE` file before public distribution.
