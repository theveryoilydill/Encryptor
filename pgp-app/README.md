# PGP for Keybase · Cloudflare Worker

A single-page React Router v8 app that runs entirely in the browser for crypto
operations, deployed as a Cloudflare Worker. Keybase is the primary source of
PGP public keys; local keys are supported but kept out of the spotlight.

## Features

- **Encrypt + sign** a message to multiple recipients (Keybase usernames or
  pasted public keys) in a single armored PGP message.
- **Decrypt + verify** an incoming PGP message: decrypts with your private key
  and verifies the signer's signature against the signer's Keybase public key.
- **Sign** plain text — cleartext-signed (inline) or detached signature.
- **Verify** any signature against a Keybase user's public key.
- **Keybase lookup**: type one or more Keybase usernames, get their public
  keys, fingerprints, key IDs, creation date, and expiration.
- **Local keys** (collapsible "advanced" section): generate a new ECC/RSA key
  pair, paste existing armored keys, store them in `localStorage`, and reuse
  them as signer or recipient.

## Crypto

All PGP operations (encrypt, decrypt, sign, verify, generate) happen
**in the browser** using [openpgp.js v6](https://openpgpjs.org/).
Private keys never leave the user's browser.

The only server-side call is the **Keybase proxy** at `/api/keybase`, which
forwards `https://keybase.io/_/api/1.0/user/lookup.json` because Keybase
does not set CORS headers. The Worker is stateless and caches responses for
5 minutes (`Cache-Control: public, max-age=300`).

## Tech stack

| Library | Version | Purpose |
| ------- | ------- | ------- |
| react-router | ^8.3 | File-based routes + SSR loaders on Workers |
| @react-router/cloudflare | ^8.3 | Cloudflare Workers adapter |
| @cloudflare/vite-plugin | ^1.49 | Workers build pipeline |
| openpgp | ^6.3 | PGP crypto (browser + Worker) |
| tailwindcss | ^4 | Styling |
| vite | ^8 | Build tool |
| wrangler | ^4.116 | Cloudflare Workers CLI |

## Develop

```bash
cd pgp-app
npm install
npm run dev
# opens http://localhost:5173 with the Vite dev server
# (the Cloudflare platform is emulated via wrangler's getPlatformProxy)
```

## Deploy

```bash
cd pgp-app
npm install
npm run build
npx wrangler login       # one-time
npm run deploy           # npx wrangler deploy
```

`wrangler deploy` publishes the Worker to your Cloudflare account. The static
assets (HTML/JS/CSS) are uploaded as Worker Sites, and the Worker handles
both the SPA and the `/api/keybase` proxy.

## Project layout

```
pgp-app/
├── app/
│   ├── root.tsx              # HTML shell
│   ├── tailwind.css          # Tailwind v4 theme
│   ├── lib/
│   │   ├── pgp.ts            # openpgp.js wrappers (encrypt/sign/decrypt/verify/generate)
│   │   └── keybase.ts        # Keybase API client (server + browser helpers)
│   └── routes/
│       ├── home.tsx          # Main UI: tabs + Keybase sidebar + Local keys card
│       └── api.keybase.ts    # Server-side Keybase proxy (loader)
├── package.json
├── vite.config.ts            # React Router + Cloudflare + Tailwind plugins
├── react-router.config.ts    # SSR enabled, no prerender
├── wrangler.toml             # Worker config (nodejs_compat flag enabled)
└── tsconfig.json
```

## Privacy

- No analytics, no tracking, no third-party fonts.
- All crypto is client-side. The Worker only sees Keybase usernames (proxied
  to keybase.io) — never your plaintext, ciphertext, or private keys.
- Local keys are stored in `localStorage` only.

## Why Keybase-first?

Keybase provides a free, public, name → PGP-public-key directory with
cryptographic proofs (Twitter/GitHub/Reddit/etc. bindings). It's the easiest
way for non-technical users to discover a recipient's PGP key without
manually exchanging fingerprints. Local key management is still supported
but kept in a collapsible "advanced" section.
