# Encryptor

A minimal, browser-only PGP toolkit for encrypting, decrypting, signing, and
verifying messages — with Keybase integration. All cryptography runs locally
in your browser; private keys and plaintext never touch the server.

<!-- Mr. AI Acting on s183173's Behalf -->

## Features

- **Encrypt & sign** — seal a message to one or more recipients (plus
  yourself), automatically signed with your key. Attach any files, or paste
  images straight into the message; they ride inside the encrypted envelope
  and render inline for the recipient.
- **Decrypt** — paste an encrypted message and it decrypts as you type.
  Signatures on the message are verified automatically, and attached files
  are extracted below the decrypted text (images open in a built-in viewer).
- **Sign** — produce cleartext-signed messages or detached signatures.
- **Verify** — verify cleartext-signed or detached signatures and see who
  signed, when, and whether the signature is valid.
- **Keybase integration** — look up recipients by Keybase username (their
  public key is fetched for you), or log in with your Keybase credentials to
  use your existing Keybase PGP key. Signers' public keys are resolved
  automatically from Keybase, keys.openpgp.org, or your locally configured
  key.
- **Message compression** — messages are compressed (zlib) before encryption
  by default; the level is adjustable in settings.
- **Markdown composer** — messages are composed in a Notion-style editor by
  default, with an optional VS Code-style split editor (source + live
  preview) in settings.

## Security model

- Crypto is performed with [OpenPGP.js](https://openpgpjs.org/) entirely
  client-side. The decrypted private key exists only in memory for the
  duration of an operation and is discarded afterwards.
- Only the passphrase-**encrypted** private key and key metadata are
  persisted (browser `localStorage`).
- No message content is ever uploaded. The only network traffic is public
  key lookups, proxied through this app's own origin (`/api/keybase/*`) to
  Keybase, keys.openpgp.org, and the Ubuntu keyserver — because those
  services don't send CORS headers.
- An in-browser crypto self-test (footer button) round-trips key generation,
  encrypt, decrypt, sign, and verify to confirm the environment is healthy.

## Development

```bash
bun install   # install dependencies
bun run dev   # start the dev server on :3000
```

Typecheck, lint, and format:

```bash
bun run typecheck
bun run lint
bun run fmt
```

## Deployment

The app is a Next.js (App Router) application deployed to Cloudflare Workers
via [OpenNext](https://opennext.js.org/):

```bash
bun run build    # next build + opennextjs-cloudflare build
bun run deploy   # deploy to Cloudflare
```

## Project layout

```
src/app/                 Next.js app (page shell + Keybase proxy API routes)
src/components/pgp/      PGP UI (tabs, recipient picker, shared blocks)
src/components/pgp/tabs/ Encrypt / Decrypt / Sign / Verify tabs
src/lib/pgp/             Crypto + envelope + Keybase lookup libraries
.github/workflows/       CI (typecheck + lint + format), CodeQL, deploy
```
