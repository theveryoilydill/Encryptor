# Key Registry — Design Notes (WORK IN PROGRESS)

> Status: research phase. This document is updated as findings come in.
>
> # Mr. AI Acting on s183173's Behalf

## Goal

A free, public key registry backed by Cloudflare D1 (SQLite) that runs inside
the existing Encryptor Worker deployment:

- **Public read** — any website or computer can look up published public keys
  (CORS `*`, cacheable, no auth).
- **Secure retraction** — a key owner can retract (revoke) a published key
  even if their machine or the service is compromised, via offline
  revocation tokens and/or signed revocation requests.

## Constraints & invariants

1. Public keys only — the registry must NEVER store private key material.
2. Revocation must survive compromise of the uploader's machine (offline
   token path) AND support the standard PGP revocation-certificate path.
3. All D1 access uses prepared statements with bound parameters.
4. The registry ships in the same Worker; no new paid services.

## Planned API surface (draft)

| Route                   | Method | Auth                      | Purpose                                                       |
| ----------------------- | ------ | ------------------------- | ------------------------------------------------------------- |
| `/api/registry/lookup`  | GET    | none (CORS \*)            | fetch by fingerprint / key id / email                         |
| `/api/registry/publish` | POST   | none (rate-limited)       | publish armored public key, returns one-time revocation token |
| `/api/registry/revoke`  | POST   | token OR signed challenge | retract a key                                                 |

## Threat model (draft)

- Attacker uploads garbage / huge payloads → parse-verify server-side, cap
  armor size, reject keys containing private material.
- Attacker deletes/replaces others' keys → replacement requires possession
  of the existing revocation token or a signature from the existing key.
- DB dump leak → only public keys + SHA-256 token hashes are stored.
- Service compromise → keys can be re-published by owners; revocation
  tokens kept offline by owners remain valid proofs.

## Open questions

- Rate limiting on the free plan (D1-backed vs in-isolate).
- Whether to mirror HKP-style endpoints for tool compatibility.
