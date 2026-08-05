# Fix Notes — Keybase Login 401

## TL;DR

The original `deriveKeysFromPassword` was almost correct — it just needed **one extra argument**: `version: 3` when constructing the `triplesec.Encryptor`. Without it, triplesec defaults to v4, which produces a different `keys.extra` slice → wrong `pwh` → wrong Ed25519 keypair → Keybase returns `BAD_LOGIN_PASSWORD` (HTTP 401).

## Symptom

POST `/api/keybase/login` returned HTTP 401. The body echoed Keybase's upstream error:

```json
{ "status": { "code": 204, "name": "BAD_LOGIN_PASSWORD", "desc": "bad passphrase" } }
```

(Earlier 401s with `SIG_CANNOT_VERIFY` were from a different buggy state during debugging — the final rejection from Keybase with the original repo code is `BAD_LOGIN_PASSWORD`.)

## Root cause

Keybase's `pwh_version: 3` (returned by `getsalt.json`) does **not** mean "use raw scrypt with these parameters". It means: **use triplesec version 3**, which is what Keybase's Go client hard-codes as `ClientTriplesecVersion = 3` (see [`go/libkb/constants.go:766`](https://github.com/keybase/client/blob/master/go/libkb/constants.go#L766) and [`go/libkb/passphrase_stream.go`](https://github.com/keybase/client/blob/master/go/libkb/passphrase_stream.go)).

The JS `triplesec` package supports both v3 and v4, but defaults to **v4** (see `node_modules/triplesec/lib/enc.js` line 116: `exports.CURRENT_VERSION = CURRENT_VERSION = 4`).

| Version | `use_twofish` | Cipher-key length consumed before `extra`              |
| ------- | ------------- | ------------------------------------------------------ |
| v3      | `true`        | 192 bytes (hmac 96 + aes 32 + twofish 32 + salsa20 32) |
| v4      | `false`       | 160 bytes (hmac 96 + aes 32 + salsa20 32)              |

So `keys.extra` — the slice of scrypt output that the code reads `pwh` and `eddsa_seed` from — starts at **byte 192** for v3, but at **byte 160** for v4. A 32-byte shift.

Per Keybase's `passphrase_stream.go`:

```go
const (
  pwhIndex   = 0       // → keys.extra[0..32]
  pwhLen     = 32
  eddsaIndex = pwhIndex + pwhLen  // → keys.extra[32..64]
  ...
  extraLen   = pwhLen + eddsaLen + dhLen + lksLen  // = 128
)
```

The JS repo code was reading the right slice (`keys.extra.slice(0, 32)` for pwh, `slice(32, 64)` for eddsa), but on the wrong triplesec version, so it was reading bytes [160..192] of the scrypt output instead of bytes [192..224]. The derived Ed25519 keypair therefore had no relationship to the one Keybase's server derived → 401.

## The fix

Pass `version: 3` explicitly when constructing the `Encryptor`:

```ts
const enc = new Encryptor({
  key: new TSBuffer(password, "utf8"),
  version: 3, // ← THE FIX
});
```

Everything else stays the same. No new dependencies, no API changes, no rewriting `deriveKeysFromPassword`. Just one argument.

## Verification

I tested the entire flow end-to-end with a real Keybase account (username `s183173`). The test script is at `/home/z/my-project/scripts/test_full_flow.cjs`. After applying the fix, the output was:

```
[1/6] getsalt...                  → salt + csrf_token + login_session ✓
[2/6] derive pwh + eddsa_seed     → triplesec v3 ✓
[3/6] generate PDPKA signatures   → pdpka4 + pdpka5 (832 chars each) ✓
[4/6] POST login.json...          → status: 0 OK, session present ✓
[5/6] fetch me.json...            → username + private_key_bundle present ✓
[6/6] decrypt bundle...           → RSA private key extracted, isDecrypted: true ✓
```

So the fix produces a real, working Keybase session and successfully decrypts the user's PGP private key.

## Files changed

| File                              | Change                                                                                                   |
| --------------------------------- | -------------------------------------------------------------------------------------------------------- |
| `src/lib/pgp/keybase-auth.ts`     | Added `version: 3` to the `Encryptor` constructor in `deriveKeysFromPassword`. Updated header docstring. |
| `pgp-app/app/lib/keybase-auth.ts` | Same fix mirrored for the Cloudflare Workers build.                                                      |
| `worklog.md`                      | Appended Task ID 2 documenting the diagnosis + fix.                                                      |

## What was NOT changed

- `decryptPrivateKeyBundle` is unchanged — it was already correct (uses `triplesec.Encryptor` with the raw password to unlock the P3SKB bundle, which is genuinely triplesec-encrypted with the password).
- The `/api/keybase/login` and `/api/keybase/getsalt` route handlers are unchanged.
- The PGP encryption / signing / verification code (`pgp.ts`) is unchanged.
- `package.json` is unchanged — `triplesec@4.0.3` was already a dependency and v4 of the package supports `version: 3` as a constructor option.

## If you ever revisit this code

**Do NOT** replace the triplesec call with "raw scrypt bytes [0..32]". That was my first (wrong) attempt at a fix — it produces a _different_ wrong pwh and Keybase will reject it just the same. The `pwh` is genuinely at bytes [192..224] of a 320-byte scrypt run, accessible only via triplesec's `resalt` with `version: 3` and `extra_keymaterial: 128`. Read the Go source linked above before touching this function.
