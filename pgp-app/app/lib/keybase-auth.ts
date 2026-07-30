/**
 * Keybase authentication + private key fetch flow.
 *
 * Flow:
 *  1. POST /api/keybase/getsalt { username }            → { salt, csrf_token, login_session }
 *  2. Client computes pwhash = scrypt(password, hex_decode(salt), N=32768, r=8, p=1, dklen=64)
 *  3. POST /api/keybase/login { username, pwhash_hex }  → { me, private_key_bundle }
 *  4. Client decrypts private_key_bundle with pwhash_hex (first 32 bytes) via openpgp.js
 *
 * The server keeps the CSRF token + login_session in memory only for the duration
 * of the request. The browser holds no Keybase cookies (we proxy everything).
 */
import { scrypt } from "scrypt-js";
import * as openpgp from "openpgp";

const SCRYPT_N = 32768;
const SCRYPT_R = 8;
const SCRYPT_P = 1;
const SCRYPT_DKLEN = 64;

/** Convert a hex string to a Uint8Array. */
function hexToBytes(hex: string): Uint8Array {
  const clean = hex.replace(/^0x/, "");
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.substr(i * 2, 2), 16);
  }
  return out;
}

/** Convert a Uint8Array to a lowercase hex string. */
function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

export interface SaltResponse {
  salt: string;
  csrf_token: string;
  login_session: string;
  pwh_version: number;
  uid: string;
}

export interface KeybaseLoginResponse {
  username: string;
  uid: string;
  picture_url?: string;
  full_name?: string;
  /** ASCII-armored encrypted private key bundle, or null if user has no key. */
  private_key_bundle: string | null;
  /** Public key fingerprint (hex). */
  primary_key_fingerprint?: string;
  primary_key_kid?: string;
}

/** Step 1: Get the salt + CSRF token for the username. */
export async function getSalt(
  username: string,
  proxyUrl = "/api/keybase/getsalt",
): Promise<SaltResponse> {
  const res = await fetch(proxyUrl, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username: username.trim().toLowerCase() }),
  });
  if (!res.ok) {
    const e = (await res.json().catch(() => ({}))) as { error?: string };
    throw new Error(e.error || `Failed to get salt (HTTP ${res.status})`);
  }
  return (await res.json()) as SaltResponse;
}

/** Step 2: Compute the 64-byte pwhash from password + salt using scrypt. */
export async function computePwHash(password: string, saltHex: string): Promise<string> {
  const passwordBytes = new TextEncoder().encode(password);
  const saltBytes = hexToBytes(saltHex);
  const key = await scrypt(passwordBytes, saltBytes, SCRYPT_N, SCRYPT_R, SCRYPT_P, SCRYPT_DKLEN);
  return bytesToHex(new Uint8Array(key));
}

/**
 * Convenience: get salt + compute pwhash in one call.
 * Returns { pwhash_hex, salt }.
 */
export async function derivePwHash(
  username: string,
  password: string,
  getsaltUrl = "/api/keybase/getsalt",
): Promise<{ pwhashHex: string; salt: SaltResponse }> {
  const salt = await getSalt(username, getsaltUrl);
  const pwhashHex = await computePwHash(password, salt.salt);
  return { pwhashHex, salt };
}

/** Step 3: Log in to Keybase (server-side proxy handles the actual API call). */
export async function loginAndFetchMe(
  username: string,
  pwhashHex: string,
  csrfToken: string,
  loginSession: string,
  loginUrl = "/api/keybase/login",
): Promise<KeybaseLoginResponse> {
  const res = await fetch(loginUrl, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      username: username.trim().toLowerCase(),
      pwhash: pwhashHex,
      csrf_token: csrfToken,
      login_session: loginSession,
    }),
  });
  if (!res.ok) {
    const e = (await res.json().catch(() => ({}))) as { error?: string };
    throw new Error(e.error || `Login failed (HTTP ${res.status})`);
  }
  return (await res.json()) as KeybaseLoginResponse;
}

/**
 * Step 4: Decrypt the private key bundle returned by me.json.
 *
 * Keybase encrypts the private key bundle with a passphrase derived from the
 * user's pwhash. We try multiple candidate passphrases (full pwhash hex, first
 * 32 bytes hex, last 32 bytes hex) to maximize the chance of success.
 */
export async function decryptPrivateKeyBundle(
  bundle: string,
  pwhashHex: string,
): Promise<{ privateKey: openpgp.PrivateKey; passphraseUsed: string }> {
  const candidates = [
    pwhashHex,
    pwhashHex.slice(0, 64), // first 32 bytes
    pwhashHex.slice(64), // last 32 bytes
  ];

  let lastError: Error | null = null;
  for (const passphrase of candidates) {
    try {
      const key = await openpgp.readKey({ armoredKey: bundle });
      if (!key.isPrivate()) {
        throw new Error("Bundle is not a private key.");
      }
      if (key.isDecrypted()) {
        return { privateKey: key as openpgp.PrivateKey, passphraseUsed: "" };
      }
      const decrypted = await openpgp.decryptKey({
        privateKey: key as openpgp.PrivateKey,
        passphrase,
      });
      return { privateKey: decrypted, passphraseUsed: passphrase };
    } catch (e) {
      lastError = e as Error;
    }
  }

  throw new Error(
    `Could not decrypt private key bundle. Keybase's auth protocol may have changed, or the password is incorrect. Last error: ${lastError?.message ?? "unknown"}`,
  );
}

/** Convert a PrivateKey back to armored form (decrypted or re-encrypted). */
export async function privateKeyToArmored(
  key: openpgp.PrivateKey,
  passphrase?: string,
): Promise<string> {
  if (passphrase) {
    const encrypted = await openpgp.encryptKey({ privateKey: key, passphrase });
    return encrypted.armor();
  }
  return key.armor();
}
