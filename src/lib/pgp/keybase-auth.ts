/**
 * Keybase authentication + private key fetch flow (PDPKA).
 *
 * Keybase deprecated simple password-based API login. The current flow requires
 * Per-Device Public Key Authentication (PDPKA):
 *
 *  1. GET /api/keybase/getsalt?email_or_username=X&pdpka_login=true
 *     → { salt, login_session, csrf_token, pwh_version: 3 }
 *
 *  2. scrypt(password, hex_decode(salt), N=2^15, r=8, p=1, dklen=128)
 *     Split the 128-byte output into:
 *       pwh         = bytes[ 0..32]  (the actual password hash)
 *       eddsa_seed  = bytes[32..64]  (seed for the pdpka5 EdDSA key)
 *       (remaining 64 bytes are unused for login)
 *
 *  3. Derive two EdDSA KeyManagers using kbpgp:
 *       km4 = KeyManager.generate({ seed: pwh })
 *       km5 = KeyManager.generate({ seed: eddsa_seed })
 *
 *  4. Generate two PGP-armored auth signatures using keybase-proofs.Auth:
 *       pdpka4 = Auth({ sig_eng: km4, host, user, nonce, session }).generate()
 *       pdpka5 = Auth({ sig_eng: km5, host, user, nonce, session }).generate()
 *
 *  5. POST /api/keybase/login { email_or_username, pdpka4, pdpka5, csrf_token, login_session }
 *     The server proxy forwards these to keybase.io/_/api/1.0/login.json with
 *     the CSRF cookie, then calls me.json with the returned session cookie to
 *     fetch the user's encrypted private key bundle.
 *
 *  6. Client decrypts the private key bundle with `pwh` (first 32 bytes of the
 *     scrypt output, hex-encoded) as the passphrase via openpgp.js.
 */
import { scrypt } from "scrypt-js";
import * as openpgp from "openpgp";

// kbpgp and keybase-proofs are heavy CommonJS libraries (kbpgp alone is ~1MB).
// We import them dynamically inside generatePdpkaSignatures() so they only
// load when the user actually clicks "Log in with Keybase", keeping the
// initial page bundle small and fast.

const SCRYPT_N = 32768; // 2^15
const SCRYPT_R = 8;
const SCRYPT_P = 1;
const SCRYPT_DKLEN = 128; // pwh(32) + eddsa(32) + dh(32) + lks(32)
const HOSTNAME = "keybase.io";

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
  uid?: string;
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

/** Derived key material from the scrypt output. */
export interface DerivedKeys {
  /** First 32 bytes — the password hash (also used as the private key bundle passphrase). */
  pwh: Uint8Array;
  /** Hex-encoded pwh — this is what openpgp.js needs as the passphrase. */
  pwhHex: string;
  /** Next 32 bytes — seed for the pdpka5 EdDSA key. */
  eddsaSeed: Uint8Array;
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

/** Step 2: Run scrypt and split the 128-byte output into pwh + eddsa seed. */
export async function deriveKeysFromPassword(
  password: string,
  saltHex: string,
): Promise<DerivedKeys> {
  const passwordBytes = new TextEncoder().encode(password);
  const saltBytes = hexToBytes(saltHex);
  const derived = await scrypt(
    passwordBytes,
    saltBytes,
    SCRYPT_N,
    SCRYPT_R,
    SCRYPT_P,
    SCRYPT_DKLEN,
  );
  const buf = new Uint8Array(derived);
  return {
    pwh: buf.slice(0, 32),
    pwhHex: bytesToHex(buf.slice(0, 32)),
    eddsaSeed: buf.slice(32, 64),
  };
}

/**
 * Step 3+4: Derive EdDSA KeyManagers from the password-derived seeds and
 * generate PGP-armored PDPKA signatures.
 *
 * Uses kbpgp (Keybase's own PGP library) and keybase-proofs (the Auth proof
 * generator) so the signatures exactly match what Keybase's server expects.
 */
export async function generatePdpkaSignatures(
  pwh: Uint8Array,
  eddsaSeed: Uint8Array,
  username: string,
  uid: string | undefined,
  loginSession: string,
): Promise<{ pdpka4: string; pdpka5: string }> {
  // Dynamically import the heavy CommonJS libraries only when needed.
  // This keeps the initial page bundle small (kbpgp alone is ~1MB).
  const kbpgpMod = await import("kbpgp");
  // Import Auth directly from lib/auth.js to avoid pulling in the DNS scraper
  // (which requires Node's 'dns' built-in and breaks browser bundles).
  const authMod = await import("keybase-proofs/lib/auth.js");
  const kb = (kbpgpMod as unknown as { kb: { KeyManager: typeof import("kbpgp").kb.KeyManager } }).kb;
  const Auth = (authMod as unknown as { Auth: typeof import("keybase-proofs/lib/auth.js").Auth }).Auth;
  const { KeyManager } = kb;

  if (!KeyManager || !Auth) {
    throw new Error("Failed to load kbpgp or keybase-proofs");
  }

  // Generate a 16-byte nonce (matches Keybase's generate_pdpka).
  const nonce = crypto.getRandomValues(new Uint8Array(16));

  // The user object Keybase expects.
  const user: Record<string, string> = {};
  if (uid) user.uid = uid;
  else user.username = username.trim().toLowerCase();

  // Derive both EdDSA KeyManagers from the password-derived seeds.
  const km4 = await generateKeyManager(KeyManager, pwh);
  const km5 = await generateKeyManager(KeyManager, eddsaSeed);

  // Generate the two PDPKA signatures.
  const pdpka4 = await signAuthChallenge(Auth, km4, user, loginSession, nonce);
  const pdpka5 = await signAuthChallenge(Auth, km5, user, loginSession, nonce);

  return { pdpka4, pdpka5 };
}

function generateKeyManager(
  KeyManager: typeof import("kbpgp").kb.KeyManager,
  seed: Uint8Array,
): Promise<InstanceType<typeof KeyManager>> {
  return new Promise((resolve, reject) => {
    KeyManager.generate(
      { seed: seed as unknown as Buffer, split: false },
      (err: Error | null, km: InstanceType<typeof KeyManager>) => {
        if (err) reject(err);
        else resolve(km);
      },
    );
  });
}

function signAuthChallenge(
  Auth: typeof import("keybase-proofs/lib/auth.js").Auth,
  km: InstanceType<typeof import("kbpgp").kb.KeyManager>,
  user: Record<string, string>,
  session: string,
  nonce: Uint8Array,
): Promise<string> {
  return new Promise((resolve, reject) => {
    const eng = new Auth({
      sig_eng: km.make_sig_eng(),
      host: HOSTNAME,
      user: { local: user },
      nonce: nonce as unknown as Buffer,
      session,
    });
    eng.generate(
      (err: Error | null, sig: { armored: string }) => {
        if (err) reject(err);
        else resolve(sig.armored);
      },
      { dohash: true },
    );
  });
}

/**
 * Step 5: Log in to Keybase (server-side proxy handles the actual API call).
 * Sends pdpka4 + pdpka5 (NOT the password or pwh) to the proxy.
 */
export async function loginAndFetchMe(
  username: string,
  pdpka4: string,
  pdpka5: string,
  csrfToken: string,
  loginSession: string,
  loginUrl = "/api/keybase/login",
): Promise<KeybaseLoginResponse> {
  const res = await fetch(loginUrl, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      username: username.trim().toLowerCase(),
      pdpka4,
      pdpka5,
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
 * High-level convenience: run the full login flow.
 * Returns the user's profile + decrypted private key.
 */
export async function loginWithPassword(
  username: string,
  password: string,
  proxies: {
    getsaltUrl: string;
    loginUrl: string;
  },
): Promise<{
  me: KeybaseLoginResponse;
  privateKey: openpgp.PrivateKey;
  pwhHex: string;
}> {
  // 1. Get salt
  const salt = await getSalt(username, proxies.getsaltUrl);

  // 2. Derive keys from password
  const keys = await deriveKeysFromPassword(password, salt.salt);

  // 3+4. Generate PDPKA signatures
  const { pdpka4, pdpka5 } = await generatePdpkaSignatures(
    keys.pwh,
    keys.eddsaSeed,
    username,
    salt.uid,
    salt.login_session,
  );

  // 5. Login + fetch me.json
  const me = await loginAndFetchMe(
    username,
    pdpka4,
    pdpka5,
    salt.csrf_token,
    salt.login_session,
    proxies.loginUrl,
  );

  if (!me.private_key_bundle) {
    throw new Error(
      "Your Keybase account has no private key bundle. Generate one in the Keybase app first.",
    );
  }

  // 6. Decrypt the private key bundle with pwhHex as the passphrase.
  const { privateKey } = await decryptPrivateKeyBundle(
    me.private_key_bundle,
    keys.pwhHex,
  );

  return { me, privateKey, pwhHex: keys.pwhHex };
}

/**
 * Decrypt the private key bundle returned by me.json.
 *
 * Keybase encrypts the bundle with the hex-encoded pwh (first 32 bytes of the
 * scrypt output) as the passphrase. We try a few candidate passphrases in case
 * Keybase changes their format.
 */
export async function decryptPrivateKeyBundle(
  bundle: string,
  pwhHex: string,
): Promise<{ privateKey: openpgp.PrivateKey; passphraseUsed: string }> {
  const candidates = [
    pwhHex,
    pwhHex.slice(0, 64), // first 32 bytes (same as pwhHex since it's already 64 chars)
    pwhHex.slice(64), // last 32 bytes (won't apply for our 32-byte pwh, but be defensive)
  ].filter((p, i, arr) => p && arr.indexOf(p) === i); // dedupe

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
