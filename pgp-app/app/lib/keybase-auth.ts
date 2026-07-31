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
import * as openpgp from "openpgp";

// triplesec, kbpgp, and keybase-proofs are heavy CommonJS libraries.
// We import them dynamically inside the functions that need them so they
// only load when the user actually clicks "Log in with Keybase", keeping
// the initial page bundle small and fast.

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

/**
 * Step 2: Derive pwh + eddsa seed from the password using triplesec's resalt.
 *
 * Keybase uses triplesec (not raw scrypt) to derive key material. triplesec's
 * `kdf` method runs scrypt with dkLen = hmac_key(96) + aes(32) + twofish(32) +
 * salsa20(32) + extra_keymaterial(128) = 320 bytes, then splits the output:
 *   bytes 0..191  → cipher keys (hmac, aes, twofish, salsa20)
 *   bytes 192..319 → extra key material (pwh + eddsa + dh + lks)
 *
 * The pwh is at bytes 192..224 of the scrypt output, NOT bytes 0..32.
 * This was the root cause of the "bad passphrase" login error.
 */
export async function deriveKeysFromPassword(
  password: string,
  saltHex: string,
): Promise<DerivedKeys> {
  const triplesec = await import("triplesec");
  const { Buffer: TSBuffer, Encryptor } = triplesec;

  const salt = new TSBuffer(saltHex, "hex");
  const enc = new Encryptor({ key: new TSBuffer(password, "utf8") });

  const keys = await new Promise<{
    extra: { toString: (enc: string) => string; slice: (a: number, b: number) => { toString: (enc: string) => string } };
  }>((resolve, reject) => {
    enc.resalt(
      { salt, extra_keymaterial: 128, progress_hook: () => {} },
      (err: Error | null, keys: { extra: { toString: (enc: string) => string; slice: (a: number, b: number) => { toString: (enc: string) => string } } }) => {
        if (err) reject(err);
        else resolve(keys);
      },
    );
  });

  const pwhHex = keys.extra.slice(0, 32).toString("hex");
  const eddsaHex = keys.extra.slice(32, 64).toString("hex");

  return {
    pwh: hexToBytes(pwhHex),
    pwhHex,
    eddsaSeed: hexToBytes(eddsaHex),
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

  // 6. Decrypt the private key bundle.
  // The P3SKB bundle from me.json is encrypted with the user's PASSWORD
  // (not the pwh) via triplesec. We decode + unlock + parse it.
  const privateKey = await decryptPrivateKeyBundle(
    me.private_key_bundle,
    password,
  );

  return { me, privateKey, pwhHex: keys.pwhHex };
}

/**
 * Decrypt the private key bundle returned by me.json.
 *
 * The bundle is a Keybase P3SKB (PGP3 Secret Key Block) — a MessagePack-
 * encoded packet that wraps a PGP private key encrypted with triplesec
 * using the user's PASSWORD (not the pwh) as the key.
 *
 * Flow:
 *  1. Decode the P3SKB packet using kbpgp's unbox_decode
 *  2. Unlock (decrypt) the packet with triplesec using the password as key
 *  3. Parse the decrypted bytes as a binary PGP private key via openpgp.js
 *  4. The key is already decrypted (no passphrase needed)
 */
export async function decryptPrivateKeyBundle(
  bundle: string,
  password: string,
): Promise<openpgp.PrivateKey> {
  // Dynamically import the heavy CommonJS libraries.
  const triplesec = await import("triplesec");
  const kbpgp = await import("kbpgp");
  const { Buffer: TSBuffer, Encryptor } = triplesec;
  const { unbox_decode } = (kbpgp as unknown as { kb: { unbox_decode: (arg: { armored: string }) => [Error | null, unknown] } }).kb;

  // 1. Decode the P3SKB packet
  const [decodeErr, packet] = unbox_decode({ armored: bundle });
  if (decodeErr || !packet) {
    throw new Error(`Failed to decode P3SKB bundle: ${decodeErr?.message ?? "unknown error"}`);
  }

  // 2. Unlock with triplesec (password as key)
  const tsEnc = new Encryptor({ key: new TSBuffer(password, "utf8") });
  const unlockErr = await new Promise<Error | null>((resolve) => {
    (packet as { unlock: (arg: { tsenc: unknown }, cb: (err: Error | null) => void) => void }).unlock(
      { tsenc: tsEnc },
      (err: Error | null) => resolve(err),
    );
  });
  if (unlockErr) {
    throw new Error(`Failed to unlock P3SKB bundle (wrong password?): ${unlockErr.message}`);
  }

  // 3. Extract the decrypted private key data
  const rawPriv = (packet as { priv: { data: Uint8Array } }).priv.data;

  // 4. Parse as a binary PGP private key
  try {
    const key = await openpgp.readKey({ binaryKey: rawPriv });
    if (!key.isPrivate()) {
      throw new Error("Decoded key is not a private key.");
    }
    return key as openpgp.PrivateKey;
  } catch (e) {
    throw new Error(`Failed to parse PGP private key from bundle: ${(e as Error).message}`);
  }
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
