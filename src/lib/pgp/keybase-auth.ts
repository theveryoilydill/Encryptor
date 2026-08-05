/**
 * Keybase authentication + private key fetch flow (PDPKA).
 *
 * Keybase deprecated simple password-based API login. The current flow requires
 * Per-Device Public Key Authentication (PDPKA):
 *
 *  1. GET /api/keybase/getsalt?email_or_username=X&pdpka_login=true
 *     → { salt, login_session, csrf_token, pwh_version: 3 }
 *
 *  2. Stretch the password using triplesec VERSION 3 (not the default v4!)
 *     with extra_keymaterial=128. The first 32 bytes of `keys.extra` are the
 *     `pwh` (seeds the pdpka4 Ed25519 key); the next 32 bytes are the
 *     `eddsa_seed` (seeds the pdpka5 Ed25519 key). See
 *     github.com/keybase/client/blob/master/go/libkb/passphrase_stream.go
 *     and github.com/keybase/go-triplesec: pwhIndex=0, eddsaIndex=32 of `extra`,
 *     and `extra = scrypt_out[DkLen:]` where DkLen=192 for triplesec v3.
 *
 *     CRITICAL: triplesec's default version is 4 (no twofish, DkLen=160),
 *     which produces a completely different `extra` slice and therefore a
 *     wrong pwh + wrong Ed25519 keypair → Keybase returns
 *     `BAD_LOGIN_PASSWORD` (code 204) on /api/keybase/login. You MUST pass
 *     `version: 3` explicitly to `new Encryptor({ ..., version: 3 })`.
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
 *  6. Client decrypts the private key bundle (P3SKB / PGP3 Secret Key Block)
 *     using triplesec with the user's raw PASSWORD as the key — NOT pwh.
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

/** True if `url` points directly at the Keybase REST API (rather than our
 *  local Next.js proxy). When true, getSalt/loginAndFetchMe use the wire
 *  format Keybase actually expects (GET with query params for getsalt,
 *  form-encoded POST for login) and unwrap the `{ status, ... }` envelope
 *  the API wraps every response in. */
function isDirectKeybase(url: string): boolean {
  return /https?:\/\/[^/]*keybase\.io/.test(url);
}

/** Step 1: Get the salt + CSRF token for the username.
 *
 *  Two modes:
 *   - Proxy mode (default, `proxyUrl` starts with `/api/keybase/...`):
 *     POSTs `{ username }` as JSON to our local Next.js route, which already
 *     unwraps the Keybase `status` envelope and returns a clean SaltResponse.
 *   - Direct mode (`proxyUrl` is a `https://keybase.io/...` URL):
 *     Performs a GET against the Keybase REST API directly with query params
 *     `email_or_username` and `pdpka_login=true`, then unwraps the `status`
 *     envelope locally. Used by the live integration test in CI.
 */
export async function getSalt(
  username: string,
  proxyUrl = "/api/keybase/getsalt",
): Promise<SaltResponse> {
  const cleanUsername = username.trim().toLowerCase();

  let res: Response;
  if (isDirectKeybase(proxyUrl)) {
    // Keybase's getsalt.json is a GET endpoint that takes query params.
    const url = `${proxyUrl}?email_or_username=${encodeURIComponent(cleanUsername)}&pdpka_login=true`;
    res = await fetch(url, {
      headers: {
        Accept: "application/json",
        "User-Agent": "encryptor/1.0",
      },
    });
  } else {
    res = await fetch(proxyUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username: cleanUsername }),
    });
  }

  if (!res.ok) {
    const e = (await res.json().catch(() => ({}))) as {
      error?: string;
      status?: { desc?: string; name?: string };
    };
    throw new Error(
      e.error || e.status?.desc || e.status?.name || `Failed to get salt (HTTP ${res.status})`,
    );
  }

  const data = (await res.json()) as Partial<SaltResponse> & {
    status?: { code: number; name: string; desc?: string };
  };

  // Direct Keybase responses are wrapped in a `status` envelope; the proxy
  // already strips it. If we see one, check the code and surface any error.
  if (data.status && typeof data.status.code === "number") {
    if (data.status.code !== 0) {
      throw new Error(
        data.status.desc || data.status.name || "Keybase getsalt API error",
      );
    }
  }

  return {
    salt: data.salt as string,
    csrf_token: data.csrf_token as string,
    login_session: data.login_session as string,
    pwh_version: data.pwh_version ?? 3,
    uid: data.uid,
  };
}

/**
 * Step 2: Derive pwh + eddsa seed from the password using triplesec v3.
 *
 * Keybase's `pwh_version: 3` means: use triplesec VERSION 3 (the version
 * Keybase's Go client hard-codes as `ClientTriplesecVersion = 3`). v3 includes
 * twofish, so its DkLen = 2*MacKeyLen(48) + 3*CipherKeyLen(32) = 192 bytes of
 * cipher keys, and `keys.extra` starts at scrypt output byte 192.
 *
 * Then per passphrase_stream.go:
 *   pwh        = keys.extra[0..32]   (seeds the pdpka4 Ed25519 key)
 *   eddsa_seed = keys.extra[32..64]  (seeds the pdpka5 Ed25519 key)
 *
 * The 32-byte gap between v3 (DkLen=192) and v4 (DkLen=160) was the root cause
 * of `BAD_LOGIN_PASSWORD`: the JS triplesec library defaults to v4 unless you
 * explicitly pass `version: 3` to the Encryptor constructor, which produced
 * `keys.extra` from scrypt bytes [160..288] instead of [192..320] — a wrong
 * pwh that no longer matched what Keybase's server derived.
 */
export async function deriveKeysFromPassword(
  password: string,
  saltHex: string,
): Promise<DerivedKeys> {
  const triplesec = await import("triplesec");
  const { Buffer: TSBuffer, Encryptor } = triplesec;

  const salt = new TSBuffer(saltHex, "hex");
  // MUST pass version: 3 — Keybase's ClientTriplesecVersion is 3, not the
  // library default of 4. Without this, the derived pwh is wrong and login
  // fails with HTTP 401 BAD_LOGIN_PASSWORD.
  const enc = new Encryptor({
    key: new TSBuffer(password, "utf8"),
    version: 3,
  });

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
 * Step 5: Log in to Keybase.
 *
 * Two modes (mirrors getSalt):
 *   - Proxy mode (default, `loginUrl` starts with `/api/keybase/...`):
 *     POSTs the JSON body to our local Next.js route, which already performs
 *     the two-step login.json + me.json flow server-side and returns a flat
 *     KeybaseLoginResponse.
 *   - Direct mode (`loginUrl` is a `https://keybase.io/.../login.json` URL):
 *     Performs the full two-step flow client-side:
 *       1. POST `application/x-www-form-urlencoded` body to login.json with
 *          the CSRF cookie — extracts the session cookie from the response.
 *       2. GET me.json with `fields=basics,public_keys,private_keys` and the
 *          session cookie — returns the user's profile + encrypted private
 *          key bundle.
 *     Used by the live integration test in CI.
 */
export async function loginAndFetchMe(
  username: string,
  pdpka4: string,
  pdpka5: string,
  csrfToken: string,
  loginSession: string,
  loginUrl = "/api/keybase/login",
): Promise<KeybaseLoginResponse> {
  const cleanUsername = username.trim().toLowerCase();

  // ---- Direct Keybase mode: do the full two-step flow client-side. ----
  if (isDirectKeybase(loginUrl)) {
    const loginParams = new URLSearchParams();
    loginParams.set("email_or_username", cleanUsername);
    loginParams.set("pdpka4", pdpka4);
    loginParams.set("pdpka5", pdpka5);

    const loginRes = await fetch(loginUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Accept: "application/json",
        "User-Agent": "encryptor/1.0",
        Cookie: `csrf_token=${csrfToken}`,
      },
      body: loginParams.toString(),
    });

    if (!loginRes.ok) {
      throw new Error(`Login failed (HTTP ${loginRes.status})`);
    }

    const loginData = (await loginRes.json()) as {
      status: { code: number; name: string; desc?: string };
      session?: string;
    };

    if (!loginData.status || loginData.status.code !== 0) {
      throw new Error(
        loginData.status?.desc ||
          loginData.status?.name ||
          "Keybase login failed (wrong username or password?)",
      );
    }

    let sessionCookie = loginData.session ?? null;
    if (!sessionCookie) {
      const setCookie = loginRes.headers.get("set-cookie") || "";
      const m = setCookie.match(/session=([^;]+)/);
      sessionCookie = m ? m[1] : null;
    }
    if (!sessionCookie) {
      throw new Error("Keybase login succeeded but no session was returned.");
    }

    // Step 2: fetch me.json with the session cookie.
    const meRes = await fetch(
      "https://keybase.io/_/api/1.0/me.json?fields=basics,public_keys,private_keys",
      {
        headers: {
          Accept: "application/json",
          "User-Agent": "encryptor/1.0",
          Cookie: `session=${sessionCookie}`,
        },
      },
    );
    if (!meRes.ok) {
      throw new Error(`me.json failed (HTTP ${meRes.status})`);
    }
    const meData = (await meRes.json()) as {
      status: { code: number; name: string; desc?: string };
      me?: {
        basics?: { username?: string; uid?: string };
        pictures?: { primary?: { url?: string } };
        profile?: { full_name?: string };
        public_keys?: {
          primary?: { bundle?: string; kid?: string; fingerprint?: string };
        };
        private_keys?: { primary?: { bundle?: string; kid?: string } };
      };
    };
    if (!meData.status || meData.status.code !== 0 || !meData.me) {
      throw new Error(
        meData.status?.desc ||
          meData.status?.name ||
          "Keybase me.json call failed",
      );
    }
    const me = meData.me;
    return {
      username: me.basics?.username ?? cleanUsername,
      uid: me.basics?.uid ?? "",
      picture_url: me.pictures?.primary?.url,
      full_name: me.profile?.full_name,
      private_key_bundle: me.private_keys?.primary?.bundle ?? null,
      primary_key_fingerprint: me.public_keys?.primary?.fingerprint,
      primary_key_kid: me.public_keys?.primary?.kid,
    };
  }

  // ---- Proxy mode: POST JSON, the server-side route returns the flat
  //      KeybaseLoginResponse shape directly. ----
  const res = await fetch(loginUrl, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      username: cleanUsername,
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
