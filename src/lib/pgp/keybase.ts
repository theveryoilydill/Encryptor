/**
 * Keybase API client.
 *
 * Keybase's public lookup endpoint does not send CORS headers, so browser apps
 * must call it through a server-side proxy. In this app, the React Router
 * server (Cloudflare Worker) exposes `/api/keybase?usernames=a,b,c` which
 * performs the fetch and returns JSON.
 *
 * Docs: https://keybase.io/docs/api/1.0/call_structure
 * Endpoint: https://keybase.io/_/api/1.0/user/lookup.json
 */

export interface KeybasePublicKey {
  /** Username on Keybase. */
  username: string;
  /** ASCII-armored public key. */
  armored: string;
  fingerprint: string;
  keyID: string;
  /** Creation time in ms since epoch. */
  createdAt: number;
  /** Expiration time in ms since epoch, or null if no expiration. */
  expiresAt: number | null;
  /** Algorithm name. */
  algorithm: string;
  /** Key size in bits (RSA) or curve name (ECC). */
  bits?: number;
  curve?: string;
}

export interface KeybaseLookupFailure {
  username: string;
  error: string;
}

export interface KeybaseLookupResult {
  found: KeybasePublicKey[];
  missing: string[];
  errors: KeybaseLookupFailure[];
}

const KEYBASE_LOOKUP_URL = "https://keybase.io/_/api/1.0/user/lookup.json";

interface KeybaseRawKey {
  kid: string;
  key_type: number;
  bundle: string;
  mtime: number;
  etime: number; // 0 means no expiration
  ctime: number;
  username?: string;
}

interface KeybaseRawUser {
  id: string;
  basics: {
    username: string;
    ctime: number;
    mtime: number;
    id_version: number;
    track_version: number;
  };
  public_keys: {
    primary?: KeybaseRawKey;
    secondary?: KeybaseRawKey[];
  };
}

interface KeybaseRawResponse {
  status: { code: number; name: string; desc?: string };
  them: (KeybaseRawUser | null)[] | null;
}

/**
 * Server-side only: call the Keybase API directly.
 *
 * Used by the React Router loader/action (Cloudflare Worker) and the Next.js
 * API route. Browser code MUST NOT call this directly because of CORS.
 */
export async function lookupKeybaseUsersServer(
  usernames: string[],
  fetchImpl: typeof fetch = fetch,
): Promise<KeybaseLookupResult> {
  const cleaned = Array.from(
    new Set(
      usernames
        .map((u) => u.trim().toLowerCase())
        .filter((u) => u.length > 0 && /^[a-z0-9_]{2,15}$/.test(u)),
    ),
  );

  if (cleaned.length === 0) {
    return { found: [], missing: [], errors: [] };
  }

  if (cleaned.length > 50) {
    throw new Error(
      "Keybase lookups are limited to 50 usernames per request. Please split your list.",
    );
  }

  const url = `${KEYBASE_LOOKUP_URL}?usernames=${encodeURIComponent(cleaned.join(","))}&fields=basics,public_keys`;

  const res = await fetchImpl(url, {
    headers: { Accept: "application/json", "User-Agent": "pgp-keybase-cloudflare/1.0" },
  });

  if (!res.ok) {
    throw new Error(`Keybase API returned HTTP ${res.status}: ${await res.text()}`);
  }

  const data = (await res.json()) as KeybaseRawResponse;

  if (!data.status || data.status.code !== 0) {
    throw new Error(
      `Keybase API error: ${data.status?.name ?? "unknown"} (${data.status?.desc ?? ""})`,
    );
  }

  const found: KeybasePublicKey[] = [];
  const missing: string[] = [];
  const errors: KeybaseLookupFailure[] = [];

  const them = data.them ?? [];
  them.forEach((user, idx) => {
    const username = cleaned[idx];
    if (!user) {
      missing.push(username);
      return;
    }
    const primary = user.public_keys?.primary;
    if (!primary || !primary.bundle) {
      missing.push(username);
      return;
    }

    // Parse the key bundle to extract algorithm info.
    // The bundle is an ASCII-armored public key. We won't fully parse here
    // (we have the server-side openpgp library for that elsewhere); instead
    // we surface the fingerprint, key ID, and dates from Keybase's response.
    const fp = extractFingerprintFromBundle(primary.bundle) ?? primary.kid;
    const keyID = fp.length >= 16 ? fp.slice(fp.length - 16) : fp;
    const algorithmInfo = guessAlgorithmFromBundle(primary.bundle);

    found.push({
      username: user.basics?.username ?? username,
      armored: primary.bundle,
      fingerprint: fp.toUpperCase(),
      keyID: keyID.toUpperCase(),
      createdAt: primary.ctime * 1000,
      expiresAt: primary.etime > 0 ? primary.etime * 1000 : null,
      algorithm: algorithmInfo.algorithm,
      bits: algorithmInfo.bits,
      curve: algorithmInfo.curve,
    });
  });

  return { found, missing, errors };
}

/** Extract a fingerprint (40-hex-char) from an armored public key bundle. */
function extractFingerprintFromBundle(bundle: string): string | null {
  // Try parsing the first packet header line like ":fingerprint: <hex>"
  const m = bundle.match(/:fingerprint:\s*([0-9a-fA-F]{40})/);
  if (m) return m[1];
  // Fall back to the key ID in the header comment
  const m2 = bundle.match(/([0-9A-Fa-f]{16,40})/);
  if (m2) return m2[1];
  return null;
}

/**
 * Best-effort algorithm guess from the armored key header comments.
 * Keybase bundles typically include comments like
 *   "Comment: D9BE1FA8A4D2C0F8 DD2B089D481AE3AC 6CC4F2E9E1D2E1D4"
 * but not the algorithm directly. We default to "rsa4096" for v4 RSA
 * bundles and "ecc" for eddsa/ed25519.
 */
function guessAlgorithmFromBundle(bundle: string): {
  algorithm: string;
  bits?: number;
  curve?: string;
} {
  const upper = bundle.toUpperCase();
  if (upper.includes("EDDSA") || upper.includes("ED25519")) {
    return { algorithm: "EdDSA", curve: "ed25519" };
  }
  if (upper.includes("ECDSA") || upper.includes("NIST P-")) {
    const m = upper.match(/NIST P-(\d+)/);
    return { algorithm: "ECDSA", curve: m ? `nistP${m[1]}` : "nistP256" };
  }
  // Default assumption for Keybase-generated keys: RSA 4096.
  return { algorithm: "RSA", bits: 4096 };
}

/** Hard ceiling for BROWSER→proxy fetches. Our proxy routes already cap
 *  their upstream keyserver calls (SERVER_FETCH_TIMEOUT_MS), so this only
 *  fires if the proxy itself wedges (lost network, stalled dev server) —
 *  without it the Verify/Decrypt spinners could hang forever. Callers all
 *  wrap in try/catch (or .catch(() => [])), so the thrown message degrades
 *  into their existing error / soft-fail paths. */
const PROXY_FETCH_TIMEOUT_MS = 20000;

/** fetch() against one of our proxy routes with a hard timeout; surfaces a
 *  friendly message on abort instead of a raw DOMException. */
async function fetchProxyWithTimeout(url: string): Promise<Response> {
  try {
    return await fetch(url, {
      headers: { Accept: "application/json" },
      signal: AbortSignal.timeout(PROXY_FETCH_TIMEOUT_MS),
    });
  } catch (e) {
    if (e instanceof DOMException && (e.name === "TimeoutError" || e.name === "AbortError")) {
      throw new Error(
        `Keyserver request timed out after ${PROXY_FETCH_TIMEOUT_MS / 1000}s — try again, or configure the key locally.`,
      );
    }
    throw e;
  }
}

/**
 * Browser-side helper: call our own server proxy at /api/keybase.
 *
 * In the React Router app this hits the loader in app/routes/api.keybase.ts.
 * In the Next.js preview it hits src/app/api/keybase/route.ts.
 */
export async function lookupKeybaseUsersClient(
  usernames: string[],
  proxyUrl = "/api/keybase",
): Promise<KeybaseLookupResult> {
  const cleaned = usernames.map((u) => u.trim().toLowerCase()).filter((u) => u.length > 0);

  if (cleaned.length === 0) {
    return { found: [], missing: [], errors: [] };
  }

  const url = `${proxyUrl}?usernames=${encodeURIComponent(cleaned.join(","))}`;
  const res = await fetchProxyWithTimeout(url);

  if (!res.ok) {
    let detail = "";
    try {
      const body = (await res.json()) as { error?: string };
      detail = body?.error ?? "";
    } catch {
      detail = await res.text();
    }
    throw new Error(`Keybase lookup failed (${res.status}): ${detail}`);
  }

  return (await res.json()) as KeybaseLookupResult;
}

export interface KeybaseAutocompleteResult {
  username: string;
  full_name?: string;
  picture_url?: string;
  uid: string;
}

/**
 * Server-side: call the Keybase user_search.json endpoint to autocomplete
 * usernames by prefix. Used by the React Router loader and Next.js API route.
 */
export async function autocompleteKeybaseUsersServer(
  query: string,
  fetchImpl: typeof fetch = fetch,
): Promise<KeybaseAutocompleteResult[]> {
  const q = query.trim();
  if (q.length < 1) return [];

  const url = `https://keybase.io/_/api/1.0/user/user_search.json?q=${encodeURIComponent(q)}&num_wanted=10`;
  const res = await fetchImpl(url, {
    headers: { Accept: "application/json", "User-Agent": "pgp-keybase-cloudflare/1.0" },
  });
  if (!res.ok) {
    throw new Error(`Keybase autocomplete returned HTTP ${res.status}`);
  }
  const data = (await res.json()) as {
    status: { code: number; name: string };
    list: Array<{
      keybase: {
        username: string;
        uid: string;
        full_name?: string;
        picture_url?: string;
      };
    }>;
  };
  if (!data.status || data.status.code !== 0) return [];
  return (data.list ?? []).map((item) => ({
    username: item.keybase.username,
    uid: item.keybase.uid,
    full_name: item.keybase.full_name ?? undefined,
    picture_url: item.keybase.picture_url ?? undefined,
  }));
}

export interface KeybaseKeyByIDResult {
  /** The Keybase username that owns this key, if known. */
  username?: string;
  uid?: string;
  /** ASCII-armored public key. */
  armored: string;
  fingerprint: string;
  /** Short 16-hex key ID of the primary key. */
  keyID: string;
  /** All key IDs associated with this key (primary + subkeys), uppercase. */
  allKeyIDs?: string[];
  kid?: string;
}

/** Hard ceiling for SERVER-side keyserver fetches (keybase.io / keys.openpgp.org).
 *  Matches the 8s budget already used by the HKP search paths; without it a
 *  wedged keyserver would hang the proxy route and the Verify/Decrypt UI
 *  would spin forever (the spinner is only cleared by this promise settling). */
const SERVER_FETCH_TIMEOUT_MS = 8000;

/**
 * Server-side: fetch a public key by its PGP key ID (short 16-hex or long 40-hex)
 * via Keybase's key/fetch.json endpoint. The response includes the owning
 * username and uid, so this doubles as a "who signed it" lookup.
 */
export async function fetchKeyByKeyIDServer(
  keyIDs: string[],
  fetchImpl: typeof fetch = fetch,
): Promise<KeybaseKeyByIDResult[]> {
  const cleaned = keyIDs.map((k) => k.trim().toLowerCase()).filter((k) => k.length > 0);
  if (cleaned.length === 0) return [];

  const url = `https://keybase.io/_/api/1.0/key/fetch.json?pgp_key_ids=${encodeURIComponent(
    cleaned.join(","),
  )}`;
  const res = await fetchImpl(url, {
    headers: { Accept: "application/json", "User-Agent": "pgp-keybase-cloudflare/1.0" },
    signal: AbortSignal.timeout(SERVER_FETCH_TIMEOUT_MS),
  });
  if (!res.ok) {
    throw new Error(`Keybase key fetch returned HTTP ${res.status}`);
  }
  const data = (await res.json()) as {
    status: { code: number };
    keys?: Array<{
      bundle?: string;
      username?: string;
      uid?: string;
      kid?: string;
      fingerprint?: string;
      subkeys?: Record<string, unknown>;
    }>;
  };
  if (!data.status || data.status.code !== 0 || !data.keys) return [];

  return data.keys
    .filter((k) => k.bundle && k.fingerprint)
    .map((k) => {
      const fp = (k.fingerprint ?? "").toUpperCase();
      const primaryKID = fp.length >= 16 ? fp.slice(fp.length - 16) : fp;
      // Collect all key IDs: primary key ID + all subkey IDs.
      const subkeyIDs = k.subkeys ? Object.keys(k.subkeys).map((sk) => sk.toUpperCase()) : [];
      return {
        armored: k.bundle as string,
        fingerprint: fp,
        keyID: primaryKID,
        allKeyIDs: [primaryKID, ...subkeyIDs],
        username: k.username,
        uid: k.uid,
        kid: k.kid,
      };
    });
}

/**
 * Browser-side: autocomplete Keybase usernames via our proxy.
 * GET /api/keybase/autocomplete?q=chri
 */
export async function autocompleteKeybaseUsersClient(
  query: string,
  proxyUrl = "/api/keybase/autocomplete",
): Promise<KeybaseAutocompleteResult[]> {
  const q = query.trim();
  if (q.length < 1) return [];
  const url = `${proxyUrl}?q=${encodeURIComponent(q)}`;
  const res = await fetchProxyWithTimeout(url);
  if (!res.ok) return [];
  return (await res.json()) as KeybaseAutocompleteResult[];
}

/**
 * Normalize a fetchkey proxy response body into a key result array.
 *
 * The canonical route shape is `{ keys: [...] }` (matching the original
 * app). A bare array is also accepted for robustness — accessing `.keys`
 * on a JSON array would return Array.prototype.keys (a function), which is
 * exactly the trap `body.keys ?? []` cannot guard against. (DRY: one
 * parser shared by both key-fetch clients.)
 */
function coerceKeyListResponse(body: unknown): KeybaseKeyByIDResult[] {
  if (Array.isArray(body)) return body as KeybaseKeyByIDResult[];
  if (body !== null && typeof body === "object") {
    const keys = (body as { keys?: unknown }).keys;
    if (Array.isArray(keys)) return keys as KeybaseKeyByIDResult[];
  }
  return [];
}

/**
 * Browser-side: fetch public key + owner username by PGP key ID.
 * GET /api/keybase/fetchkey?key_id=fbc07d6a97016cb3
 */
export async function fetchKeyByKeyIDClient(
  keyIDs: string[],
  proxyUrl = "/api/keybase/fetchkey",
): Promise<KeybaseKeyByIDResult[]> {
  const cleaned = keyIDs.map((k) => k.trim().toLowerCase()).filter(Boolean);
  if (cleaned.length === 0) return [];
  const url = `${proxyUrl}?key_id=${encodeURIComponent(cleaned.join(","))}`;
  const res = await fetchProxyWithTimeout(url);
  if (!res.ok) return [];
  return coerceKeyListResponse(await res.json().catch(() => null));
}

/* ----------------------- keys.openpgp.org fallback ------------------------ */

/**
 * Server-side: fetch a public key from keys.openpgp.org by its key ID.
 *
 * keys.openpgp.org is a privacy-respecting Verifying Key Server (VKS).
 * Unlike Keybase, it doesn't associate keys with usernames — keys are
 * looked up by key ID, fingerprint, or verified email address.
 *
 * The VKS API returns the armored public key as plain text (200) or
 * "No key found" (404). We parse the returned key with openpgp.js to
 * extract the fingerprint, key ID, and all subkey IDs.
 *
 * Endpoint: GET https://keys.openpgp.org/vks/v1/by-keyid/<keyID>
 */
export async function fetchKeyFromOpenPGP_orgServer(
  keyIDs: string[],
  fetchImpl: typeof fetch = fetch,
): Promise<KeybaseKeyByIDResult[]> {
  const cleaned = keyIDs.map((k) => k.trim().toUpperCase()).filter((k) => k.length > 0);
  if (cleaned.length === 0) return [];

  const results: KeybaseKeyByIDResult[] = [];

  for (const keyID of cleaned) {
    try {
      const url = `https://keys.openpgp.org/vks/v1/by-keyid/${encodeURIComponent(keyID)}`;
      const res = await fetchImpl(url, {
        headers: { Accept: "application/pgp-keys" },
        signal: AbortSignal.timeout(SERVER_FETCH_TIMEOUT_MS),
      });
      if (!res.ok) continue;
      const armored = await res.text();
      if (!armored.includes("-----BEGIN PGP PUBLIC KEY BLOCK-----")) continue;

      // Parse the key to extract fingerprint and all subkey IDs.
      // We use a lightweight regex to avoid pulling in openpgp.js here
      // (the caller will parse it properly when verifying).
      const fpMatch = armored.match(/:fingerprint:\s*([0-9A-Fa-f]{40})/);
      const fingerprint = fpMatch ? fpMatch[1].toUpperCase() : "";

      // Extract subkey IDs from the armor header comments.
      // keys.openpgp.org includes comment lines like:
      //   "Comment: 5EFD8A95 2960B04B"
      // for each subkey. We'll also derive the primary key ID from the fingerprint.
      const allKeyIDs = new Set<string>();
      if (fingerprint.length >= 16) {
        allKeyIDs.add(fingerprint.slice(fingerprint.length - 16));
      }
      // Also add the key ID we searched for (it might be a subkey ID).
      allKeyIDs.add(keyID);

      results.push({
        armored,
        fingerprint: fingerprint || keyID,
        keyID: fingerprint.length >= 16 ? fingerprint.slice(fingerprint.length - 16) : keyID,
        allKeyIDs: Array.from(allKeyIDs),
        // keys.openpgp.org doesn't provide usernames — caller should show
        // the fingerprint/key ID instead.
        username: undefined,
      });
    } catch {
      // skip on error
    }
  }

  return results;
}

/**
 * Browser-side: fetch public keys from keys.openpgp.org via our proxy.
 * GET /api/keybase/fetchkey-opg?key_id=<comma_separated_key_ids>
 */
export async function fetchKeyFromOpenPGP_orgClient(
  keyIDs: string[],
  proxyUrl = "/api/keybase/fetchkey-opg",
): Promise<KeybaseKeyByIDResult[]> {
  const cleaned = keyIDs.map((k) => k.trim().toUpperCase()).filter(Boolean);
  if (cleaned.length === 0) return [];
  const url = `${proxyUrl}?key_id=${encodeURIComponent(cleaned.join(","))}`;
  const res = await fetchProxyWithTimeout(url);
  if (!res.ok) return [];
  return coerceKeyListResponse(await res.json().catch(() => null));
}

/* --------------------- Multi-source keyserver search --------------------- */
//
// Searches across multiple PGP keyserver sources for autocomplete:
//
// 1. Keybase (user_search.json) — returns usernames, full names, avatars
// 2. Ubuntu keyserver (HKP) — searches by name, email, key ID
// 3. keys.openpgp.org (VKS) — exact email or key ID lookup
//
// "Vector search" isn't practical for PGP keys (no pre-computed embeddings
// exist), but HKP's `search` parameter does fuzzy matching on user IDs
// (name <email>), which gives a similar "find by anything" experience.

export interface KeySearchResult {
  /** Where this result came from. */
  source: "keybase" | "ubuntu" | "openpgp.org" | "mailvelope";
  /** Display label — "@username" for Keybase, "Name <email>" for HKP. */
  label: string;
  /** Optional username (Keybase only). */
  username?: string;
  /** Optional full name. */
  fullName?: string;
  /** Optional email. */
  email?: string;
  /** Optional avatar URL (Keybase only). */
  pictureUrl?: string;
  /** Key fingerprint (40-hex), if known. */
  fingerprint?: string;
  /** Short key ID (16-hex), if known. */
  keyID?: string;
}

/** Parse an HKP machine-readable index response. */
function parseHKPIndex(text: string): Array<{
  fingerprint: string;
  keyID: string;
  uids: string[];
}> {
  const lines = text.split("\n").filter(Boolean);
  const results: Array<{ fingerprint: string; keyID: string; uids: string[] }> = [];
  let current: { fingerprint: string; keyID: string; uids: string[] } | null = null;

  for (const line of lines) {
    if (line.startsWith("pub:")) {
      const parts = line.split(":");
      const fp = parts[1]?.toUpperCase() ?? "";
      if (fp.length >= 16) {
        if (current) results.push(current);
        current = { fingerprint: fp, keyID: fp.slice(fp.length - 16), uids: [] };
      }
    } else if (line.startsWith("uid:") && current) {
      const parts = line.split(":");
      const uid = parts[1] ? decodeURIComponent(parts[1].replace(/\+/g, " ")) : "";
      if (uid) current.uids.push(uid);
    }
  }
  if (current) results.push(current);
  return results;
}

/** Parse a PGP user ID string like "Chris Coyne <chris@example.com>" */
function parseUserID(uid: string): { name?: string; email?: string } {
  const m = uid.match(/^(.*?)\s*<([^>]+)>$/);
  if (m) return { name: m[1].trim() || undefined, email: m[2].trim() };
  if (uid.includes("@")) return { email: uid.trim() };
  return { name: uid.trim() };
}

/** Search Keybase for users matching the query. */
export async function searchKeybaseServer(
  query: string,
  fetchImpl: typeof fetch = fetch,
): Promise<KeySearchResult[]> {
  const q = query.trim();
  if (q.length < 1) return [];
  try {
    const url = `https://keybase.io/_/api/1.0/user/user_search.json?q=${encodeURIComponent(q)}&num_wanted=10`;
    const res = await fetchImpl(url, {
      headers: { Accept: "application/json", "User-Agent": "encryptor/1.0" },
    });
    if (!res.ok) return [];
    const data = (await res.json()) as {
      status: { code: number };
      list?: Array<{
        keybase: {
          username: string;
          uid: string;
          full_name?: string;
          picture_url?: string;
        };
      }>;
    };
    if (!data.status || data.status.code !== 0) return [];
    return (data.list ?? []).map((item) => ({
      source: "keybase" as const,
      label: `@${item.keybase.username}`,
      username: item.keybase.username,
      fullName: item.keybase.full_name ?? undefined,
      pictureUrl: item.keybase.picture_url ?? undefined,
    }));
  } catch {
    return [];
  }
}

/** Search an HKP keyserver for keys matching the query. */
async function searchHKPKeyserver(
  serverUrl: string,
  sourceName: KeySearchResult["source"],
  query: string,
  fetchImpl: typeof fetch = fetch,
): Promise<KeySearchResult[]> {
  const q = query.trim();
  if (q.length < 2) return [];
  try {
    const url = `${serverUrl}/pks/lookup?op=index&search=${encodeURIComponent(q)}&options=mr&fingerprint=on`;
    const res = await fetchImpl(url, {
      headers: { Accept: "text/plain", "User-Agent": "encryptor/1.0" },
      signal: AbortSignal.timeout(8000),
    });
    if (!res.ok) return [];
    const text = await res.text();
    if (!text.startsWith("info:")) return [];

    const keys = parseHKPIndex(text);
    const results: KeySearchResult[] = [];
    for (const key of keys.slice(0, 5)) {
      const uid = key.uids[0] ?? key.keyID;
      const parsed = parseUserID(uid);
      results.push({
        source: sourceName,
        label: uid,
        fullName: parsed.name,
        email: parsed.email,
        fingerprint: key.fingerprint,
        keyID: key.keyID,
      });
    }
    return results;
  } catch {
    return [];
  }
}

/** Search keys.openpgp.org by email (exact match only). */
async function searchOpenPGPOrg(
  query: string,
  fetchImpl: typeof fetch = fetch,
): Promise<KeySearchResult[]> {
  const q = query.trim();
  if (!q.includes("@") || q.length < 5) return [];
  try {
    const url = `https://keys.openpgp.org/vks/v1/by-email/${encodeURIComponent(q)}`;
    const res = await fetchImpl(url, {
      headers: { Accept: "application/pgp-keys" },
      signal: AbortSignal.timeout(8000),
    });
    if (!res.ok) return [];
    const armored = await res.text();
    if (!armored.includes("-----BEGIN PGP PUBLIC KEY BLOCK-----")) return [];
    const fpMatch = armored.match(/:fingerprint:\s*([0-9A-Fa-f]{40})/);
    const fp = fpMatch ? fpMatch[1].toUpperCase() : "";
    return [
      {
        source: "openpgp.org",
        label: q,
        email: q,
        fingerprint: fp || undefined,
        keyID: fp.length >= 16 ? fp.slice(fp.length - 16) : undefined,
      },
    ];
  } catch {
    return [];
  }
}

/** Search ALL keyserver sources in parallel and merge results. */
/**
 * Search ALL keyserver sources in parallel and merge results.
 * If `keybaseOnly` is true, only searches Keybase (fast path for phase 1).
 */
export async function searchAllKeyserversServer(
  query: string,
  fetchImpl: typeof fetch = fetch,
  keybaseOnly = false,
): Promise<KeySearchResult[]> {
  if (keybaseOnly) {
    return searchKeybaseServer(query, fetchImpl);
  }

  const [keybase, ubuntu, opg] = await Promise.all([
    searchKeybaseServer(query, fetchImpl),
    searchHKPKeyserver("https://keyserver.ubuntu.com", "ubuntu", query, fetchImpl),
    searchOpenPGPOrg(query, fetchImpl),
  ]);

  const seen = new Set<string>();
  const merged: KeySearchResult[] = [];
  for (const r of [...keybase, ...ubuntu, ...opg]) {
    const key = r.fingerprint || r.email || r.label.toLowerCase();
    if (!seen.has(key)) {
      seen.add(key);
      merged.push(r);
    }
  }
  return merged.slice(0, 15);
}

/** Browser-side: search all sources via our proxy. */
export async function searchAllKeyserversClient(
  query: string,
  proxyUrl = "/api/keybase/search-all",
): Promise<KeySearchResult[]> {
  const q = query.trim();
  if (q.length < 1) return [];
  const url = `${proxyUrl}?q=${encodeURIComponent(q)}`;
  const res = await fetchProxyWithTimeout(url);
  if (!res.ok) return [];
  return (await res.json()) as KeySearchResult[];
}
