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
  const cleaned = usernames
    .map((u) => u.trim().toLowerCase())
    .filter((u) => u.length > 0);

  if (cleaned.length === 0) {
    return { found: [], missing: [], errors: [] };
  }

  const url = `${proxyUrl}?usernames=${encodeURIComponent(cleaned.join(","))}`;
  const res = await fetch(url, { headers: { Accept: "application/json" } });

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
