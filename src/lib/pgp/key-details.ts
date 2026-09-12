/**
 * Pure display helpers for the "Key details" panel in ConfigureModal.
 *
 * No DOM access — safe to call during render or unit test. Field names are
 * read from the live `PublicKeyInfo` shape in src/lib/pgp/pgp.ts; rows whose
 * backing field is undefined/empty are skipped.
 *
 * NOTE on dates: PgpApp persists the whole PrivateKeyConfig (including
 * `info`) as JSON in localStorage, which stringifies Date objects to ISO
 * strings. `toLocalizedDate` therefore accepts BOTH fresh Date instances and
 * their restored string form so the panel never crashes on a reloaded config.
 */
import { formatFingerprint, type PublicKeyInfo } from "@/lib/pgp/pgp";

/** One row of the "Key details" disclosure (label/value definition grid). */
export interface KeyDetailRow {
  label: string;
  value: string;
  /** Render the value in monospace (key IDs, fingerprints). */
  mono?: boolean;
}

/**
 * Parse a Date-or-ISO-string value (the two shapes a localStorage JSON
 * round-trip produces) into a Date. Returns null for missing/unparseable
 * input. Shared by toLocalizedDate and getKeyExpiryStatus so the tolerance
 * lives in exactly one place. EXPORTED since R11: EncryptTab's selfRecipient
 * derivation consumes it too — the persisted config's expirationTime is an
 * ISO string after a localStorage JSON round-trip, and calling .getTime()
 * on it directly crashed the tab on reload ("getTime is not a function").
 */
export function parseLooseDate(value: unknown): Date | null {
  if (!(value instanceof Date) && typeof value !== "string") return null;
  const date = value instanceof Date ? value : new Date(value);
  return Number.isNaN(date.getTime()) ? null : date;
}

/**
 * Localized date (date only, e.g. "7/14/2023") for a creation/expiration
 * field. Returns null for missing/unparseable values → the caller skips the
 * row. pgp.ts's formatKeyDate is intentionally NOT reused here because its
 * "never" sentinel and date+time output don't match the panel's spec
 * ("Never expires", date only).
 */
function toLocalizedDate(value: unknown): string | null {
  const date = parseLooseDate(value);
  return date ? date.toLocaleDateString() : null;
}

/**
 * Build the "Key details" rows for a configured key, in display order:
 * Key ID, Fingerprint (formatted via the shared formatFingerprint helper),
 * Algorithm, Created, Expires ("Never expires" when null), User IDs
 * (count + primary email), Subkeys (count from the runtime-only
 * subkeyFingerprints field describePublicKey always attaches).
 * Returns [] gracefully for empty input / no data.
 */
export function describeKeyDetails(info: PublicKeyInfo): KeyDetailRow[] {
  if (!info) return [];
  const rows: KeyDetailRow[] = [];

  if (info.keyID) {
    rows.push({ label: "Key ID", value: info.keyID, mono: true });
  }
  if (info.fingerprint) {
    rows.push({
      label: "Fingerprint",
      value: formatFingerprint(info.fingerprint),
      mono: true,
    });
  }
  if (info.algorithm) {
    const algorithm = humanizeAlgorithm(info.algorithm);
    const detail = algorithmDetail(info, algorithm);
    rows.push({
      label: "Algorithm",
      value: detail ? `${algorithm}${detail}` : algorithm,
    });
  }
  const created = toLocalizedDate(info.creationTime);
  if (created) {
    rows.push({ label: "Created", value: created });
  }
  if (info.expirationTime) {
    const expires = toLocalizedDate(info.expirationTime);
    if (expires) rows.push({ label: "Expires", value: expires });
  } else if (info.expirationTime === null) {
    // Explicit null = the key never expires (missing field → skip the row).
    rows.push({ label: "Expires", value: "Never expires" });
  }
  const userIDs = Array.isArray(info.userIDs) ? info.userIDs : [];
  if (userIDs.length > 0) {
    const primaryEmail = userIDs[0]?.email;
    rows.push({
      label: "User IDs",
      value: primaryEmail ? `${userIDs.length} · ${primaryEmail}` : String(userIDs.length),
    });
  }
  // describePublicKey attaches subkeyFingerprints via a spread cast (useful
  // but not part of the exported type) — read it defensively. When the R11
  // per-subkey list has rows, the detailed list REPLACES this count row
  // (rendering both would duplicate the same information); configs stored
  // before R11 carry no subkeyDetails → describeSubkeyDetails returns [] and
  // the count row still renders (back-compat, no crash).
  const subkeyFingerprints = (info as { subkeyFingerprints?: unknown }).subkeyFingerprints;
  if (Array.isArray(subkeyFingerprints) && describeSubkeyDetails(info).length === 0) {
    rows.push({
      label: "Subkeys",
      value: String(subkeyFingerprints.length),
    });
  }

  return rows;
}

/**
 * One compact row of the per-subkey list (R11) rendered below the "Key
 * details" rows when the configured info carries subkey data.
 */
export interface SubkeyDetailRow {
  keyID: string;
  /** Humanized algorithm label (raw openpgp value → display name). */
  algorithm: string;
  created: string;
  /** Localized expiration date, or null when the subkey never expires. */
  expires: string | null;
  expiring: boolean;
  expired: boolean;
}

/**
 * Build the per-subkey rows for the Key details panel (R11).
 *
 * describePublicKey attaches a runtime-only `subkeyDetails` array via a
 * spread cast (deliberately not part of the exported PublicKeyInfo type), so
 * this reads it defensively: absent/invalid field → [], per-item shape
 * validation, malformed items skipped. `created`/`expiresAt` tolerate BOTH
 * fresh Date/number values and their localStorage JSON round-trip forms
 * (ISO strings) via the shared parseLooseDate helper — same tolerance as
 * describeKeyDetails.
 *
 * Expiry flags reuse getKeyExpiryStatus (same 30-day window as the badges):
 * "expired" → expired, "expiring" → expiring, "none" → neither. expiresAt
 * must be a finite positive epoch-ms number (openpgp v6's Infinity sentinel
 * never reaches this layer — pgp.ts already guards it to null).
 *
 * Back-compat: configs stored before R11 have NO subkeyDetails field → this
 * returns [] and the panel shows only the legacy "Subkeys: N" count row.
 */
export function describeSubkeyDetails(info: PublicKeyInfo): SubkeyDetailRow[] {
  if (!info) return [];
  const raw = (info as { subkeyDetails?: unknown }).subkeyDetails;
  if (!Array.isArray(raw)) return [];
  const rows: SubkeyDetailRow[] = [];
  for (const item of raw) {
    if (typeof item !== "object" || item === null) continue;
    const rec = item as {
      keyID?: unknown;
      algorithm?: unknown;
      created?: unknown;
      expiresAt?: unknown;
    };
    // Malformed items are skipped, never fatal (one bad subkey must not
    // take down the panel).
    if (typeof rec.keyID !== "string" || rec.keyID.trim() === "") continue;
    if (typeof rec.algorithm !== "string" || rec.algorithm.trim() === "") continue;
    const created = toLocalizedDate(rec.created);
    if (!created) continue;
    let expiresAt: Date | null = null;
    if (typeof rec.expiresAt === "number" && Number.isFinite(rec.expiresAt) && rec.expiresAt > 0) {
      expiresAt = new Date(rec.expiresAt);
    }
    const expiry = expiresAt ? getKeyExpiryStatus(expiresAt) : null;
    rows.push({
      keyID: rec.keyID,
      algorithm: humanizeRawAlgorithm(rec.algorithm),
      created,
      expires: expiresAt ? (toLocalizedDate(expiresAt) ?? null) : null,
      expiring: expiry?.status === "expiring",
      expired: expiry?.status === "expired",
    });
  }
  return rows;
}

/**
 * Human-friendly display names for openpgp.js's raw algorithm identifiers
 * (openpgp.js v6 reports e.g. "eddsaLegacy", "ecdhX25519", "rsaSign").
 * Case-insensitive; unknown values fall back to the raw string verbatim.
 *
 * Scope note (R6): R5 deliberately kept describe* output verbatim. This map
 * humanizes ONLY the "Algorithm" display row of the key-details panel —
 * pgp.ts still returns raw values everywhere else (Recipient algorithm
 * fields, ZIP metadata, etc.). A Map (not a plain object) avoids the
 * prototype-chain pitfall ("constructor" etc.) on adversarial input.
 */
const ALGORITHM_LABELS: ReadonlyMap<string, string> = new Map<string, string>([
  ["ed25519legacy", "EdDSA (Curve25519)"],
  ["eddsalegacy", "EdDSA (legacy)"],
  ["rsa4", "RSA"],
  ["rsasign", "RSA"],
  ["rsaencrypt", "RSA"],
  ["ecdh", "ECDH"],
  ["ecdhx25519", "ECDH (Curve25519)"],
  ["ecdsanistp256", "ECDSA (NIST P-256)"],
  ["ecdsanistp384", "ECDSA (NIST P-384)"],
  ["ecdsanistp521", "ECDSA (NIST P-521)"],
  ["curve25519", "Curve25519"],
  ["nistp256", "NIST P-256"],
  ["nistp384", "NIST P-384"],
  ["nistp521", "NIST P-521"],
  ["elgamal", "ElGamal"],
  ["aes128", "AES-128"],
  ["aes192", "AES-192"],
  ["aes256", "AES-256"],
]);

/** Map a raw algorithm identifier to its human-friendly label (or itself). */
function humanizeAlgorithm(raw: string): string {
  return ALGORITHM_LABELS.get(raw.toLowerCase()) ?? raw;
}

/**
 * Display-only humanizer for RAW openpgp.js algorithm identifiers stored on
 * data records (e.g. Recipient.algorithm carries "rsaEncryptSign" /
 * "eddsaLegacy" from keyserver and manual-paste adds, and the self chip's
 * info.algorithm from describePublicKey). Reuses the panel's
 * ALGORITHM_LABELS map (prototype-chain safe); unknown values fall back to
 * the raw string verbatim.
 *
 * Keybase adds store already-humanized guesses (e.g. "EdDSA") rather than
 * raw identifiers — those never match a map key and pass through verbatim,
 * which is exactly the desired passthrough behavior.
 */
export function humanizeRawAlgorithm(raw: string): string {
  return humanizeAlgorithm(raw);
}

/**
 * Friendly names for openpgp.js curve identifiers (PublicKeyInfo.curve —
 * describePublicKey reads them off getAlgorithmInfo()). Same shape/scope as
 * ALGORITHM_LABELS above: Map (prototype-chain safe), lowercase keys, display
 * only — pgp.ts still returns raw curve values everywhere else.
 */
const CURVE_LABELS: ReadonlyMap<string, string> = new Map<string, string>([
  ["ed25519legacy", "Curve25519"],
  ["curve25519legacy", "Curve25519"],
  ["nistp256", "NIST P-256"],
  ["nistp384", "NIST P-384"],
  ["nistp521", "NIST P-521"],
  ["brainpoolp256r1", "Brainpool P-256"],
  ["brainpoolp384r1", "Brainpool P-384"],
  ["brainpoolp512r1", "Brainpool P-512"],
  ["secp256k1", "secp256k1"],
]);

/**
 * Extra qualifier appended to the humanized Algorithm row value, or "" when
 * nothing meaningful is available. Curve wins when it ADDS information (the
 * humanized label already names the curve for most ECC entries — e.g.
 * "ECDSA (NIST P-256)" — and repeating it would be noise); otherwise the RSA
 * bit size is used ("RSA · 4096 bits"). humanizeAlgorithm itself is NOT
 * restructured (R6 scope note).
 */
function algorithmDetail(info: PublicKeyInfo, humanized: string): string {
  const curve =
    typeof info.curve === "string" ? CURVE_LABELS.get(info.curve.toLowerCase()) : undefined;
  if (curve && !humanized.toLowerCase().includes(curve.toLowerCase())) {
    return ` · ${curve}`;
  }
  if (typeof info.bitSize === "number" && Number.isFinite(info.bitSize) && info.bitSize > 0) {
    return ` · ${info.bitSize} bits`;
  }
  return "";
}

/** Expiry status of a key, for the ConfigureModal badge. */
export interface KeyExpiryStatus {
  status: "expired" | "expiring" | "none";
  label: string;
}

const MS_PER_DAY = 24 * 60 * 60 * 1000;

/** Days-out threshold for the "expiring" window. */
const EXPIRING_SOON_DAYS = 30;

/**
 * Expiry status for a key's expirationTime — accepts Date | ISO string |
 * null | undefined (same tolerance as toLocalizedDate, via the shared
 * parseLooseDate helper). Returns null when there is no (parseable)
 * expiration, so the caller can skip rendering entirely.
 *
 *   - "expired": expiration date < now
 *   - "expiring": fewer than 30 days out (label "Expires in N days",
 *     N = ceil of the days remaining, singular-safe)
 *   - "none": 30+ days out — the label carries the localized date (the
 *     "Never expires" wording intentionally does NOT appear here; that is
 *     already a dedicated details row, and the badge never renders for
 *     "none" anyway).
 */
export function getKeyExpiryStatus(expirationTime: unknown): KeyExpiryStatus | null {
  const date = parseLooseDate(expirationTime);
  if (!date) return null;
  const remainingMs = date.getTime() - Date.now();
  if (remainingMs <= 0) {
    return { status: "expired", label: "Expired" };
  }
  const daysRemaining = Math.ceil(remainingMs / MS_PER_DAY);
  if (daysRemaining < EXPIRING_SOON_DAYS) {
    return {
      status: "expiring",
      label: `Expires in ${daysRemaining} day${daysRemaining === 1 ? "" : "s"}`,
    };
  }
  return { status: "none", label: toLocalizedDate(date) ?? "" };
}

/**
 * File name for a key backup download: slugified label (same slug pattern
 * as shared.tsx's output filename: lowercase, /[^a-z0-9]+/g → "-", trimmed
 * dashes) + "-public-key.asc" / "-private-key.asc".
 * e.g. downloadKeyName("public", "@max") → "max-public-key.asc".
 */
export function downloadKeyName(kind: "public" | "private", label: string): string {
  const slug = label
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
  return `${slug || "pgp"}-${kind}-key.asc`;
}
