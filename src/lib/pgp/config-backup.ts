/**
 * Config backup export/import (pure localStorage — no other DOM access).
 *
 * A backup is a pretty-printed JSON file capturing every key the app stores
 * in localStorage (see STORAGE_KEYS in src/lib/constants.ts):
 *
 *   {
 *     "app": "encryptor",
 *     "version": 1,
 *     "exportedAt": "2026-02-11T12:34:56.789Z",
 *     "warning": "This backup contains your private key material …",
 *     "data": { "<storageKey>": <parsed JSON value or raw string> }
 *   }
 *
 * SECURITY: `data` includes `encryptor.config.v1`, i.e. the passphrase-
 * ENCRYPTED armored private key (manual/generated sources). It never contains
 * a passphrase or a decrypted key — but anyone holding the file plus the
 * user's passphrase could decrypt messages. That is what the `warning` field
 * (and the UI warning line) is for.
 *
 * All functions are sync and side-effect-free except applyConfigBackup, which
 * writes to localStorage. No page reload happens here — the caller decides.
 */
import { STORAGE_KEYS } from "@/lib/constants";

/** Top-level warning baked into every export. */
const BACKUP_WARNING =
  "This backup contains your private key material (passphrase-encrypted). " +
  "Anyone with this file and your passphrase can read your messages.";

/** The exact shape written by buildConfigBackup. */
export interface ConfigBackupFile {
  app: "encryptor";
  version: 1;
  exportedAt: string;
  warning: string;
  data: Record<string, unknown>;
}

/** Result of parseConfigBackup (discriminated on `ok`). */
export type ConfigBackupParseResult =
  | { ok: true; data: Record<string, unknown>; count: number }
  | { ok: false; error: string };

/** Known storage keys, as a Set for O(1) filtering. */
const KNOWN_STORAGE_KEYS: ReadonlySet<string> = new Set(Object.values(STORAGE_KEYS));

/**
 * localStorage accessor, guarded so this module stays usable (importable)
 * outside a browser: SSR, tests, or privacy modes where even TOUCHING
 * localStorage throws. Returns null when unavailable.
 */
function getLocalStorage(): Storage | null {
  try {
    if (typeof window === "undefined" || !window.localStorage) return null;
    return window.localStorage;
  } catch {
    return null;
  }
}

/**
 * Parse a stored raw value into its "natural" form: JSON where the value was
 * stored as JSON (config object, includeSelf boolean, recentRecipients
 * array), the raw string otherwise (lastTab, includeSelf's "true"/"false"
 * plain strings — JSON.parse turns those into booleans, which apply
 * round-trips back to the identical "true"/"false" strings).
 */
function parseMaybeJson(raw: string): unknown {
  try {
    return JSON.parse(raw);
  } catch {
    return raw;
  }
}

/**
 * Build a backup JSON string from everything currently stored under the
 * known STORAGE_KEYS. Keys that were never written are skipped (so importing
 * never creates phantom "null" entries); if nothing at all is stored, this
 * throws — the caller surfaces the message as a destructive toast rather
 * than producing a backup file that could never be imported back.
 */
export function buildConfigBackup(): string {
  const storage = getLocalStorage();
  if (!storage) {
    throw new Error("localStorage is unavailable in this browser, so there is nothing to back up.");
  }
  const data: Record<string, unknown> = {};
  for (const key of Object.values(STORAGE_KEYS)) {
    const raw = storage.getItem(key);
    if (raw === null) continue;
    data[key] = parseMaybeJson(raw);
  }
  if (Object.keys(data).length === 0) {
    throw new Error("Nothing to back up yet — no Encryptor settings were found.");
  }
  const backup: ConfigBackupFile = {
    app: "encryptor",
    version: 1,
    exportedAt: new Date().toISOString(),
    warning: BACKUP_WARNING,
    data,
  };
  return JSON.stringify(backup, null, 2);
}

/**
 * Strictly validate backup text BEFORE anything is written:
 *   1. must be JSON                       → "That file is not valid JSON."
 *   2. app === "encryptor"                → "This doesn't look like an Encryptor backup."
 *   3. version === 1                      → "This backup format isn't supported (version mismatch)."
 *   4. data must be a non-empty object    → "This backup doesn't contain any settings."
 *
 * Unknown data keys are ignored (never applied). When no known key remains
 * after filtering, the "no settings" error is returned — applying nothing
 * and reloading would be a confusing no-op. `count` is the number of keys
 * that WILL be applied; `data` is the pre-filtered record for applyConfigBackup.
 */
export function parseConfigBackup(text: string): ConfigBackupParseResult {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return { ok: false, error: "That file is not valid JSON." };
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    return { ok: false, error: "This doesn't look like an Encryptor backup." };
  }
  const obj = parsed as Record<string, unknown>;
  if (obj.app !== "encryptor") {
    return { ok: false, error: "This doesn't look like an Encryptor backup." };
  }
  if (obj.version !== 1) {
    return {
      ok: false,
      error: "This backup format isn't supported (version mismatch).",
    };
  }
  const rawData = obj.data;
  if (typeof rawData !== "object" || rawData === null || Array.isArray(rawData)) {
    return { ok: false, error: "This backup doesn't contain any settings." };
  }
  const data: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(rawData as Record<string, unknown>)) {
    if (KNOWN_STORAGE_KEYS.has(key)) data[key] = value;
  }
  if (Object.keys(data).length === 0) {
    return { ok: false, error: "This backup doesn't contain any settings." };
  }
  return { ok: true, data, count: Object.keys(data).length };
}

/**
 * Write each known key back into localStorage. Object/array values are
 * stored JSON.stringify'd (matching how PgpApp/RecipientPicker persist
 * config/recentRecipients); every other value is stored via String() — e.g.
 * an exported boolean false round-trips to the plain "false" string that
 * PgpApp's include-self reader expects. Unknown keys are skipped (defense in
 * depth — parseConfigBackup already filters). Returns the count applied.
 * Does NOT reload the page — the caller decides.
 */
export function applyConfigBackup(data: Record<string, unknown>): number {
  const storage = getLocalStorage();
  if (!storage) {
    throw new Error("localStorage is unavailable in this browser, so settings cannot be restored.");
  }
  let applied = 0;
  for (const [key, value] of Object.entries(data)) {
    if (!KNOWN_STORAGE_KEYS.has(key)) continue;
    storage.setItem(
      key,
      typeof value === "object" && value !== null ? JSON.stringify(value) : String(value),
    );
    applied += 1;
  }
  return applied;
}
