/**
 * User preferences (localStorage-backed, JSON).
 *
 * # Mr. AI Acting on s183173's Behalf
 *
 * Settings are small, typed, and always read through loadSettings() so a
 * corrupted or partial stored value falls back to the defaults instead of
 * breaking the app (same guarded posture as every other storage reader in
 * the repo). Saved via saveSettings(); the ConfigureModal writes through it
 * and PgpApp keeps the loaded object in React state so tabs re-render when
 * a preference changes.
 */
import { STORAGE_KEYS } from "@/lib/constants";

/** Message compression applied before encryption (see encryptAndSign).
 *  - "zlib": maximum compression (default) — every OpenPGP.js-generated and
 *    modern GnuPG recipient key advertises zlib support.
 *  - "zip": standard DEFLATE (raw).
 *  - "off": no compression.
 *  NOTE: openpgp.js only uses the sender's preferred algorithm when ALL
 *  recipient keys advertise it in their preferences; otherwise it falls
 *  back to uncompressed automatically. bzip2 is intentionally not offered:
 *  OpenPGP.js-generated keys don't advertise it, so it would silently
 *  disable compression. */
export type CompressionLevel = "zlib" | "zip" | "off";

/** Message composer style on the Encrypt tab. */
export type MarkdownEditorKind = "notion" | "vscode";

export interface AppSettings {
  compression: CompressionLevel;
  markdownEditor: MarkdownEditorKind;
}

export const DEFAULT_SETTINGS: AppSettings = {
  // Compress messages by default, at maximum supported compression.
  compression: "zlib",
  // Notion/Affine-style block editor by default.
  markdownEditor: "notion",
};

/** Human labels + the openpgp config value for each compression level. */
export const COMPRESSION_OPTIONS: ReadonlyArray<{
  value: CompressionLevel;
  label: string;
}> = [
  { value: "zlib", label: "Maximum" },
  { value: "zip", label: "Standard" },
  { value: "off", label: "Off" },
];

export const EDITOR_OPTIONS: ReadonlyArray<{
  value: MarkdownEditorKind;
  label: string;
}> = [
  { value: "notion", label: "Notion-style editor" },
  { value: "vscode", label: "VS Code-style (split preview)" },
];

/** Parse an unknown stored value into AppSettings, keeping valid fields and
 *  defaulting everything else. */
function coerceSettings(raw: unknown): AppSettings {
  const out: AppSettings = { ...DEFAULT_SETTINGS };
  if (typeof raw === "object" && raw !== null) {
    const r = raw as Partial<AppSettings>;
    if (r.compression === "zlib" || r.compression === "zip" || r.compression === "off") {
      out.compression = r.compression;
    }
    if (r.markdownEditor === "notion" || r.markdownEditor === "vscode") {
      out.markdownEditor = r.markdownEditor;
    }
  }
  return out;
}

/** Load settings from localStorage (defaults when unavailable/corrupted). */
export function loadSettings(): AppSettings {
  try {
    const raw = localStorage.getItem(STORAGE_KEYS.settings);
    if (raw) return coerceSettings(JSON.parse(raw));
  } catch {
    // fall through to defaults
  }
  return { ...DEFAULT_SETTINGS };
}

/** Persist settings (guarded like every other storage write). */
export function saveSettings(settings: AppSettings): void {
  try {
    localStorage.setItem(STORAGE_KEYS.settings, JSON.stringify(settings));
  } catch {
    // ignore
  }
}
