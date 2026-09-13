/**
 * Session-scoped passphrase cache — opt-in convenience, memory ONLY.
 *
 * When the user checks "remember for this session" on the passphrase prompt,
 * the passphrase is held in this module-level variable so later operations
 * (sign, decrypt-to-self, re-encrypt) can unlock the private key silently.
 *
 * SECURITY CONTRACT:
 * - Never written to localStorage / sessionStorage / cookies / IndexedDB —
 *   a module variable dies with the tab, which is exactly the scope the
 *   user opted into.
 * - Never logged, never included in errors or telemetry.
 * - Cleared: on tab close (automatic), when the key config is removed or
 *   replaced with a different fingerprint, via the header "forget" button,
 *   or immediately after a cached passphrase fails to unlock the key.
 * - Keybase passwords are intentionally NOT cacheable (the prompt flow for
 *   Keybase re-fetches the key bundle; callers never consult the cache for
 *   Keybase sources).
 *
 * The module holds only the string; callers own all unlock/verify logic.
 */

let cached: string | null = null;

export function getCachedPassphrase(): string | null {
  return cached;
}

/** Store the passphrase for this session (overwrites any previous value). */
export function cachePassphrase(passphrase: string): void {
  cached = passphrase;
}

/** Drop the cached passphrase (idempotent). */
export function forgetPassphrase(): void {
  cached = null;
}
