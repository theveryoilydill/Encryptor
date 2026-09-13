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
/** Epoch ms when the current cache entry was stored (0 = nothing cached).
 *  Powers the auto-lock countdown UI and the freshness gate below. */
let cachedAt = 0;

export function getCachedPassphrase(): string | null {
	return cached;
}

/** When the current cache entry was stored (epoch ms; 0 = nothing cached). */
export function getCachedPassphraseAt(): number {
	return cachedAt;
}

/** Store the passphrase for this session (overwrites any previous value). */
export function cachePassphrase(passphrase: string): void {
	cached = passphrase;
	cachedAt = Date.now();
}

/** Drop the cached passphrase (idempotent). */
export function forgetPassphrase(): void {
	cached = null;
	cachedAt = 0;
}

/** Freshness gate (R9 auto-lock): returns the cached passphrase only while
 *  it is younger than `autoLockMinutes` (0 = no lock — the pre-R9 behavior).
 *  A STALE entry is forgotten as a side effect so callers can also flip
 *  their "cached" indicator off without a second call. Fractional minutes
 *  are accepted on purpose — tests/QA rely on sub-minute values. */
export function getCachedPassphraseIfFresh(autoLockMinutes: number): string | null {
	if (!cached) return null;
	if (!autoLockMinutes || autoLockMinutes <= 0) return cached;
	if (Date.now() - cachedAt > autoLockMinutes * 60_000) {
		cached = null;
		cachedAt = 0;
		return null;
	}
	return cached;
}
