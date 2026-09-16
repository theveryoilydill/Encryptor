/**
 * Registry watch — per-browser memory of key sightings for change detection.
 *
 * Every successful lookup RECORDS the row's `updatedAt`/`revoked` state.
 * On later lookups of the same fingerprint the stored sighting is compared
 * against the live record, so a key whose material was REPLACED (new
 * updated_at) or REVOKED since the last sight is flagged in the UI. This is
 * the client-side half of replacement detection: the server can only report
 * the current state — noticing "different from what I saw before" has to
 * happen somewhere that remembers. localStorage is exactly that memory.
 *
 * Best-effort by design: every access is guarded because localStorage can
 * throw (quota, privacy mode, disabled storage) and change detection must
 * never break a lookup. # Mr. AI Acting on s183173's Behalf
 */

const STORAGE_KEY = "encryptor-registry-watch-v1";
/** Bound the map so years of lookups can't grow it unbounded. */
const MAX_ENTRIES = 200;

export interface KeySighting {
	/** Registry `updated_at` (epoch SECONDS) at last sight. */
	updatedAt: number;
	/** Registry revoked flag at last sight. */
	revoked: boolean;
	/** Local time of the sighting (epoch ms) — shown in the UI. */
	seenAt: number;
}

function readAll(): Record<string, KeySighting> {
	try {
		if (typeof window === "undefined") return {};
		const raw = window.localStorage.getItem(STORAGE_KEY);
		if (!raw) return {};
		const parsed: unknown = JSON.parse(raw);
		if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return {};
		return parsed as Record<string, KeySighting>;
	} catch {
		return {};
	}
}

function writeAll(map: Record<string, KeySighting>): void {
	try {
		window.localStorage.setItem(STORAGE_KEY, JSON.stringify(map));
	} catch {
		/* storage unavailable — change detection silently degrades */
	}
}

/** Prior sighting for a fingerprint, or null when never seen on this device. */
export function getKeySighting(fingerprint: string): KeySighting | null {
	const rec = readAll()[fingerprint.toUpperCase()];
	return rec && typeof rec.updatedAt === "number" ? rec : null;
}

/** Record (or refresh) a sighting of a key's current registry state. */
export function noteKeySighted(
	fingerprint: string,
	current: { updatedAt: number; revoked: boolean },
): void {
	const fpr = fingerprint.toUpperCase();
	const map = readAll();
	map[fpr] = {
		updatedAt: current.updatedAt,
		revoked: Boolean(current.revoked),
		seenAt: Date.now(),
	};
	// Prune oldest sightings when over budget (skip the key just written).
	const entries = Object.entries(map);
	if (entries.length > MAX_ENTRIES) {
		entries
			.filter(([k]) => k !== fpr)
			.sort((a, b) => a[1].seenAt - b[1].seenAt)
			.slice(0, entries.length - MAX_ENTRIES)
			.forEach(([k]) => delete map[k]);
	}
	writeAll(map);
}

/** Drop a sighting (used by tests and by "forget" affordances). */
export function forgetSighting(fingerprint: string): void {
	const map = readAll();
	delete map[fingerprint.toUpperCase()];
	writeAll(map);
}
