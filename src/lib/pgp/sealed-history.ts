/**
 * Recent sealed outputs — a ciphertext-only local history for the Encrypt
 * tab. After every successful encrypt the armored output (and, when
 * produced, its quantum-sealed copy) is appended here so the user can go
 * back to an earlier sealed message after the output block has been reset
 * or replaced by a newer one.
 *
 * PRIVACY POSTURE: ciphertext only, by construction. The plaintext is
 * deleted from the composer BEFORE an entry is recorded, and the sealed
 * armor is exactly what the user would paste into an email anyway —
 * keeping it is no more sensitive than the message sitting in the output
 * box. Still bounded like every other store: capped count, capped per-
 * entry size (a several-MB attachment envelope is skipped rather than
 * half-stored), guarded reads/writes that degrade to an empty list or a
 * rejected append — never a thrown error in the UI.
 */

export interface SealedHistoryEntry {
	/** Stable id (crypto.randomUUID with a fallback) for list keys and
	 *  per-entry removal. */
	id: string;
	/** Epoch milliseconds — when the message was sealed. */
	at: number;
	/** Recipient key count (the same number the success strip shows). */
	keys: number;
	/** Whether the output was also signed. */
	signed: boolean;
	/** Whether a quantum-sealed copy was produced for this output. */
	pqSealed: boolean;
	/** The classical armored output (what OutputBlock shows). */
	armor: string;
	/** The ML-KEM-768 quantum-sealed copy, when one was produced. */
	sealedArmor: string | null;
}

const HISTORY_KEY = "encryptor.sealed.history.v1";
/** 8 entries × ≤64 KB ≈ 0.5 MB worst case — comfortably inside the ~5 MB
 *  engine quota even alongside templates, drafts and config backup. */
export const MAX_SEALED_ENTRIES = 8;
export const MAX_SEALED_ARMOR_CHARS = 64 * 1024;

function makeId(): string {
	try {
		if (typeof crypto !== "undefined" && typeof crypto.randomUUID === "function") {
			return crypto.randomUUID();
		}
	} catch {
		// fall through to the manual fallback
	}
	return `sealed-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`;
}

/** Read all sealed outputs, newest first. Corrupted/oversized rows are
 *  skipped individually — one bad entry never blanks the whole list. */
export function loadSealedHistory(): SealedHistoryEntry[] {
	try {
		const raw = localStorage.getItem(HISTORY_KEY);
		if (!raw) return [];
		const parsed: unknown = JSON.parse(raw);
		if (!Array.isArray(parsed)) return [];
		const entries: SealedHistoryEntry[] = [];
		for (const row of parsed.slice(0, MAX_SEALED_ENTRIES * 2)) {
			if (typeof row !== "object" || row === null) continue;
			const e = row as Record<string, unknown>;
			if (typeof e.armor !== "string" || e.armor.length === 0) continue;
			if (e.armor.length > MAX_SEALED_ARMOR_CHARS) continue;
			if (e.sealedArmor !== null && typeof e.sealedArmor !== "string") continue;
			if (typeof e.sealedArmor === "string" && e.sealedArmor.length > MAX_SEALED_ARMOR_CHARS) {
				// Keep the classical armor; drop just the oversized PQ copy.
				e.sealedArmor = null;
			}
			entries.push({
				id: typeof e.id === "string" ? e.id : makeId(),
				at: typeof e.at === "number" ? e.at : 0,
				keys: typeof e.keys === "number" ? e.keys : 0,
				signed: e.signed === true,
				pqSealed: e.pqSealed === true,
				armor: e.armor,
				sealedArmor: typeof e.sealedArmor === "string" ? e.sealedArmor : null,
			});
		}
		return entries.sort((a, b) => b.at - a.at).slice(0, MAX_SEALED_ENTRIES);
	} catch {
		return [];
	}
}

function persist(entries: SealedHistoryEntry[]): void {
	try {
		localStorage.setItem(HISTORY_KEY, JSON.stringify(entries.slice(0, MAX_SEALED_ENTRIES)));
	} catch {
		// Quota / private mode / disabled storage — the in-memory UI keeps
		// working; the history just won't survive a reload.
	}
}

/** Append a sealed output. Returns the refreshed list (newest first), or
 *  null when the entry was intentionally not stored (oversized armor). */
export function appendSealedOutput(input: {
	armor: string;
	sealedArmor?: string | null;
	keys: number;
	signed: boolean;
	pqSealed: boolean;
}): { entries: SealedHistoryEntry[]; stored: boolean } {
	if (input.armor.length > MAX_SEALED_ARMOR_CHARS) {
		// Deliberate skip: a truncated ciphertext would decrypt to garbage —
		// worse than not storing it at all.
		return { entries: loadSealedHistory(), stored: false };
	}
	const entry: SealedHistoryEntry = {
		id: makeId(),
		at: Date.now(),
		keys: input.keys,
		signed: input.signed,
		pqSealed: input.pqSealed,
		armor: input.armor,
		sealedArmor: input.sealedArmor ?? null,
	};
	const entries = [entry, ...loadSealedHistory().filter((e) => e.armor !== input.armor)].slice(
		0,
		MAX_SEALED_ENTRIES,
	);
	persist(entries);
	return { entries, stored: true };
}

/** Remove one entry by id. Returns the refreshed list. */
export function removeSealedEntry(id: string): SealedHistoryEntry[] {
	const entries = loadSealedHistory().filter((e) => e.id !== id);
	persist(entries);
	return entries;
}

/** Drop the whole history. Returns the (empty) list. */
export function clearSealedHistory(): SealedHistoryEntry[] {
	try {
		localStorage.removeItem(HISTORY_KEY);
	} catch {
		// nothing to recover — the UI state still clears
	}
	return [];
}
