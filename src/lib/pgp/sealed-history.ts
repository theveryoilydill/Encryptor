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
	/** Recipient labels at seal time (display-only, capped) — powers the
	 *  "Sealed to: …" tooltip on the vault's key-count chip. Optional so
	 *  entries written before this field shipped still load. */
	labels?: string[];
	/** Display label of the signing key, captured at seal time (MAX 48
	 *  chars, control characters stripped) — powers the "signed by …"
	 *  chip. Optional so entries written before this field shipped still
	 *  load. */
	signer?: string;
	/** Attachment count wrapped into the envelope at seal time (0-99).
	 *  Optional so legacy entries still load. */
	files?: number;
	/** Signing key fingerprint at seal time (round 16): hex only, lower-
	 *  cased, capped at 64 chars (sanitizeFingerprint). Powers the
	 *  verify-style tooltips — the FULL grouped fingerprint on the vault
	 *  row, the short key id on the strip. Optional so entries written
	 *  before this field shipped still load. */
	signerFp?: string;
}

const HISTORY_KEY = "encryptor.sealed.history.v1";
/** 8 entries × ≤64 KB ≈ 0.5 MB worst case — comfortably inside the ~5 MB
 *  engine quota even alongside templates, drafts and config backup. */
export const MAX_SEALED_ENTRIES = 8;
export const MAX_SEALED_ARMOR_CHARS = 64 * 1024;

/** Display-only caps for the recipient-label list (8 names × 48 chars). */
export const MAX_SEALED_LABELS = 8;
export const MAX_SEALED_LABEL_CHARS = 48;

/** Display-only cap for the signer label (same budget as one recipient
 *  label — it renders inside the same chip row). */
export const MAX_SEALED_SIGNER_CHARS = 48;
/** Upper bound for the per-entry attachment count; oversized values clamp
 *  here, garbage drops out entirely. */
export const MAX_SEALED_FILES = 99;

function sanitizeLabels(input: unknown): string[] {
	if (!Array.isArray(input)) return [];
	return input
		.filter((l): l is string => typeof l === "string" && l.trim() !== "")
		.slice(0, MAX_SEALED_LABELS)
		.map((l) => l.trim().slice(0, MAX_SEALED_LABEL_CHARS));
}

/** Signer display label (round 15): control characters stripped, trimmed,
 *  capped at 48 — an empty or garbage value becomes undefined so the UI
 *  falls back to the bare "signed" chip. */
function sanitizeSigner(input: unknown): string | undefined {
	if (typeof input !== "string") return undefined;
	const cleaned = input
		// eslint-disable-next-line no-control-regex -- stripping control characters IS the goal
		.replace(/[\u0000-\u001f\u007f]/g, "")
		.trim()
		.slice(0, MAX_SEALED_SIGNER_CHARS);
	return cleaned === "" ? undefined : cleaned;
}

/** Attachment count: finite non-negative numbers only, floored and clamped
 *  to 99 — garbage becomes undefined (the chip simply doesn't render). */
function sanitizeFiles(input: unknown): number | undefined {
	if (typeof input !== "number" || !Number.isFinite(input) || input < 0) return undefined;
	return Math.min(MAX_SEALED_FILES, Math.floor(input));
}

/** Fingerprint (round 16): display metadata, not a security check — hex
 *  digits only, lowercased, capped at 64 (v4 fingerprints are 40 chars,
 *  v6 are 64); at least 8 hex chars must survive the strip or the value
 *  is treated as garbage (undefined → the tooltip falls back to the
 *  plain "captured at seal time" wording). Exported so tests and future
 *  importers share the exact same tolerance. */
export function sanitizeFingerprint(input: unknown): string | undefined {
	if (typeof input !== "string") return undefined;
	const hex = input
		.replace(/[^0-9a-fA-F]/g, "")
		.toLowerCase()
		.slice(0, 64);
	return hex.length >= 8 ? hex : undefined;
}

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
				labels: sanitizeLabels(e.labels),
				signer: sanitizeSigner(e.signer),
				files: sanitizeFiles(e.files),
				signerFp: sanitizeFingerprint(e.signerFp),
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
	labels?: string[];
	signer?: string;
	files?: number;
	signerFp?: string;
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
		labels: sanitizeLabels(input.labels),
		signer: sanitizeSigner(input.signer),
		files: sanitizeFiles(input.files),
		signerFp: sanitizeFingerprint(input.signerFp),
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
