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
	/** User-entered note (optional): a free-form one-liner the user attaches
	 *  to an entry ("Contract for Alice — emailed 9/23"). Same display-only
	 *  treatment as labels/signer: control characters stripped, capped,
	 *  garbage becomes undefined. Travels with exported manifests and is
	 *  re-sanitized on import through the shared sanitizeHistoryRow. */
	note?: string;
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
/** Display-only cap for the user note: a sentence fragment, not a field —
 *  long enough to be useful ("Contract for Alice — emailed 9/23"), short
 *  enough to render on one line of the vault row. */
export const MAX_SEALED_NOTE_CHARS = 120;
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

/** User note (optional): control characters stripped (the note renders on
 *  one line inside the vault row — newlines would break the layout),
 *  trimmed, capped at 120; empty or garbage becomes undefined so the row
 *  simply shows no note. Same tolerance philosophy as sanitizeSigner. */
function sanitizeNote(input: unknown): string | undefined {
	if (typeof input !== "string") return undefined;
	const cleaned = input
		// eslint-disable-next-line no-control-regex -- stripping control characters IS the goal
		.replace(/[\u0000-\u001f\u007f]/g, "")
		.trim()
		.slice(0, MAX_SEALED_NOTE_CHARS);
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

/**
 * Round 18: the ONE shared per-row validator for sealed-history rows —
 * the localStorage load path and the vault-manifest importer both map
 * rows through it, so a hostile manifest faces the exact same armor caps
 * and label/signer/signerFp/files sanitizers as a local-storage row.
 * Returns null for structurally invalid rows (no/oversized armor,
 * malformed sealedArmor); soft metadata fields sanitize to their safe
 * forms instead of rejecting the row. Pure — never mutates the input.
 */
export function sanitizeHistoryRow(raw: unknown): SealedHistoryEntry | null {
	if (typeof raw !== "object" || raw === null) return null;
	const e = raw as Record<string, unknown>;
	if (typeof e.armor !== "string" || e.armor.length === 0) return null;
	if (e.armor.length > MAX_SEALED_ARMOR_CHARS) return null;
	if (e.sealedArmor !== null && typeof e.sealedArmor !== "string") return null;
	// Oversized PQ copy: keep the classical armor, drop just the copy —
	// the same verdict the load path has always made, now without
	// mutating the caller's object.
	const sealedArmor =
		typeof e.sealedArmor === "string" && e.sealedArmor.length <= MAX_SEALED_ARMOR_CHARS
			? e.sealedArmor
			: null;
	return {
		id: typeof e.id === "string" ? e.id : makeId(),
		at: typeof e.at === "number" ? e.at : 0,
		keys: typeof e.keys === "number" ? e.keys : 0,
		signed: e.signed === true,
		pqSealed: e.pqSealed === true,
		armor: e.armor,
		sealedArmor,
		labels: sanitizeLabels(e.labels),
		signer: sanitizeSigner(e.signer),
		files: sanitizeFiles(e.files),
		signerFp: sanitizeFingerprint(e.signerFp),
		note: sanitizeNote(e.note),
	};
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
			// Round 18: per-row validation lives in ONE shared exported
			// validator — the vault-manifest importer maps rows through the
			// exact same sanitizeHistoryRow, so a hostile manifest cannot
			// smuggle anything past the caps this path already enforces.
			const entry = sanitizeHistoryRow(row);
			if (entry) entries.push(entry);
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

/** Set (or clear) a user note on one entry. Empty/whitespace-only notes
 *  CLEAR the field — clearing is a first-class action, not a special case.
 *  The input runs through sanitizeNote again on write, so the UI cannot
 *  persist anything the load path would refuse. Returns the updated list
 *  (same shape as removeSealedEntry); unknown ids leave storage untouched
 *  and return the list unchanged. */
export function updateSealedEntryNote(id: string, note: string): SealedHistoryEntry[] {
	const entries = loadSealedHistory().map((e) => {
		if (e.id !== id) return e;
		const cleaned = sanitizeNote(note);
		return cleaned === undefined ? { ...e, note: undefined } : { ...e, note: cleaned };
	});
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

export interface ParsedVaultManifest {
	/** Manifest's exportedAt passthrough (display-only, already validated
	 *  as a string — parse/format at the UI layer). */
	exportedAt?: string;
	/** Every row that survived the shared sanitizeHistoryRow validator. */
	entries: SealedHistoryEntry[];
	/** Rows rejected by the validator (counted, not fatal). */
	skipped: number;
}

/**
 * Round 18: parse + validate a vault manifest — the counterpart to the
 * round-17 export format. GATES FIRST on the kind/version markers:
 * anything else throws a friendly Error (the UI toasts it and the vault
 * stays untouched — nothing is half-applied). Every surviving row then
 * runs the SAME sanitizeHistoryRow as the localStorage load path, so a
 * hostile manifest cannot smuggle oversized signer labels / files
 * metadata / armor past the caps; unusable rows are counted and skipped
 * individually instead of rejecting the whole file.
 */
export function parseVaultManifest(json: unknown): ParsedVaultManifest {
	if (typeof json !== "object" || json === null) {
		throw new Error('Not a vault manifest — expected kind "encryptor-vault-manifest", version 1.');
	}
	const m = json as Record<string, unknown>;
	if (m.kind !== "encryptor-vault-manifest" || m.version !== 1) {
		throw new Error('Not a vault manifest — expected kind "encryptor-vault-manifest", version 1.');
	}
	const rows = Array.isArray(m.entries) ? m.entries : [];
	const entries: SealedHistoryEntry[] = [];
	let skipped = 0;
	for (const row of rows) {
		const entry = sanitizeHistoryRow(row);
		if (entry) entries.push(entry);
		else skipped += 1;
	}
	return {
		exportedAt: typeof m.exportedAt === "string" ? m.exportedAt : undefined,
		entries,
		skipped,
	};
}

export interface SealedImportResult {
	/** Incoming rows that ACTUALLY landed in the returned vault. */
	added: number;
	/** Incoming rows skipped as armor-duplicates (against the current
	 *  vault or within the incoming batch itself). */
	duplicates: number;
	/** Incoming-only rows that were accepted but then cap-truncated —
	 *  current entries dropped by the cap are NOT counted here. */
	dropped: number;
}

/**
 * Round 18: bring manifest entries into the vault.
 *
 * MERGE — armor-dedupe by exact string match, first against the current
 * vault and then within the incoming batch itself (re-importing your own
 * export is therefore a no-op: every row duplicates). Ids colliding with
 * surviving entries are re-keyed. Accepted rows merge with the current
 * entries, sort newest-first and cut to the same MAX_SEALED_ENTRIES cap
 * the vault always enforces — which CAN keep a newer current entry over
 * an older incoming one, so "added" is counted via a reference-identity
 * set over the kept array (never by id or armor equality), and "dropped"
 * only ever counts incoming rows that were accepted and then truncated.
 *
 * REPLACE — the vault becomes exactly the manifest: incoming sorted
 * newest-first, sliced to the cap, persisted.
 *
 * Both modes persist the resulting list and return it alongside the
 * counts, so the UI words its toast from the same source of truth.
 */
export function importSealedEntries(
	incoming: SealedHistoryEntry[],
	current: SealedHistoryEntry[],
	mode: "merge" | "replace",
): { entries: SealedHistoryEntry[] } & SealedImportResult {
	if (mode === "replace") {
		const kept = [...incoming].sort((a, b) => b.at - a.at).slice(0, MAX_SEALED_ENTRIES);
		persist(kept);
		return {
			entries: kept,
			added: kept.length,
			duplicates: 0,
			dropped: incoming.length - kept.length,
		};
	}

	const currentArmors = new Set(current.map((e) => e.armor));
	const usedIds = new Set(current.map((e) => e.id));
	const batchArmors = new Set<string>();
	const accepted: SealedHistoryEntry[] = [];
	let duplicates = 0;
	for (const entry of incoming) {
		if (currentArmors.has(entry.armor) || batchArmors.has(entry.armor)) {
			duplicates += 1;
			continue;
		}
		batchArmors.add(entry.armor);
		// Re-key id collisions so list keys and per-row actions stay unique.
		let id = entry.id;
		while (usedIds.has(id)) id = makeId();
		usedIds.add(id);
		accepted.push(id === entry.id ? entry : { ...entry, id });
	}

	const merged = [...accepted, ...current].sort((a, b) => b.at - a.at).slice(0, MAX_SEALED_ENTRIES);
	// Count what ACTUALLY landed via reference identity of the kept
	// objects — value equality could never distinguish a kept incoming row
	// from a coincidentally identical current one.
	const landed = new Set(merged);
	const added = accepted.filter((e) => landed.has(e)).length;
	const dropped = accepted.length - added;
	persist(merged);
	return { entries: merged, added, duplicates, dropped };
}
