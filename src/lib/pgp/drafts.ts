/**
 * Unsent-composer drafts (sessionStorage-backed, per-tab keys).
 *
 * # Mr. AI Acting on s183173's Behalf
 *
 * A refresh (or accidental Cmd+R) used to destroy whatever was typed into
 * the Encrypt / Sign composers — the message lived only in React state.
 * Drafts bridge exactly that gap WITHOUT widening the app's at-rest
 * footprint:
 *
 *   - sessionStorage, NOT localStorage — the draft survives a reload but
 *     dies with the tab, so nothing plaintext lingers on disk for days.
 *     This matches the app's posture ("keys and plaintext never touch our
 *     servers", local storage only by explicit choice) while keeping the
 *     at-rest window as short as the feature's purpose allows.
 *   - Attachments ride along ONLY when the whole serialized draft fits a
 *     conservative 2.5 MB budget (sessionStorage quota is typically 5 MB
 *     per origin; leaving headroom avoids starving the other keys). Over
 *     budget → text-only draft, and the restore note says attachments
 *     weren't kept. Text alone over budget → no draft at all.
 *   - Every read goes through guarded validation (same posture as every
 *     other storage reader in the repo): a corrupted or partial stored
 *     value falls back to the defaults instead of breaking the composer.
 *   - `envelope://` image markers in a restored draft stay inert text —
 *     they only resolve against a live files array at render time — so a
 *     missing attachment can never break encryption, only show a broken
 *     preview until the user re-attaches.
 */
import { STORAGE_KEYS } from "@/lib/constants";
import type { EnvelopeFile } from "@/lib/pgp/envelope";

/** Which composer a draft belongs to. */
export type DraftKey = "encrypt" | "sign";

const DRAFT_STORAGE_KEYS: Record<DraftKey, string> = {
	encrypt: STORAGE_KEYS.draftEncrypt,
	sign: STORAGE_KEYS.draftSign,
};

/** Hard cap on the serialized draft (text + attachment JSON). ~2.5 MB sits
 *  safely under the ~5 MB per-origin sessionStorage quota most browsers
 *  grant, and far above any realistic message body. */
export const MAX_DRAFT_SERIALIZED_CHARS = 2_621_440;

/** Shape persisted under each draft key. `files` is null when attachments
 *  were dropped for size (or when the composer has none); `filesDropped`
 *  distinguishes "no attachments existed" from "too big to keep". */
export interface StoredDraft {
	text: string;
	files: EnvelopeFile[] | null;
	filesDropped: boolean;
}

/** Read a draft. Returns null when absent / unreadable / corrupt — callers
 *  treat null exactly like "nothing was saved". */
export function loadDraft(key: DraftKey): StoredDraft | null {
	try {
		const raw = sessionStorage.getItem(DRAFT_STORAGE_KEYS[key]);
		if (!raw || raw.length > MAX_DRAFT_SERIALIZED_CHARS) return null;
		const parsed: unknown = JSON.parse(raw);
		if (typeof parsed !== "object" || parsed === null) return null;
		const text = (parsed as { text?: unknown }).text;
		if (typeof text !== "string") return null;
		const files = parseDraftFiles((parsed as { files?: unknown }).files);
		const filesDropped = (parsed as { filesDropped?: unknown }).filesDropped === true;
		// A whitespace-only text draft carries no user work worth restoring.
		if (text.trim() === "" && (!files || files.length === 0)) return null;
		return { text, files, filesDropped };
	} catch {
		// Quota errors, JSON hiccups, private-mode quirks — drafts are a
		// convenience layer, so every failure degrades to "no draft".
		return null;
	}
}

/** Persist a draft. Attachments are kept only while the whole serialized
 *  payload fits the budget; oversized payloads degrade to text-only, and
 *  text-only payloads that are themselves oversized skip the write. */
export function saveDraft(key: DraftKey, text: string, files: EnvelopeFile[] = []): void {
	try {
		const withFiles: StoredDraft = {
			text,
			files: files.length > 0 ? files : null,
			filesDropped: false,
		};
		let payload = JSON.stringify(withFiles);
		if (payload.length > MAX_DRAFT_SERIALIZED_CHARS) {
			payload = JSON.stringify({ text, files: null, filesDropped: files.length > 0 });
		}
		if (payload.length > MAX_DRAFT_SERIALIZED_CHARS) return;
		sessionStorage.setItem(DRAFT_STORAGE_KEYS[key], payload);
	} catch {
		// Storage full / disabled — the composer keeps working without drafts.
	}
}

/** Remove a draft (seal-and-clear, explicit Discard). */
export function clearDraft(key: DraftKey): void {
	try {
		sessionStorage.removeItem(DRAFT_STORAGE_KEYS[key]);
	} catch {
		// Unreadable storage — nothing to clear, nothing to surface.
	}
}

/** Validate the stored `files` array shape: name/type/data strings and a
 *  numeric size per row, mirroring EnvelopeFile. Anything malformed is
 *  dropped row-by-row (not rejected wholesale) so a single bad entry can't
 *  destroy the surrounding text draft. */
function parseDraftFiles(value: unknown): EnvelopeFile[] | null {
	if (!Array.isArray(value)) return null;
	const files: EnvelopeFile[] = [];
	for (const row of value) {
		if (typeof row !== "object" || row === null) continue;
		const { name, type, data, size } = row as Record<string, unknown>;
		if (typeof name !== "string" || name.length === 0) continue;
		if (typeof type !== "string") continue;
		if (typeof data !== "string" || !/^[A-Za-z0-9+/=]*$/.test(data)) continue;
		if (typeof size !== "number" || !Number.isFinite(size) || size < 0) continue;
		files.push({ name, type, data, size });
	}
	return files;
}
