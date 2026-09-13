/**
 * Composer draft rescue — sessionStorage-backed mirror of the Encrypt tab's
 * message text.
 *
 * WHY sessionStorage and NOT localStorage: this is an encryption app whose
 * documented posture is "plaintext stays in RAM" (the composer even wipes
 * the plaintext the moment the ciphertext exists). A draft IS plaintext, so
 * persisting it to the browser profile (localStorage = on-disk, survives for
 * weeks) would quietly undermine that promise. sessionStorage keeps the
 * rescue exactly where it matters — an accidental reload mid-composition
 * (reloads PRESERVE sessionStorage) — while guaranteeing the draft is gone
 * the moment the tab closes. Attachment payloads are deliberately NOT
 * mirrored: they are the heavy part (quota risk) and never the irreplaceable
 * part (they exist as files on the user's disk).
 *
 * Guarded reads/writes per the repo-wide storage posture: any storage
 * failure (private mode, quota, disabled) degrades to "no rescue", never an
 * error. Size-capped so a runaway paste can't blow the ~5 MB engine quota —
 * 256 KB is far above any realistic composed message.
 */

const DRAFT_KEY = "encryptor.composer.draft";
const MAX_DRAFT_CHARS = 256 * 1024;

/** Read the rescued draft, or null when absent/unreadable/oversized. */
export function loadComposerDraft(): string | null {
	try {
		const draft = sessionStorage.getItem(DRAFT_KEY);
		if (draft === null) return null;
		// Defensive cap on the way IN too: a draft written by an older build
		// (or hostile storage edit) must never flood the composer.
		return draft.length > MAX_DRAFT_CHARS ? null : draft;
	} catch {
		return null;
	}
}

/** Persist the draft. Oversized drafts are dropped silently — rescuing a
 *  giant paste is not worth breaking the composer. */
export function saveComposerDraft(text: string): void {
	try {
		if (!text || text.length > MAX_DRAFT_CHARS) {
			sessionStorage.removeItem(DRAFT_KEY);
			return;
		}
		sessionStorage.setItem(DRAFT_KEY, text);
	} catch {
		// ignore — rescue is best-effort by design
	}
}

/** Drop the draft (encrypt succeeded, composer cleared, or PGP-block text —
 *  the rescue path is for composed messages only). */
export function clearComposerDraft(): void {
	try {
		sessionStorage.removeItem(DRAFT_KEY);
	} catch {
		// ignore
	}
}
