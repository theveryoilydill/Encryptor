/**
 * Content-derived filenames for text downloads.
 *
 * The decrypt tab's "Save as .txt" used to write a hardcoded
 * "decrypted-message.txt" — every save collided with the last one in the
 * downloads folder and nothing about the name helped the user recognize
 * the file later. This helper derives a short, filesystem-safe stem from
 * the text itself (its first heading/subject line when the text has one),
 * falling back to a dated name for messages that open mid-sentence.
 *
 * PRIVACY POSTURE: the name is derived from the same decrypted plaintext
 * the user is already saving, so it exposes nothing the file contents
 * wouldn't. It is never applied to ciphertext (the vault's armor rows
 * keep their title-based names, where content-derived names would be
 * meaningless hashes of armor).
 *
 * # Mr. AI Acting on s183173's Behalf
 */

/** Hard cap on how much text is inspected — the first heading lives in
 *  the first few lines; scanning megabytes would be waste. */
const SCAN_WINDOW_CHARS = 10_000;

/** Slug budget: ~6 words / 40 chars keeps the name readable at 390px
 *  where browsers truncate long download names first. */
const MAX_SLUG_CHARS = 40;
const MAX_SLUG_WORDS = 6;

/** Markdown/formatting characters stripped from a candidate heading line
 *  before slugging ("## Meeting notes — **Thu**" → "meeting-notes-thu"). */
const MARKDOWN_NOISE = /^[#>*_`~\-+\s]+|[*_`~]+$/g;

/**
 * Suggest a filename for a plain-text download, derived from the text's
 * first non-empty line when it reads like a heading/subject:
 *
 *  - "# Meeting notes (Thu)"  → meeting-notes-thu.txt
 *  - "Invoice #4127 — Acme"   → invoice-4127-acme.txt
 *  - "Hi\nlonger body"        → decrypted-2026-09-23.txt  (one-word opener)
 *  - ""                       → decrypted-2026-09-23.txt  (empty text)
 *
 *  Note: a short 2+ word first line ("hey, quick question") DOES slug —
 *  a readable name beats a dated one whenever the line has structure
 *  (two words or eight chars). Only single-word openers too short to be
 *  meaningful fall back to the dated name.
 *
 * Pure function: never throws, never returns an empty or dangerous name
 * (control chars, path separators and reserved characters are collapsed
 * by the slug step; the fallback path is a fixed stem + ISO date).
 */
export function suggestTextFilename(text: string, fallbackBase = "decrypted-message"): string {
	const dated = `${fallbackBase}-yyyy-mm-dd.txt`.replace(
		"yyyy-mm-dd",
		new Date().toISOString().slice(0, 10),
	);

	const window = (typeof text === "string" ? text : "").slice(0, SCAN_WINDOW_CHARS);
	for (const rawLine of window.split(/\r?\n/)) {
		const line = rawLine.trim();
		if (!line) continue;

		// First non-empty line: strip markdown noise and take the remainder
		// as the candidate heading.
		const candidate = line.replace(MARKDOWN_NOISE, "").trim();
		if (!candidate) continue;

		// Heading heuristic: short-ish AND letter-bearing. A one-word line
		// like "Hi" is technically a heading but a useless filename —
		// require either 2+ words or 8+ chars to commit to it.
		const hasLetter = /[a-z0-9]/i.test(candidate);
		const plausible =
			hasLetter &&
			candidate.length >= 3 &&
			candidate.length <= 120 &&
			(candidate.split(/\s+/).length >= 2 || candidate.length >= 8);
		if (!plausible) break; // prose opener — stop looking, use the fallback

		const slug = candidate
			.toLowerCase()
			.replace(/[^a-z0-9]+/g, "-")
			.replace(/^-+|-+$/g, "")
			.split("-")
			.filter(Boolean)
			.slice(0, MAX_SLUG_WORDS)
			.join("-")
			.slice(0, MAX_SLUG_CHARS)
			.replace(/-+$/g, "");

		return slug.length >= 3 ? `${slug}.txt` : dated;
	}
	return dated;
}
