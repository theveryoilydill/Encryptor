/**
 * User-defined composer templates — the "your templates" half of the
 * Insert-template menu (the curated starters live in EncryptTab).
 *
 * WHY localStorage (unlike composer drafts, which use sessionStorage):
 * a template is content the user EXPLICITLY chose to keep — persistence
 * is the entire point. The save dialog copy says where it's kept ("in
 * this browser") so the plaintext-in-RAM posture stays honest: saving a
 * template is an explicit act, not a silent side effect.
 *
 * Guarded reads/writes per the repo-wide storage posture: any storage
 * failure (private mode, quota, disabled) degrades to an empty list or a
 * rejected save — never a thrown error in the composer UI.
 */

export interface UserTemplate {
	id: string;
	name: string;
	body: string;
	createdAt: number;
}

const TEMPLATE_KEY = "encryptor.composer.templates.v1";
/** Cap both dimensions: a runaway paste saved as a template must not blow
 *  the ~5 MB engine quota (same reasoning as composer-draft's 256 KB cap). */
export const MAX_TEMPLATES = 24;
export const MAX_TEMPLATE_BODY_CHARS = 32 * 1024;
export const MAX_TEMPLATE_NAME_CHARS = 60;

/** Read all user templates, newest first. Corrupted/oversized entries are
 *  skipped individually — one bad row never blanks the whole list. */
export function loadUserTemplates(): UserTemplate[] {
	try {
		const raw = localStorage.getItem(TEMPLATE_KEY);
		if (!raw) return [];
		const parsed: unknown = JSON.parse(raw);
		if (!Array.isArray(parsed)) return [];
		const templates: UserTemplate[] = [];
		for (const entry of parsed.slice(0, MAX_TEMPLATES * 2)) {
			if (typeof entry !== "object" || entry === null) continue;
			const e = entry as Record<string, unknown>;
			if (typeof e.id !== "string" || typeof e.name !== "string" || typeof e.body !== "string")
				continue;
			if (e.body.length > MAX_TEMPLATE_BODY_CHARS) continue;
			templates.push({
				id: e.id,
				name: e.name.slice(0, MAX_TEMPLATE_NAME_CHARS),
				body: e.body,
				createdAt: typeof e.createdAt === "number" ? e.createdAt : 0,
			});
		}
		return templates.sort((a, b) => b.createdAt - a.createdAt);
	} catch {
		return [];
	}
}

/** Persist a new template. Returns the refreshed list on success, or a
 *  short user-facing error string (quota, caps, storage disabled). */
export function saveUserTemplate(
	name: string,
	body: string,
): { ok: true; templates: UserTemplate[] } | { ok: false; error: string } {
	const trimmedName = name.trim().slice(0, MAX_TEMPLATE_NAME_CHARS) || "Untitled template";
	const trimmedBody = body.slice(0, MAX_TEMPLATE_BODY_CHARS);
	try {
		const existing = loadUserTemplates();
		if (existing.length >= MAX_TEMPLATES) {
			return { ok: false, error: `Template list is full (${MAX_TEMPLATES}) — delete one first.` };
		}
		const template: UserTemplate = {
			id: `tpl-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
			name: trimmedName,
			body: trimmedBody,
			createdAt: Date.now(),
		};
		const next = [template, ...existing];
		localStorage.setItem(TEMPLATE_KEY, JSON.stringify(next));
		return { ok: true, templates: next };
	} catch {
		return {
			ok: false,
			error: "Couldn't save the template (browser storage unavailable or full).",
		};
	}
}

/** Delete one template by id; returns the refreshed list. */
export function deleteUserTemplate(id: string): UserTemplate[] {
	try {
		const next = loadUserTemplates().filter((t) => t.id !== id);
		localStorage.setItem(TEMPLATE_KEY, JSON.stringify(next));
		return next;
	} catch {
		return loadUserTemplates();
	}
}
