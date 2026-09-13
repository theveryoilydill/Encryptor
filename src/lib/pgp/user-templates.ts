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

/* ------------------------------- export/import ---------------------------- */

/** Versioned envelope for the template JSON file. Keeping an explicit
 *  "kind" lets importTemplates reject any random .json the user picked by
 *  mistake instead of blowing up mid-parse. */
export interface TemplateExportFile {
	kind: "encryptor.templates";
	version: 1;
	exportedAt: string;
	templates: UserTemplate[];
}

/** Serialize the current list for download. Pretty-printed — these files
 *  are small and humans may want to read/curate them. */
export function exportTemplates(): string {
	const file: TemplateExportFile = {
		kind: "encryptor.templates",
		version: 1,
		exportedAt: new Date().toISOString(),
		templates: loadUserTemplates(),
	};
	return JSON.stringify(file, null, 2);
}

function downloadFileName(): string {
	const d = new Date();
	const p = (n: number) => String(n).padStart(2, "0");
	return `encryptor-templates-${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}.json`;
}

export { downloadFileName };

/**
 * Merge an exported file into the stored list. Tolerant inputs: the
 * versioned envelope OR a bare template array (hand-edited files still
 * import). Dedupe key is name+body — re-importing the same file is a
 * no-op instead of duplicating everything. Ids are preserved unless they
 * collide with different content (then a fresh id is minted).
 */
export function importTemplates(
	json: string,
):
	| { ok: true; templates: UserTemplate[]; added: number; skipped: number }
	| { ok: false; error: string } {
	let parsed: unknown;
	try {
		parsed = JSON.parse(json);
	} catch {
		return { ok: false, error: "That file isn't valid JSON." };
	}
	const rawList: unknown[] | null = Array.isArray(parsed)
		? parsed
		: typeof parsed === "object" &&
			  parsed !== null &&
			  (parsed as Record<string, unknown>).kind === "encryptor.templates" &&
			  Array.isArray((parsed as Record<string, unknown>).templates)
			? ((parsed as Record<string, unknown>).templates as unknown[])
			: null;
	if (rawList === null) {
		return { ok: false, error: "That file isn't an Encryptor templates export." };
	}

	const existing = loadUserTemplates();
	const byKey = new Set(existing.map((t) => `${t.name}\u0000${t.body}`));
	const usedIds = new Set(existing.map((t) => t.id));
	const merged = [...existing];
	let added = 0;
	let skipped = 0;

	for (const entry of rawList) {
		if (typeof entry !== "object" || entry === null) {
			skipped += 1;
			continue;
		}
		const e = entry as Record<string, unknown>;
		if (typeof e.name !== "string" || typeof e.body !== "string" || e.body.length === 0) {
			skipped += 1;
			continue;
		}
		if (e.body.length > MAX_TEMPLATE_BODY_CHARS) {
			skipped += 1;
			continue;
		}
		const name = e.name.trim().slice(0, MAX_TEMPLATE_NAME_CHARS) || "Untitled template";
		const body = e.body;
		const key = `${name}\u0000${body}`;
		if (byKey.has(key)) {
			skipped += 1; // exact duplicate (name+body) — re-import no-op
			continue;
		}
		if (merged.length >= MAX_TEMPLATES) {
			skipped += 1;
			continue;
		}
		let id =
			typeof e.id === "string" && e.id
				? e.id
				: `tpl-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
		if (usedIds.has(id)) {
			id = `tpl-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
		}
		usedIds.add(id);
		byKey.add(key);
		merged.push({
			id,
			name,
			body,
			createdAt: typeof e.createdAt === "number" ? e.createdAt : Date.now(),
		});
		added += 1;
	}

	if (added === 0) {
		return {
			ok: false,
			error:
				skipped > 0
					? "Nothing new to import — all entries were duplicates or invalid."
					: "That file contains no templates.",
		};
	}
	try {
		const next = merged.sort((a, b) => b.createdAt - a.createdAt);
		localStorage.setItem(TEMPLATE_KEY, JSON.stringify(next));
		return { ok: true, templates: next, added, skipped };
	} catch {
		return {
			ok: false,
			error: "Couldn't save the imported templates (browser storage unavailable or full).",
		};
	}
}
