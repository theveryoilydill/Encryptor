/**
 * Client-safe display-name normalization — the ONE source of truth shared
 * by the registry server (keys.ts indexes) and the browser search paths
 * (key-lookup.ts), so a query is validated exactly like the index it hits.
 *
 * Valid normalized name: printable, no angle brackets (they delimit the
 * email part of a User ID), 1-64 chars after normalization.
 *
 * # Mr. AI Acting on s183173's Behalf
 */
export function normalizeDisplayName(raw: string): string | null {
	const name = raw
		.replace(/\s+/g, " ")
		.trim()
		.replace(/^["']+|["']+$/g, "")
		.toLowerCase();
	if (!name || name.length > 64) return null;
	if (!/^[^<>]+$/.test(name)) return null;
	// Reject C0 control characters and DEL without embedding them in a regex.
	for (const ch of name) {
		const code = ch.codePointAt(0) ?? 0;
		if (code < 0x20 || code === 0x7f) return null;
	}
	return name;
}
