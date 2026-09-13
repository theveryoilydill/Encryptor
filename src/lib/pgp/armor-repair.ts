/**
 * PGP armor repair — fixes the ways email clients, mailing lists, and
 * copy/paste mangle armored blocks before they reach the Decrypt/Verify
 * input. Pure string functions, no crypto: the output is either a
 * well-formed armor block the normal openpgp.js path can parse, or null
 * when the damage is unrecoverable (truncated block).
 *
 * Handled damage:
 *  - HTML entities from webmail ("&lt;" instead of "<")
 *  - Email quote prefixes ("> " on every line)
 *  - CRLF / CR line endings
 *  - Lost or padded header dashes ("BEGIN PGP MESSAGE" with no "-----")
 *  - Stray prose / blank lines inside the base64 body
 *  - Missing or wrong CRC24 checksum line (recomputed from the body)
 *  - Junk text before BEGIN / after END
 *
 * Privacy posture: everything runs locally on the pasted string — nothing
 * is stored, logged, or sent anywhere (same rule as every lib in this app).
 */

export type ArmorFix =
	| "html-entities"
	| "quote-prefix"
	| "line-endings"
	| "header-dashes"
	| "stray-lines"
	| "checksum";

/** Human-readable fix list for the repair banner (order = display order). */
const FIX_LABELS: Record<ArmorFix, string> = {
	"html-entities": "HTML entities",
	"quote-prefix": "quote markers",
	"line-endings": "line endings",
	"header-dashes": "header dashes",
	"stray-lines": "stray lines",
	checksum: "checksum",
};

export function describeFixes(fixes: ArmorFix[]): string {
	return fixes.map((f) => FIX_LABELS[f]).join(", ");
}

/** "BEGIN PGP MESSAGE" → "-----BEGIN PGP MESSAGE-----" (canonical dash run). */
function canonicalBegin(type: string): string {
	return `-----BEGIN ${type}-----`;
}
function canonicalEnd(type: string): string {
	return `-----END ${type}-----`;
}

const HTML_ENTITIES: ReadonlyArray<readonly [RegExp, string]> = [
	[/&lt;/g, "<"],
	[/&gt;/g, ">"],
	[/&quot;/g, '"'],
	[/&#0?39;|&apos;/g, "'"],
	// &amp; LAST so "&amp;lt;" (double-encoded) collapses to "<", not "&lt;".
	[/&amp;/g, "&"],
];

/**
 * Cheap detection pass for the input banner — returns the damage classes
 * found, empty array when the block looks clean (or isn't an armor block
 * at all — the tabs' existing detectPgpBlock hints cover that case).
 */
export function findArmorIssues(text: string): ArmorFix[] {
	const issues = new Set<ArmorFix>();
	if (!text.trim()) return [];

	if (HTML_ENTITIES.some(([re]) => re.test(text))) issues.add("html-entities");
	if (/\r/.test(text)) issues.add("line-endings");
	// Any line whose first non-space char is ">" — armor never starts a line
	// with ">" (base64 alphabet + "=-" checksum + dash markers only).
	if (/^[ \t]*>/m.test(text)) issues.add("quote-prefix");

	const allLines = text.split("\n");
	const beginLine = allLines.find((l) => /BEGIN (?:PGP|ENCRYPTOR)/.test(l));
	const endLine = allLines.find((l) => /END (?:PGP|ENCRYPTOR)/.test(l));
	// Cleartext SIGNED blocks carry arbitrary prose between the markers —
	// "stray lines" there are the signed content itself, never damage.
	const isCleartextSigned = /BEGIN PGP SIGNED MESSAGE/.test(beginLine ?? "");
	// Dashes: marker line exists but isn't canonical (lost/mangled dashes,
	// leading "On ... wrote:" style prefixes are handled under stray-lines).
	if (beginLine && !/^-----BEGIN (?:PGP|ENCRYPTOR) [A-Z-]+-----\s*$/.test(beginLine.trim())) {
		issues.add("header-dashes");
	}
	if (endLine && !/^-----END (?:PGP|ENCRYPTOR) [A-Z-]+-----\s*$/.test(endLine.trim())) {
		issues.add("header-dashes");
	}
	// Stray lines: blank lines / non-base64 junk INSIDE the body region
	// between the markers. The blank line right after BEGIN is the RFC's
	// mandatory header separator — body starts at the first non-blank,
	// non-header line; anything blank/junk AFTER that point is damage.
	if (beginLine && endLine && !isCleartextSigned) {
		const bi = allLines.findIndex((l) => l.includes("BEGIN"));
		const ei = allLines.findIndex((l) => l.includes("END"));
		const between = allLines.slice(bi + 1, ei);
		// Skip the header section: header lines ("Version: x") plus the
		// blank separator that ends it.
		let i = 0;
		while (
			i < between.length &&
			(/^[A-Za-z-]+: /.test(between[i].trim()) || between[i].trim() === "")
		)
			i++;
		const body = between.slice(i);
		const hasStray = body.some((l) => {
			const t = l.trim();
			if (t === "") return true; // blank line inside the body region
			if (t.startsWith("=")) return false; // checksum line
			if (/^[A-Za-z0-9+/=\s]+$/.test(t)) return false; // base64
			return true; // prose / quoted junk
		});
		if (hasStray) issues.add("stray-lines");
	}
	return [...issues];
}

/** CRC-24 over the base64-DECODED body bytes (RFC 4880 §6.6). */
function crc24(bytes: Uint8Array): number {
	const INIT = 0xb704ce;
	const POLY = 0x1864cfb;
	let crc = INIT;
	for (const b of bytes) {
		crc ^= b << 16;
		for (let i = 0; i < 8; i++) {
			crc <<= 1;
			if (crc & 0x1000000) crc ^= POLY;
		}
	}
	return crc & 0xffffff;
}

function crc24ToBase64(crc: number): string {
	const b = String.fromCharCode((crc >> 16) & 0xff, (crc >> 8) & 0xff, crc & 0xff);
	// btoa is available in every browser context this runs in.
	return btoa(b);
}

function base64ToBytes(b64: string): Uint8Array {
	const clean = b64.replace(/\s+/g, "");
	const bin = atob(clean);
	const out = new Uint8Array(bin.length);
	for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
	return out;
}

/**
 * Repair the pasted text. Returns the cleaned block + the fix list applied,
 * or null when the damage is unrecoverable (no END marker → the ciphertext
 * itself is truncated and no framing cleanup can bring it back).
 */
export function repairArmor(input: string): { text: string; fixes: ArmorFix[] } | null {
	const fixes = new Set<ArmorFix>();
	let text = input;

	// 1. HTML entities (whole input — junk before/after gets discarded later,
	//    but entities INSIDE markers must be undone before they're findable).
	for (const [re, replacement] of HTML_ENTITIES) {
		if (re.test(text)) {
			text = text.replace(re, replacement);
			fixes.add("html-entities");
		}
	}

	// 2. Line endings: CRLF/CR → LF.
	if (/\r/.test(text)) {
		text = text.replace(/\r\n?/g, "\n");
		fixes.add("line-endings");
	}

	// 3. Locate the block. BEGIN may have lost its dashes entirely.
	const lines = text.split("\n");
	const beginIdx = lines.findIndex((l) => /BEGIN (?:PGP|ENCRYPTOR)/.test(l));
	if (beginIdx === -1) return null;
	const endIdx = lines.findIndex((l) => /END (?:PGP|ENCRYPTOR)/.test(l));
	if (endIdx === -1 || endIdx < beginIdx) return null; // truncated — unrecoverable
	// Anything before BEGIN or after END is mail-client noise (quoted reply
	// tails, "Sent from my iPhone", scroll triggers). Dropping it is a fix.
	if (
		lines.slice(0, beginIdx).some((l) => l.trim() !== "") ||
		lines.slice(endIdx + 1).some((l) => l.trim() !== "")
	) {
		fixes.add("stray-lines");
	}

	// 4. Identify the block type from whichever marker line is usable.
	const beginRaw = lines[beginIdx].trim();
	const endRaw = lines[endIdx].trim();
	const typeMatch =
		/(?:BEGIN|END) (PGP (?:MESSAGE|SIGNED MESSAGE|SIGNATURE|PUBLIC KEY BLOCK|PRIVATE KEY BLOCK)|ENCRYPTOR QUANTUM-SEALED)/.exec(
			beginRaw.replace(/^-*\s*/, "").replace(/\s*-*$/, "") +
				" " +
				endRaw.replace(/^-*\s*/, "").replace(/\s*-*$/, ""),
		);
	if (!typeMatch) return null;
	const blockType = typeMatch[1];
	// Cleartext signed messages can't be auto-repaired safely: the signed
	// body is arbitrary prose (mutating it invalidates the signature, and
	// openpgp.js verifies what's actually between the markers). Surface
	// nothing rather than "repairing" a block into a bad signature.
	if (blockType === "PGP SIGNED MESSAGE") return null;

	// 5. Rebuild markers canonically (fixes lost/padded dashes, quote
	//    prefixes on the marker lines themselves).
	const canonicalBeginLine = canonicalBegin(blockType);
	const canonicalEndLine = canonicalEnd(blockType);
	if (beginRaw !== canonicalBeginLine || endRaw !== canonicalEndLine) {
		fixes.add("header-dashes");
	}

	// 6. Sanitize the body: strip quote prefixes, drop blank + non-base64
	//    lines, keep the checksum line (=XXXX) if present.
	const bodyLines: string[] = [];
	let oldChecksum: string | null = null;
	for (let i = beginIdx + 1; i < endIdx; i++) {
		const stripped = lines[i].replace(/^[ \t]*>[>]?\s?/, "");
		if (stripped !== lines[i]) fixes.add("quote-prefix");
		const line = stripped.trim();
		if (line === "") continue; // blank line noise
		if (line.startsWith("=")) {
			if (/^=[A-Za-z0-9+/]{4}$/.test(line)) oldChecksum = line;
			continue; // checksum is recomputed below either way
		}
		if (!/^[A-Za-z0-9+/=\s]+$/.test(line)) {
			fixes.add("stray-lines"); // prose / signature boilerplate inside body
			continue;
		}
		bodyLines.push(line);
	}
	if (bodyLines.length === 0) return null; // nothing left to decrypt

	// Rejoin + re-wrap at 64 chars (RFC 4880 line length) — also normalizes
	// the 40-char wraps some clients produce.
	const joined = bodyLines.join("");
	const wrapped: string[] = [];
	for (let i = 0; i < joined.length; i += 64) wrapped.push(joined.slice(i, i + 64));

	// 7. Recompute the CRC24 checksum from the (possibly cleaned) body.
	let bytes: Uint8Array;
	try {
		bytes = base64ToBytes(joined);
	} catch {
		return null; // body isn't valid base64 — beyond framing repair
	}
	const newChecksum = `=${crc24ToBase64(crc24(bytes))}`;
	if (oldChecksum !== newChecksum) fixes.add("checksum");

	// 8. Preserve armor header lines (Version:/Comment:) that sat between
	//    BEGIN and the first body line in the original.
	const headerLines: string[] = [];
	for (let i = beginIdx + 1; i < endIdx; i++) {
		const t = lines[i].trim();
		if (t === "") continue;
		if (/^[A-Za-z-]+: /.test(t) && !t.startsWith("=")) headerLines.push(t);
	}

	// The blank line between the header section and the body is mandatory
	// (RFC 4880 §6.2) even when there are no header lines at all —
	// openpgp.js rejects blocks without it.
	const rebuilt = [
		canonicalBeginLine,
		...headerLines.slice(0, 4),
		"",
		...wrapped,
		newChecksum,
		canonicalEndLine,
	].join("\n");

	if (fixes.size === 0) return null; // nothing actually changed
	return { text: rebuilt, fixes: [...fixes] };
}
