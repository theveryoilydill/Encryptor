/**
 * Browser-side ZIP bundle builder.
 *
 * Creates a ZIP file containing the operation output (encrypted/signed/decrypted
 * text), any attached/extracted files, and a metadata.json with signers,
 * timestamp, and operation type. Returns a Blob ready for download.
 *
 * Uses the `jszip` library (loaded dynamically so it doesn't bloat the
 * initial client bundle).
 */

export interface ZipFileEntry {
	name: string;
	/** Raw file contents. */
	data: Uint8Array | string;
	/** Whether `data` is a UTF-8 string (true) or binary (false). */
	text?: boolean;
}

export interface ZipMetadata {
	/** Operation type: "encrypt" | "decrypt" | "sign" | "verify". */
	operation: string;
	/** ISO timestamp when the ZIP was generated. */
	generatedAt: string;
	/** The main output text (encrypted message, signed message, etc.). */
	output?: string;
	/** Signer info extracted from the operation (if any). */
	signers?: Array<{
		keyID?: string;
		fingerprint?: string;
		username?: string;
		name?: string;
		email?: string;
		comment?: string;
		userID?: string;
		allUserIDs?: string[];
		verified?: string;
		timestampIso?: string;
	}>;
	/** Verification result for the operation (if applicable). */
	verificationResult?: string;
	/** Number of attached/extracted files. */
	fileCount?: number;
	/** Any extra fields the caller wants to include. */
	[key: string]: unknown;
}

/**
 * Reduce a sender-controlled attachment name to a safe, unique ZIP entry
 * basename before it reaches JSZip:
 *  - strip directory components (a decrypted `../../.bashrc` must never
 *    become a traversal path inside the archive),
 *  - drop leading dots AFTER trimming whitespace (hidden files /
 *    relative-hop leftovers — " .bashrc" is a hidden file too),
 *  - strip TRAILING dot/space runs (Windows extractors delete them when
 *    creating the on-disk file, so `report` and `report.` would extract to
 *    the same path and clobber each other — this also keeps the WRITTEN
 *    entry name Windows-clean),
 *  - fall back when nothing usable remains,
 *  - de-duplicate so two entries never silently overwrite one another
 *    (case-INSENSITIVELY — Windows/macOS extractors default to
 *    case-preserving-but-insensitive filesystems, where `Report.pdf` and
 *    `report.pdf` would clobber each other at extraction time even though
 *    the archive lists them as distinct entries — and NFC-normalized, so
 *    two names that only differ in Unicode normalization form (e.g.
 *    "café.pdf" NFC vs NFD) are also treated as the same file, which
 *    macOS's normalization-insensitive APFS would otherwise overwrite).
 */
function sanitizeZipEntryName(rawName: string, used: Set<string>): string {
	const base = rawName.replace(/\\/g, "/").split("/").pop() ?? "";
	// Trim FIRST: the leading-dot strip must see the real first character —
	// for " .bashrc" a dot-strip before trim would miss the dot and the name
	// would still resolve to a hidden file after trimming.
	const stripped = base
		.trim()
		.replace(/^\.+/, "")
		.replace(/[. ]+$/, "");
	const safe = stripped.length > 0 ? stripped : "attachment";
	// Original case (and the sender's own normalization form) is returned to
	// the archive; only the collision bookkeeping is folded.
	const collisionKey = (s: string) => s.normalize("NFC").toLowerCase();
	if (!used.has(collisionKey(safe))) {
		used.add(collisionKey(safe));
		return safe;
	}
	const dot = safe.lastIndexOf(".");
	const stem = dot > 0 ? safe.slice(0, dot) : safe;
	const ext = dot > 0 ? safe.slice(dot) : "";
	let n = 2;
	while (used.has(collisionKey(`${stem}-${n}${ext}`))) n++;
	const unique = `${stem}-${n}${ext}`;
	used.add(collisionKey(unique));
	return unique;
}

/**
 * Build a ZIP blob from the given entries + metadata.
 *
 * The ZIP always contains:
 *   - output.txt        — the main output text (if provided)
 *   - metadata.json     — structured metadata about the operation
 *   - files/<name>      — any attached/extracted files
 */
export async function buildZipBundle(
	entries: ZipFileEntry[],
	metadata: ZipMetadata,
): Promise<Blob> {
	const JSZip = (await import("jszip")).default;
	const zip = new JSZip();

	// Add the main output as output.txt (if it's a string in metadata).
	if (metadata.output) {
		zip.file("output.txt", metadata.output);
	}

	// Add attached/extracted files under files/ — names are sanitized
	// (basename-only, no leading dots) and de-duplicated per bundle
	// (case-insensitively, so extraction on case-insensitive filesystems
	// can never overwrite one entry with another).
	const filesFolder = zip.folder("files");
	const usedNames = new Set<string>();
	for (const entry of entries) {
		if (filesFolder) {
			filesFolder.file(sanitizeZipEntryName(entry.name, usedNames), entry.data);
		}
	}

	// Add metadata.json with structured info.
	zip.file(
		"metadata.json",
		JSON.stringify(
			{
				...metadata,
				fileCount: metadata.fileCount ?? entries.length,
				generatedAt: metadata.generatedAt || new Date().toISOString(),
			},
			null,
			2,
		),
	);

	return zip.generateAsync({
		type: "blob",
		compression: "DEFLATE",
		compressionOptions: { level: 6 },
	});
}

/**
 * Trigger a browser download of a Blob with the given filename.
 */
export function downloadBlob(blob: Blob, filename: string): void {
	const url = URL.createObjectURL(blob);
	const a = document.createElement("a");
	a.href = url;
	a.download = filename;
	document.body.appendChild(a);
	a.click();
	document.body.removeChild(a);
	// Revoke the object URL after a short delay to ensure the download starts.
	setTimeout(() => URL.revokeObjectURL(url), 1000);
}

/**
 * Generate a safe filename for a ZIP bundle based on the operation type
 * and current timestamp.
 */
export function zipFilename(operation: string, now: Date = new Date()): string {
	const ts = now.toISOString().replace(/[:.]/g, "-").replace("T", "_").slice(0, 19);
	return `encryptor-${operation}-${ts}.zip`;
}

/**
 * Convert a base64 string (no data: prefix) to a Uint8Array for JSZip.
 */
export function base64ToUint8Array(base64: string): Uint8Array {
	const binary = atob(base64);
	const bytes = new Uint8Array(binary.length);
	for (let i = 0; i < binary.length; i++) {
		bytes[i] = binary.charCodeAt(i);
	}
	return bytes;
}
