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

	// Add attached/extracted files under files/.
	const filesFolder = zip.folder("files");
	for (const entry of entries) {
		if (filesFolder) {
			filesFolder.file(entry.name, entry.data);
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
