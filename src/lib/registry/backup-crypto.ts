/**
 * Passphrase encryption for offline keys-backup files.
 *
 * The plaintext backup (encryptor-keys-backup v1) contains revocation
 * tokens — the ONLY way to revoke a published key — so a lost laptop with
 * an unencrypted backup is a real revocation-power leak. This module adds
 * a version-2 envelope that seals the same JSON payload with a passphrase:
 *
 *   PBKDF2-SHA256 (600,000 iterations, random 16-byte salt)
 *     → AES-256-GCM (random 12-byte IV, GCM auth tag = integrity)
 *
 * Everything runs in the browser's WebCrypto; the passphrase never leaves
 * this module's call scope and the ciphertext blob never sees the network.
 * A wrong passphrase fails GCM authentication and is reported as such —
 * there is no fallback that could silently "recover" the file.
 *
 * # Mr. AI Acting on s183173's Behalf
 */

/** Envelope format marker — distinct from the plaintext v1 marker so the
 *  restore flow can pick the right path with a cheap sniff. */
export const ENCRYPTED_BACKUP_FORMAT = "encryptor-keys-backup-encrypted";

/** Envelope version — bumped independently of the payload format. */
export const ENCRYPTED_BACKUP_VERSION = 2;

/** OWASP-aligned PBKDF2 work factor for offline attacker budgets. */
export const PBKDF2_ITERATIONS = 600_000;

const SALT_BYTES = 16;
const IV_BYTES = 12;

/** machine-readable causes so the UI can show the right message. */
export type BackupDecryptErrorReason =
	| "not-encrypted"
	| "unsupported-version"
	| "corrupt"
	| "wrong-passphrase";

export class BackupDecryptFailure extends Error {
	reason: BackupDecryptErrorReason;

	constructor(reason: BackupDecryptErrorReason, message: string) {
		super(message);
		this.name = "BackupDecryptFailure";
		this.reason = reason;
	}
}

export interface EncryptedBackupEnvelope {
	format: typeof ENCRYPTED_BACKUP_FORMAT;
	version: typeof ENCRYPTED_BACKUP_VERSION;
	/** Payload export time, kept in the clear for the restore dialog. */
	exportedAt: string;
	kdf: {
		name: "PBKDF2";
		hash: "SHA-256";
		iterations: number;
		/** base64. */
		salt: string;
	};
	cipher: {
		name: "AES-GCM";
		/** base64. */
		iv: string;
	};
	/** base64 AES-GCM ciphertext of the plaintext backup JSON. */
	ciphertext: string;
	/** Advisory only — lets the dialog size expectations without decrypting. */
	keyCount?: number;
}

/* ------------------------------- base64 I/O ------------------------------- */

function toBase64(bytes: Uint8Array<ArrayBuffer>): string {
	// Chunked so a large ciphertext can't blow the call-stack with one
	// String.fromCharCode(...bytes) spread (arg-count limit ≈ 65k).
	let out = "";
	const CHUNK = 0x8000;
	for (let i = 0; i < bytes.length; i += CHUNK) {
		out += String.fromCharCode(...bytes.subarray(i, i + CHUNK));
	}
	return btoa(out);
}

function fromBase64(b64: string): Uint8Array<ArrayBuffer> {
	const bin = atob(b64);
	const out = new Uint8Array(new ArrayBuffer(bin.length));
	for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
	return out;
}

/* ------------------------------- key schedule ----------------------------- */

async function deriveKey(passphrase: string, salt: Uint8Array<ArrayBuffer>): Promise<CryptoKey> {
	const material = await crypto.subtle.importKey(
		"raw",
		new TextEncoder().encode(passphrase),
		"PBKDF2",
		false,
		["deriveKey"],
	);
	return crypto.subtle.deriveKey(
		{ name: "PBKDF2", hash: "SHA-256", salt, iterations: PBKDF2_ITERATIONS },
		material,
		{ name: "AES-GCM", length: 256 },
		false,
		["encrypt", "decrypt"],
	);
}

/* --------------------------------- public --------------------------------- */

/** Cheap structural sniff: is this backup text a v2 encrypted envelope? */
export function isEncryptedBackupText(text: string): boolean {
	try {
		const d: unknown = JSON.parse(text);
		return (
			!!d &&
			typeof d === "object" &&
			!Array.isArray(d) &&
			(d as { format?: unknown }).format === ENCRYPTED_BACKUP_FORMAT
		);
	} catch {
		return false;
	}
}

/**
 * Seal a plaintext backup JSON (the exportMyKeys() payload) into a version-2
 * encrypted envelope. Non-extractable derived key; IV and salt are fresh
 * per call, so identical payloads never produce identical files.
 */
export async function encryptKeysBackup(plaintext: string, passphrase: string): Promise<string> {
	if (!passphrase) throw new BackupDecryptFailure("corrupt", "A passphrase is required.");
	const salt = crypto.getRandomValues(new Uint8Array(new ArrayBuffer(SALT_BYTES)));
	const iv = crypto.getRandomValues(new Uint8Array(new ArrayBuffer(IV_BYTES)));
	const key = await deriveKey(passphrase, salt);
	const ct = await crypto.subtle.encrypt(
		{ name: "AES-GCM", iv },
		key,
		new TextEncoder().encode(plaintext),
	);
	// Advisory key count for the restore dialog (payload stays the authority).
	let keyCount: number | undefined;
	try {
		const parsed: unknown = JSON.parse(plaintext);
		if (
			parsed &&
			typeof parsed === "object" &&
			Array.isArray((parsed as { keys?: unknown }).keys)
		) {
			keyCount = (parsed as { keys: unknown[] }).keys.length;
		}
	} catch {
		// payload sniffing is advisory only
	}
	const envelope: EncryptedBackupEnvelope = {
		format: ENCRYPTED_BACKUP_FORMAT,
		version: ENCRYPTED_BACKUP_VERSION,
		exportedAt: new Date().toISOString(),
		kdf: {
			name: "PBKDF2",
			hash: "SHA-256",
			iterations: PBKDF2_ITERATIONS,
			salt: toBase64(salt),
		},
		cipher: { name: "AES-GCM", iv: toBase64(iv) },
		ciphertext: toBase64(new Uint8Array(ct)),
		...(keyCount !== undefined ? { keyCount } : {}),
	};
	return JSON.stringify(envelope, null, 2);
}

/**
 * Open a version-2 envelope and return the plaintext backup JSON.
 * Throws BackupDecryptFailure with a machine-readable reason:
 *   not-encrypted       → the text is not an encrypted envelope at all
 *   unsupported-version → future envelope version this build can't read
 *   corrupt             → structurally broken envelope / undecryptable blob
 *   wrong-passphrase    → GCM auth failed (wrong passphrase or mangled file)
 */
export async function decryptKeysBackup(text: string, passphrase: string): Promise<string> {
	if (!isEncryptedBackupText(text)) {
		throw new BackupDecryptFailure("not-encrypted", "This backup is not passphrase-encrypted.");
	}
	let d: EncryptedBackupEnvelope;
	try {
		d = JSON.parse(text) as EncryptedBackupEnvelope;
	} catch {
		throw new BackupDecryptFailure("corrupt", "The encrypted backup is not valid JSON.");
	}
	if (d.version !== ENCRYPTED_BACKUP_VERSION) {
		throw new BackupDecryptFailure(
			"unsupported-version",
			`Unsupported encrypted backup version (${String(d.version)}). This app reads version ${ENCRYPTED_BACKUP_VERSION}.`,
		);
	}
	if (
		!d.kdf ||
		d.kdf.name !== "PBKDF2" ||
		d.kdf.hash !== "SHA-256" ||
		typeof d.kdf.iterations !== "number" ||
		!Number.isFinite(d.kdf.iterations) ||
		d.kdf.iterations < 1 ||
		d.kdf.iterations > 10_000_000 ||
		typeof d.kdf.salt !== "string" ||
		!d.cipher ||
		d.cipher.name !== "AES-GCM" ||
		typeof d.cipher.iv !== "string" ||
		typeof d.ciphertext !== "string"
	) {
		throw new BackupDecryptFailure("corrupt", "The encrypted backup envelope is malformed.");
	}
	let key: CryptoKey;
	let plaintext: ArrayBuffer;
	try {
		key = await deriveKey(passphrase, fromBase64(d.kdf.salt));
		plaintext = await crypto.subtle.decrypt(
			{ name: "AES-GCM", iv: fromBase64(d.cipher.iv) },
			key,
			fromBase64(d.ciphertext),
		);
	} catch {
		// GCM auth failure covers both a wrong passphrase and a tampered file;
		// by far the most common cause is the passphrase.
		throw new BackupDecryptFailure(
			"wrong-passphrase",
			"Wrong passphrase — the backup stays sealed.",
		);
	}
	const out = new TextDecoder().decode(plaintext);
	if (!out.trim().startsWith("{")) {
		// Decrypted to something unexpected: treat as corruption, not success.
		throw new BackupDecryptFailure("corrupt", "The decrypted backup payload is malformed.");
	}
	return out;
}
