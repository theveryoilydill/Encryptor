/**
 * Server-side OpenPGP parsing for the registry. The server NEVER trusts
 * client metadata: it re-parses the armored key, rejects private material,
 * and derives fingerprint / key IDs / emails from the parsed packets.
 *
 * # Mr. AI Acting on s183173's Behalf
 */
import * as openpgp from "openpgp";

import { RegistryError } from "./db";

/** Email grammar for registry indexing (strict, lowercase-normalized). */
const EMAIL_RE = /^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$/;

/** Fingerprint: 40 hex chars, normalized to uppercase without 0x. */
export const FINGERPRINT_RE = /^[0-9A-F]{40}$/;

/** Long key ID: 16 hex chars, normalized to uppercase without 0x. */
export const KEY_ID_RE = /^[0-9A-F]{16}$/;

/** Normalize + validate a fingerprint; null when malformed. */
export function normalizeFingerprint(raw: string): string | null {
	const hex = raw.replace(/^0x/i, "").replace(/\s+/g, "").toUpperCase();
	return FINGERPRINT_RE.test(hex) ? hex : null;
}

/** Normalize + validate a long key ID; null when malformed. */
export function normalizeKeyID(raw: string): string | null {
	const hex = raw.replace(/^0x/i, "").replace(/\s+/g, "").toUpperCase();
	return KEY_ID_RE.test(hex) ? hex : null;
}

/** Normalize + validate an email address; null when malformed. */
export function normalizeEmail(raw: string): string | null {
	const email = raw.trim().toLowerCase();
	if (email.length < 6 || email.length > 254) return null;
	return EMAIL_RE.test(email) ? email : null;
}

/**
 * Quantum-seal public key: base64 of a raw ML-KEM-768 (FIPS 203) public
 * key — exactly 1184 bytes. Stored as an OPTIONAL public column: the
 * secret half never leaves the owner's device, and the public half is
 * only ever used to ENCAPSULATE (seal) archive copies to this key.
 * Returns the trimmed value, or null when malformed.
 */
export const MLKEM768_PUBLIC_KEY_BYTES = 1184;

const PQ_SEAL_PK_B64_RE = /^[A-Za-z0-9+/]+={0,2}$/;

export function parsePqSealPk(raw: string): string | null {
	const value = raw.trim();
	if (value.length < 100 || value.length > 2048 || !PQ_SEAL_PK_B64_RE.test(value)) return null;
	try {
		if (atob(value).length !== MLKEM768_PUBLIC_KEY_BYTES) return null;
		return value;
	} catch {
		return null;
	}
}

/** A public key fully derived server-side from the armored input. */
export interface ParsedPublicKey {
	fingerprint: string;
	keyId: string;
	subkeyIds: string[];
	emails: string[];
	/** Canonicalized armor produced by re-serializing the parsed key. */
	armored: string;
	createdAt: number;
}

/**
 * Extract self-reported User ID emails from a parsed key. openpgp v6
 * getUserIDs() returns RAW userid strings ("Name <email>"), so emails are
 * pulled from the parsed User ID packets with a raw-string regex fallback.
 */
export function extractEmails(key: openpgp.Key, cap: number): string[] {
	const emails: string[] = [];
	const users = key.users ?? [];
	for (const user of users) {
		const userID = user?.userID;
		if (!userID) continue;
		// userID.email is parsed from the packet; fall back to the raw
		// userid string ("Name <email>") when the packet has no email field.
		const candidate = userID.email || userID.userID?.match(/<([^<>]+@[^<>]+)>/)?.[1] || "";
		const email = normalizeEmail(candidate);
		if (email && !emails.includes(email)) emails.push(email);
		if (emails.length >= cap) break;
	}
	return emails;
}

/**
 * Parse and validate an armored PUBLIC key. Throws RegistryError with a
 * 4xx status on any malformed input, private material, or oversized keys.
 * The returned armored value is re-serialized from the parsed packet set
 * so downstream storage is canonical and free of surrounding garbage.
 */
export async function parsePublicArmored(
	input: string,
	maxArmorBytes: number,
): Promise<ParsedPublicKey> {
	if (typeof input !== "string" || input.trim().length === 0) {
		throw new RegistryError("The 'armored' field is required", 400);
	}
	if (input.length > maxArmorBytes) {
		throw new RegistryError(`Key exceeds the ${maxArmorBytes} byte limit`, 413);
	}

	let key: openpgp.Key;
	try {
		key = await openpgp.readKey({ armoredKey: input });
	} catch {
		throw new RegistryError("Input is not a parseable OpenPGP key", 400);
	}

	// Hard rule: the registry stores public keys only. readKey produces a
	// private key whenever any private-key packet is present in the input.
	if (key.isPrivate()) {
		throw new RegistryError("Private key material detected — publish the PUBLIC key only", 400);
	}

	// Structural validation: the primary key and EVERY subkey must carry
	// valid self-/binding signatures. Without this, an attacker could glue
	// someone else's subkey packet onto their own primary key ("subkey
	// squatting") and hijack that subkey's key-ID lookup.
	try {
		await key.verifyPrimaryKey();
	} catch {
		throw new RegistryError("Key has an invalid primary key self-signature", 400);
	}
	if (key.subkeys.length > maxSubkeys()) {
		throw new RegistryError(`Key exceeds the maximum of ${maxSubkeys()} subkeys`, 400);
	}
	for (const subkey of key.subkeys) {
		try {
			// verify() checks the binding signatures against the key this
			// subkey was parsed under — a foreign subkey glued onto another
			// primary key fails here.
			await subkey.verify();
		} catch {
			throw new RegistryError("Key contains a subkey with an invalid binding signature", 400);
		}
	}

	const fingerprint = key.getFingerprint().toUpperCase();
	const allIds = key.getKeyIDs().map((id) => id.toHex().toUpperCase());
	const [primary] = allIds;
	if (!fingerprint || !primary) {
		throw new RegistryError("Key is missing a fingerprint or key ID", 400);
	}

	// Extract and normalize self-reported User ID emails (deduped, capped).
	const emails = extractEmails(key, maxEmails());

	// Best-effort creation time (epoch seconds); 0 when unavailable.
	const creation = key.getCreationTime();
	const createdAt =
		creation instanceof Date && !Number.isNaN(creation.getTime())
			? Math.floor(creation.getTime() / 1000)
			: 0;

	let armored: string;
	try {
		armored = key.armor();
	} catch {
		throw new RegistryError("Key could not be re-serialized", 400);
	}
	if (armored.length > maxArmorBytes) {
		throw new RegistryError(`Key exceeds the ${maxArmorBytes} byte limit`, 413);
	}

	return {
		fingerprint,
		keyId: primary,
		subkeyIds: allIds.slice(1),
		emails,
		armored,
		createdAt,
	};
}

/** A passphrase-encrypted private key validated against a known fingerprint. */
export interface ParsedEncryptedPrivate {
	/** Verified to equal the public record's fingerprint. */
	fingerprint: string;
	/** Canonicalized armor produced by re-serializing the parsed key. */
	armored: string;
}

/**
 * Parse and validate an armored ENCRYPTED private key for escrow. The
 * registry may hold private key material ONLY when every secret packet is
 * passphrase-encrypted (the armored backup form users already keep offline).
 * Throws RegistryError with a 4xx status on public keys, decrypted secret
 * packets, fingerprint mismatches, or malformed input.
 */
export async function parseEncryptedPrivateArmored(
	input: string,
	maxArmorBytes: number,
	expectedFingerprint: string,
): Promise<ParsedEncryptedPrivate> {
	if (typeof input !== "string" || input.trim().length === 0) {
		throw new RegistryError("The 'encryptedPrivate' field is required", 400);
	}
	if (input.length > maxArmorBytes) {
		throw new RegistryError(`Encrypted private key exceeds the ${maxArmorBytes} byte limit`, 413);
	}

	let key: openpgp.Key;
	try {
		key = await openpgp.readKey({ armoredKey: input });
	} catch {
		throw new RegistryError("encryptedPrivate is not a parseable OpenPGP key", 400);
	}
	if (!key.isPrivate()) {
		throw new RegistryError("encryptedPrivate must be a PRIVATE key", 400);
	}

	// Identity binding: the escrowed key must be the SAME key as the public
	// record — otherwise a lookup could hand back a decoy key that the
	// requester believes is theirs.
	const fingerprint = key.getFingerprint().toUpperCase();
	if (fingerprint !== expectedFingerprint) {
		throw new RegistryError("encryptedPrivate does not match this fingerprint", 400);
	}

	// Hard rule: NO usable private bytes in the database. openpgp.js keeps
	// a per-packet flag, so walk every packet ourselves instead of relying
	// on Key.isDecrypted() (whose "some vs every" semantics shifted across
	// major versions). A single decrypted packet rejects the whole upload.
	const packets = key.getKeys();
	const anyDecrypted = packets.some(({ keyPacket }) => {
		const secret = keyPacket as { isDecrypted?: () => boolean };
		return typeof secret.isDecrypted === "function" && secret.isDecrypted() === true;
	});
	if (anyDecrypted) {
		throw new RegistryError(
			"Private key contains decrypted material — encrypt it with a passphrase first",
			400,
		);
	}

	try {
		await key.verifyPrimaryKey();
	} catch {
		throw new RegistryError("Private key has an invalid primary key self-signature", 400);
	}

	let armored: string;
	try {
		armored = key.armor();
	} catch {
		throw new RegistryError("Private key could not be re-serialized", 400);
	}
	if (armored.length > maxArmorBytes) {
		throw new RegistryError(`Encrypted private key exceeds the ${maxArmorBytes} byte limit`, 413);
	}

	return { fingerprint, armored };
}

/**
 * The exact canonical message key holders must sign for challenge-response
 * revocation/replacement. Keeping it in ONE place (DRY) guarantees the
 * server and the client document agree on the bytes.
 */
export function challengeMessage(fingerprint: string, nonce: string): string {
	return `encryptor key registry\naction: prove-key-possession\nfingerprint: ${fingerprint}\nnonce: ${nonce}\n`;
}

/**
 * Verify a cleartext-signed challenge response against the STORED public
 * key of the fingerprint being operated on. Returns true only when the
 * signature is cryptographically valid for the exact expected message.
 */
export async function verifyChallengeSignature(
	storedArmored: string,
	fingerprint: string,
	nonce: string,
	cleartextSigned: string,
): Promise<boolean> {
	if (
		typeof cleartextSigned !== "string" ||
		cleartextSigned.length > maxChallengeSignatureBytes()
	) {
		return false;
	}
	let key: openpgp.Key;
	try {
		key = await openpgp.readKey({ armoredKey: storedArmored });
	} catch {
		return false;
	}
	try {
		const message = await openpgp.readCleartextMessage({
			cleartextMessage: cleartextSigned,
		});
		const expected = challengeMessage(fingerprint, nonce);
		if (message.getText() !== expected) return false;
		const result = await openpgp.verify({
			message,
			verificationKeys: key,
			expectSigned: true,
		});
		// Verify EXPLICITLY: a forged/invalid signature also yields a
		// signatures entry, so length alone would be a false positive.
		await Promise.all(result.signatures.map((sig) => sig.verified));
		return result.signatures.length > 0;
	} catch {
		return false;
	}
}

/** Cap for the posted cleartext-signed challenge (signed message is small). */
export function maxChallengeSignatureBytes(): number {
	return 16 * 1024;
}

/** Maximum subkeys accepted per published key (bounds storage + batches). */
export function maxSubkeys(): number {
	return 16;
}

/** Maximum self-reported emails indexed per key (single source of truth). */
export function maxEmails(): number {
	return 10;
}
