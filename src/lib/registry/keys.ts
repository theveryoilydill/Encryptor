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

	const fingerprint = key.getFingerprint().toUpperCase();
	const allIds = key.getKeyIDs().map((id) => id.toHex().toUpperCase());
	const [primary] = allIds;
	if (!fingerprint || !primary) {
		throw new RegistryError("Key is missing a fingerprint or key ID", 400);
	}

	// Extract and normalize self-reported User ID emails (deduped, capped).
	const emails: string[] = [];
	for (const userID of key.getUserIDs()) {
		const email = normalizeEmail(userID);
		if (email && !emails.includes(email)) emails.push(email);
		if (emails.length >= 10) break;
	}

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
		return result.signatures.length > 0;
	} catch {
		return false;
	}
}

/** Cap for the posted cleartext-signed challenge (signed message is small). */
export function maxChallengeSignatureBytes(): number {
	return 16 * 1024;
}
