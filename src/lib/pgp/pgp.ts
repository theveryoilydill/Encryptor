/**
 * PGP operations backed by openpgp.js v6.
 *
 * All functions are pure (no IO) so they can run client-side in the browser
 * or server-side inside a Cloudflare Worker / Next.js server route.
 */
import * as openpgp from "openpgp";

export type Armored = string;

export interface PublicKeyInfo {
	armored: Armored;
	fingerprint: string;
	keyID: string;
	userIDs: { name?: string; email?: string; userID?: string }[];
	creationTime: Date;
	expirationTime: Date | null;
	algorithm: string;
	bitSize?: number;
	curve?: string;
	isRevoked: boolean;
}

export interface PrivateKeyInfo extends PublicKeyInfo {
	/** Whether the private key material is present (true) or just public. */
	isPrivate: true;
	isDecrypted: boolean;
}

export type AnyKeyInfo = PublicKeyInfo | PrivateKeyInfo;

export interface GenerateKeyOptions {
	name?: string;
	email?: string;
	passphrase?: string;
	/**
	 * "ecc" uses modern Edwards-curve keys (recommended, default).
	 * "rsa" is older but widely compatible.
	 */
	type?: "ecc" | "rsa";
	/** For ECC: see openpgp.EllipticCurveName */
	curve?:
		| "ed25519Legacy"
		| "curve25519Legacy"
		| "nistP256"
		| "nistP384"
		| "nistP521"
		| "brainpoolP256r1"
		| "brainpoolP384r1"
		| "brainpoolP512r1"
		| "secp256k1";
	/** For RSA: 2048 | 3072 | 4096 */
	rsaBits?: 2048 | 3072 | 4096;
	/** Key expiration in seconds from now. 0 = no expiration. */
	expirationSeconds?: number;
}

export interface GeneratedKeyPair {
	privateKey: Armored;
	publicKey: Armored;
	info: PrivateKeyInfo;
}

export interface EncryptAndSignOptions {
	plaintext: string;
	recipientPublicKeys: Armored[];
	/** The signer's private key — can be an armored string or an already-parsed PrivateKey object. */
	signerPrivateKey: Armored | openpgp.PrivateKey;
	signerPassphrase?: string;
	/** Sign as a separate detached signature file (false = inline signature in the encrypted message). */
	detached?: boolean;
	/** Message compression preference (settings-driven). openpgp.js uses the
	 *  sender's preferred algorithm only when every recipient key advertises
	 *  it, and falls back to uncompressed otherwise — see settings.ts. */
	compression?: "uncompressed" | "zip" | "zlib";
}

export interface DecryptAndVerifyOptions {
	armoredMessage: string;
	/** The decryption private key — can be an armored string or an already-parsed PrivateKey object. */
	decryptionPrivateKey: Armored | openpgp.PrivateKey;
	decryptionPassphrase?: string;
	/** One or more public keys that may have signed the message. */
	verificationPublicKeys: Armored[];
}

export interface DecryptAndVerifyResult {
	plaintext: string;
	signatures: {
		keyID: string;
		fingerprint?: string;
		verified: "valid" | "invalid" | "unknown";
		error?: string;
		/** Signer's full name from the public key's primary user ID. */
		name?: string;
		/** Signer's email from the public key's primary user ID. */
		email?: string;
		/** Comment field from the public key's primary user ID. */
		comment?: string;
		/** Raw user ID string from the public key. */
		userID?: string;
		/** All user IDs on the public key. */
		allUserIDs?: string[];
		/** High-precision ISO timestamp from the signature's timestamp notation. */
		timestampIso?: string;
	}[];
}

export interface SignOptions {
	plaintext: string;
	/** The signer's private key — can be an armored string or an already-parsed PrivateKey object. */
	privateKey: Armored | openpgp.PrivateKey;
	passphrase?: string;
	/** Detached = separate signature block; inline = cleartext signed message. */
	detached?: boolean;
}

export interface VerifyOptions {
	/** The original plaintext. Required for detached signatures; ignored for cleartext-signed messages. */
	plaintext?: string;
	/** Either a detached signature or a cleartext-signed message. */
	armoredSignature: string;
	/** Public keys that may have signed. */
	publicKeys: Armored[];
	/** When false, armoredSignature is treated as a cleartext-signed message and plaintext is ignored. */
	detached?: boolean;
}

export interface VerifyResult {
	verified: "valid" | "invalid" | "unknown";
	signatures: {
		keyID: string;
		fingerprint?: string;
		verified: "valid" | "invalid" | "unknown";
		error?: string;
		/** Signer's full name from the public key's primary user ID. */
		name?: string;
		/** Signer's email from the public key's primary user ID. */
		email?: string;
		/** Comment field from the public key's primary user ID. */
		comment?: string;
		/** Raw user ID string from the public key. */
		userID?: string;
		/** All user IDs on the public key. */
		allUserIDs?: string[];
		/** High-precision ISO timestamp from the signature's timestamp notation. */
		timestampIso?: string;
	}[];
}

function keyIDToHex(keyID: openpgp.KeyID | undefined): string {
	if (!keyID) return "";
	return keyID.toHex().toUpperCase();
}

function formatDate(d: Date | null): string {
	if (!d) return "";
	return d.toISOString();
}

/** Read an armored key (public or private) into a Key object. */
export async function readKey(armored: Armored): Promise<openpgp.Key> {
	try {
		return await openpgp.readKey({ armoredKey: armored });
	} catch (e) {
		// Some users paste keys with extra whitespace; try a tolerant read.
		try {
			return await openpgp.readKey({
				armoredKey: armored.trim(),
			});
		} catch {
			throw new Error(
				`Could not read PGP key: ${(e as Error).message}. Make sure you pasted a valid ASCII-armored key block.`,
			);
		}
	}
}

/**
 * Read a private key (unlocking it if needed) and return its public half as
 * ASCII-armored text. Used for "Include me as a recipient" — derives the
 * user's own public key from their configured private key.
 */
export async function derivePublicFromPrivate(
	armoredPrivate: Armored,
	passphrase?: string,
): Promise<Armored> {
	const key = await readKey(armoredPrivate);
	if (!key.isPrivate()) {
		return key.armor();
	}
	const unlocked = await unlockPrivateKey(key as openpgp.PrivateKey, passphrase);
	return unlocked.toPublic().armor();
}

export async function readPrivateKey(armored: Armored): Promise<openpgp.PrivateKey> {
	const key = await readKey(armored);
	if (!key.isPrivate()) {
		throw new Error(
			"The provided key is a public key. A private key is required for signing and decryption.",
		);
	}
	return key as openpgp.PrivateKey;
}

/** Unlock an encrypted (passphrase-protected) private key. No-op if already unlocked. */
export async function unlockPrivateKey(
	key: openpgp.PrivateKey,
	passphrase?: string,
): Promise<openpgp.PrivateKey> {
	if (!key.isDecrypted()) {
		if (!passphrase) {
			throw new Error("This private key is passphrase-protected. Please provide the passphrase.");
		}
		try {
			return await openpgp.decryptKey({ privateKey: key, passphrase });
		} catch (e) {
			throw new Error(`Failed to unlock private key: ${(e as Error).message}`);
		}
	}
	return key;
}

/**
 * Runtime-only per-subkey metadata attached to describePublicKey output via a
 * spread cast (like subkeyFingerprints below — deliberately NOT part of the
 * exported PublicKeyInfo type, so every consumer that serializes the info
 * keeps working untouched). Shape (R11):
 *   { keyID: string (uppercase hex), algorithm: string (RAW openpgp value,
 *   e.g. "ecdhX25519" / "rsaEncryptSign"), created: Date, expiresAt:
 *   number | null (epoch-ms; null = never/unknown) }
 * Consumers must read it defensively — describeSubkeyDetails in
 * key-details.ts is the canonical display-side parser.
 */
interface SubkeyRuntimeDetail {
	keyID: string;
	algorithm: string;
	created: Date;
	expiresAt: number | null;
}

/**
 * Subkey expiration → epoch-ms with the SAME guard posture as the primary
 * key's expiration in describePublicKey below: a valid Date → getTime(); an
 * Array → first valid element (openpgp can return arrays for multi-key
 * cases); a number → only when finite and > 0 (openpgp v6 returns Infinity
 * for keys it considers non-expiring — Infinity must NEVER become
 * new Date(Infinity), which is an Invalid Date → NaN epoch-ms). Any throw,
 * null, or invalid value → null (treated as "never/unknown", never fatal).
 */
async function subkeyExpirationMs(subkey: openpgp.Subkey): Promise<number | null> {
	try {
		const exp = await subkey.getExpirationTime();
		if (exp instanceof Date) {
			return Number.isNaN(exp.getTime()) ? null : exp.getTime();
		}
		if (Array.isArray(exp)) {
			const first = exp[0];
			if (first instanceof Date && !Number.isNaN(first.getTime())) {
				return first.getTime();
			}
			if (typeof first === "number" && Number.isFinite(first) && first > 0) {
				return first;
			}
			return null;
		}
		if (typeof exp === "number" && Number.isFinite(exp) && exp > 0) {
			return exp;
		}
		return null;
	} catch {
		return null;
	}
}

export async function describePublicKey(armored: Armored): Promise<PublicKeyInfo> {
	const key = await readKey(armored);
	const primary = key.getAlgorithmInfo();
	const fp = key.getFingerprint().toUpperCase();
	const subkeys = key.getSubkeys();
	const subkeyFPs = subkeys.map((s) => s.getFingerprint().toUpperCase());

	// Try to find the most relevant encryption-capable subkey's expiration
	let expirationTime: Date | null = null;
	try {
		const exp = await key.getExpirationTime();
		if (exp instanceof Date) {
			// Guard against clock-skew garbage: an invalid Date would flow through
			// as NaN epoch-ms downstream (badges/timestamps). Treat as unknown.
			expirationTime = Number.isNaN(exp.getTime()) ? null : exp;
		} else if (Array.isArray(exp)) {
			// openpgp can return arrays of Dates or numbers for multi-key cases.
			const first = exp[0];
			if (first instanceof Date && !Number.isNaN(first.getTime())) {
				expirationTime = first;
			} else if (typeof first === "number" && Number.isFinite(first) && first > 0) {
				expirationTime = new Date(first);
			}
		} else if (typeof exp === "number" && Number.isFinite(exp) && exp > 0) {
			// openpgp v6 returns Infinity (a number) for keys it considers
			// non-expiring — Infinity must NOT become new Date(Infinity) (Invalid
			// Date → NaN epoch-ms), so require a finite value here.
			expirationTime = new Date(exp);
		}
	} catch {
		expirationTime = null;
	}

	// Per-subkey details (R11): captured alongside subkeyFingerprints. Each
	// subkey is fully isolated in try/catch so one malformed subkey can never
	// break the whole describe — it just yields no entry (or expiresAt: null
	// via subkeyExpirationMs' guard posture). Promise.all over a map keeps the
	// result in packet order (deterministic display order).
	const describedSubkeys = await Promise.all(
		subkeys.map(async (s): Promise<SubkeyRuntimeDetail | null> => {
			try {
				return {
					keyID: keyIDToHex(s.getKeyID()),
					algorithm: s.getAlgorithmInfo().algorithm,
					created: s.getCreationTime(),
					expiresAt: await subkeyExpirationMs(s),
				};
			} catch {
				// One bad subkey never breaks describe — skip it entirely.
				return null;
			}
		}),
	);
	const subkeyDetails = describedSubkeys.filter((d): d is SubkeyRuntimeDetail => d !== null);

	return {
		armored,
		fingerprint: fp,
		keyID: keyIDToHex(key.getKeyID()),
		userIDs: key.getUserIDs().map((uid) => {
			const m = uid.match(/^(.*?)\s*<(.*)>$/);
			if (m) return { name: m[1].trim(), email: m[2].trim(), userID: uid };
			return { userID: uid };
		}),
		creationTime: key.getCreationTime(),
		expirationTime,
		algorithm: primary.algorithm,
		bitSize: (primary as { bits?: number }).bits,
		curve: (primary as { curve?: string }).curve,
		isRevoked: key.revocationSignatures.length > 0,
		// include subkey fingerprints + per-subkey details for
		// debugging/visibility (not part of the exported type but useful —
		// consumers read these spread-cast fields defensively, e.g.
		// describeSubkeyDetails in key-details.ts)
		...({ subkeyFingerprints: subkeyFPs, subkeyDetails } as object),
	};
}

export async function describePrivateKey(
	armored: Armored,
	_passphrase?: string,
): Promise<PrivateKeyInfo> {
	const key = await readPrivateKey(armored);
	const pub = await describePublicKey(armored);
	return {
		...pub,
		isPrivate: true,
		isDecrypted: key.isDecrypted(),
	};
}

export async function generateKeyPair(opts: GenerateKeyOptions): Promise<GeneratedKeyPair> {
	const type = opts.type ?? "ecc";
	const userIDs = [
		{
			name: opts.name?.trim() || undefined,
			email: opts.email?.trim() || undefined,
		},
	].filter((u) => u.name || u.email) as { name?: string; email?: string }[];

	// Key expiration - openpgp accepts a Date or 0/undefined
	let keyExpirationTime: number | undefined;
	if (opts.expirationSeconds && opts.expirationSeconds > 0) {
		keyExpirationTime = opts.expirationSeconds;
	}

	// openpgp.js v6 has overloads on the `format` field. We want armored output,
	// so we construct the options inline to get the right overload.
	const generated = await openpgp.generateKey({
		type,
		userIDs: userIDs.length ? userIDs : [{}],
		passphrase: opts.passphrase || undefined,
		format: "armored",
		...(type === "ecc"
			? { curve: opts.curve ?? "ed25519Legacy" }
			: { rsaBits: opts.rsaBits ?? 4096 }),
		...(keyExpirationTime ? { keyExpirationTime } : {}),
	});

	const info = await describePrivateKey(generated.privateKey, opts.passphrase);
	return {
		privateKey: generated.privateKey,
		publicKey: generated.publicKey,
		info,
	};
}

export async function encryptAndSign(opts: EncryptAndSignOptions): Promise<string> {
	if (!opts.plaintext) throw new Error("Plaintext is required.");
	if (!opts.recipientPublicKeys.length)
		throw new Error("At least one recipient public key is required.");
	if (!opts.signerPrivateKey) throw new Error("A signer private key is required.");

	const encryptionKeys: openpgp.PublicKey[] = [];
	for (const arm of opts.recipientPublicKeys) {
		encryptionKeys.push(await readKey(arm));
	}

	const signingKey =
		typeof opts.signerPrivateKey === "string"
			? await unlockPrivateKey(await readPrivateKey(opts.signerPrivateKey), opts.signerPassphrase)
			: opts.signerPrivateKey;

	const message = await openpgp.createMessage({ text: opts.plaintext });

	// Embed a high-precision timestamp notation on the signing signature.
	const { buildTimestampNotation } = await import("@/lib/pgp/signer-info");
	const signatureNotations = buildTimestampNotation();

	const encrypted = await openpgp.encrypt({
		message,
		encryptionKeys,
		signingKeys: [signingKey],
		signatureNotations,
		// Compression preference (v6 replaced the old compress flag with the
		// sender's preferredCompressionAlgorithm; openpgp.js still degrades
		// gracefully when a recipient doesn't advertise the algorithm).
		...(opts.compression
			? {
					config: {
						preferredCompressionAlgorithm:
							opts.compression === "zlib"
								? openpgp.enums.compression.zlib
								: opts.compression === "zip"
									? openpgp.enums.compression.zip
									: openpgp.enums.compression.uncompressed,
					},
				}
			: {}),
		format: "armored",
	});

	return encrypted as string;
}

/** Encrypt WITHOUT signing (the "auto sign off" preference path): no private
 *  key or passphrase required — the message is only encrypted to the
 *  recipients. Shares the compression handling with encryptAndSign. */
export async function encryptMessage(opts: {
	plaintext: string;
	recipientPublicKeys: string[];
	compression?: "zlib" | "zip" | "uncompressed";
}): Promise<string> {
	if (!opts.plaintext) throw new Error("Plaintext is required.");
	if (!opts.recipientPublicKeys.length)
		throw new Error("At least one recipient public key is required.");

	const encryptionKeys: openpgp.PublicKey[] = [];
	for (const arm of opts.recipientPublicKeys) {
		encryptionKeys.push(await readKey(arm));
	}

	const message = await openpgp.createMessage({ text: opts.plaintext });
	const encrypted = await openpgp.encrypt({
		message,
		encryptionKeys,
		...(opts.compression
			? {
					config: {
						preferredCompressionAlgorithm:
							opts.compression === "zlib"
								? openpgp.enums.compression.zlib
								: opts.compression === "zip"
									? openpgp.enums.compression.zip
									: openpgp.enums.compression.uncompressed,
					},
				}
			: {}),
		format: "armored",
	});
	return encrypted as string;
}

export async function decryptAndVerify(
	opts: DecryptAndVerifyOptions,
): Promise<DecryptAndVerifyResult> {
	if (!opts.armoredMessage) throw new Error("An encrypted message is required.");
	if (!opts.decryptionPrivateKey) throw new Error("A decryption private key is required.");

	// Accept either an armored string or an already-parsed PrivateKey object.
	const decryptionKey =
		typeof opts.decryptionPrivateKey === "string"
			? await unlockPrivateKey(
					await readPrivateKey(opts.decryptionPrivateKey),
					opts.decryptionPassphrase,
				)
			: opts.decryptionPrivateKey;

	const verificationKeys: openpgp.PublicKey[] = [];
	for (const arm of opts.verificationPublicKeys) {
		try {
			verificationKeys.push(await readKey(arm));
		} catch {
			// skip invalid keys
		}
	}

	const message = await openpgp.readMessage({ armoredMessage: opts.armoredMessage });

	const result = await openpgp.decrypt({
		message,
		decryptionKeys: [decryptionKey],
		verificationKeys,
	});

	const plaintext = typeof result.data === "string" ? result.data : "";

	// In openpgp.js v6, `sig.verified` is `Promise<true>` and *throws* on
	// invalid signature or missing key. Build a fingerprint + signer-info
	// lookup from the verification keys for richer reporting.
	const fpByKeyID = new Map<string, string>();
	const infoByKeyID = new Map<
		string,
		{ name?: string; email?: string; comment?: string; userID?: string; allUserIDs?: string[] }
	>();
	for (const k of verificationKeys) {
		try {
			const fp = k.getFingerprint().toUpperCase();
			fpByKeyID.set(keyIDToHex(k.getKeyID()), fp);

			// Extract user IDs from the verification key so we can surface the
			// signer's name + email.
			const allUserIDs = k.getUserIDs();
			let primary: { name?: string; email?: string; comment?: string; userID?: string } = {};
			try {
				const p = await k.getPrimaryUser();
				if (p?.user?.userID) {
					const { parseUserID } = await import("@/lib/pgp/signer-info");
					primary = {
						...parseUserID(p.user.userID.userID ?? ""),
						userID: p.user.userID.userID,
					};
				}
			} catch {
				if (allUserIDs.length > 0) {
					const { parseUserID } = await import("@/lib/pgp/signer-info");
					primary = {
						...parseUserID(allUserIDs[0]),
						userID: allUserIDs[0],
					};
				}
			}
			// Index by every key ID this key advertises (primary + subkeys).
			for (const kid of k.getKeyIDs()) {
				infoByKeyID.set(keyIDToHex(kid), { ...primary, allUserIDs });
			}
		} catch {
			// ignore
		}
	}

	const sigsWithV = await Promise.all(
		(result.signatures || []).map(async (sig) => {
			const keyID = keyIDToHex(sig.keyID);
			const fingerprint = fpByKeyID.get(keyID);
			const info = infoByKeyID.get(keyID);
			let verified: "valid" | "invalid" | "unknown" = "unknown";
			let error: string | undefined;
			try {
				await sig.verified;
				verified = "valid";
			} catch (e) {
				const msg = (e as Error).message || "";
				if (/not present|could not verify|no key/i.test(msg)) {
					verified = "unknown";
				} else {
					verified = "invalid";
				}
				error = msg;
			}

			// Read the high-precision timestamp notation from the signature.
			let timestampIso: string | undefined;
			try {
				const sigObj = await sig.signature;
				const packet = sigObj?.packets?.[0];
				if (packet?.rawNotations) {
					const { readTimestampNotation } = await import("@/lib/pgp/signer-info");
					timestampIso = readTimestampNotation(
						packet.rawNotations as unknown as Array<{
							name: string;
							value: Uint8Array;
							humanReadable: boolean;
							critical: boolean;
						}>,
					);
				}
			} catch {
				// ignore — timestamp is best-effort
			}

			return {
				keyID,
				fingerprint,
				verified,
				error,
				name: info?.name,
				email: info?.email,
				comment: info?.comment,
				userID: info?.userID,
				allUserIDs: info?.allUserIDs,
				timestampIso,
			};
		}),
	);

	return { plaintext, signatures: sigsWithV };
}

/**
 * Decrypt a message, then fetch the signers' public keys by key ID via the
 * provided lookup callback, and re-decrypt with verificationKeys set so the
 * signatures can be verified. Returns the plaintext plus richer signature
 * info (including the owner username if the lookup returned one).
 */
export async function decryptAndAutoVerify(
	opts: DecryptAndVerifyOptions,
	fetchKeysByKeyID: (keyIDs: string[]) => Promise<
		Array<{
			armored: string;
			keyID: string;
			fingerprint: string;
			username?: string;
			allKeyIDs?: string[];
			/** True when the record came from the caller's own configured key. */
			self?: boolean;
			/** Expiration of the record's key as epoch-ms, when known (R9: only
			 *  locally-resolved records carry it). */
			expiresAt?: number | null;
			/** Which source resolved this key (local / Keybase / openpgp.org). */
			resolvedFrom?: "local" | "keybase" | "openpgp.org";
		}>
	>,
): Promise<{
	plaintext: string;
	signatures: Array<{
		keyID: string;
		fingerprint?: string;
		username?: string;
		verified: "valid" | "invalid" | "unknown";
		error?: string;
		name?: string;
		email?: string;
		comment?: string;
		userID?: string;
		allUserIDs?: string[];
		timestampIso?: string;
		/** True when the signer is the user's own locally-configured key. */
		self?: boolean;
		/** Expiration of the signer's key as epoch-ms, when known. */
		expiresAt?: number | null;
		/** Where the verification key came from. */
		resolvedFrom?: "local" | "keybase" | "openpgp.org";
	}>;
}> {
	if (!opts.armoredMessage) throw new Error("An encrypted message is required.");
	if (!opts.decryptionPrivateKey) throw new Error("A decryption private key is required.");

	// Accept either an armored string or an already-parsed PrivateKey object.
	const decryptionKey =
		typeof opts.decryptionPrivateKey === "string"
			? await unlockPrivateKey(
					await readPrivateKey(opts.decryptionPrivateKey),
					opts.decryptionPassphrase,
				)
			: opts.decryptionPrivateKey;

	// First pass: decrypt without verification to discover signature key IDs.
	const message = await openpgp.readMessage({
		armoredMessage: opts.armoredMessage,
	});

	const initial = await openpgp.decrypt({
		message,
		decryptionKeys: [decryptionKey],
		verificationKeys: [],
	});

	const plaintext = typeof initial.data === "string" ? initial.data : "";
	const initialSigs = initial.signatures ?? [];

	if (initialSigs.length === 0) {
		return { plaintext, signatures: [] };
	}

	// Collect unique key IDs.
	const keyIDs = Array.from(new Set(initialSigs.map((s) => keyIDToHex(s.keyID)).filter(Boolean)));

	// Fetch the corresponding public keys.
	const fetched = keyIDs.length > 0 ? await fetchKeysByKeyID(keyIDs) : [];

	if (fetched.length === 0) {
		// No keys could be fetched — return unknown signatures with key IDs only.
		return {
			plaintext,
			signatures: initialSigs.map((s) => ({
				keyID: keyIDToHex(s.keyID),
				verified: "unknown" as const,
			})),
		};
	}

	// Second pass: decrypt again with verificationKeys so we get verified statuses.
	const verificationKeys: openpgp.PublicKey[] = [];
	for (const f of fetched) {
		try {
			verificationKeys.push(await readKey(f.armored));
		} catch {
			// skip invalid keys
		}
	}
	// Also include any caller-supplied verification keys (for manual fallback).
	for (const arm of opts.verificationPublicKeys ?? []) {
		try {
			verificationKeys.push(await readKey(arm));
		} catch {
			// skip
		}
	}

	// Build a lookup of parsed PublicKey objects by key ID so we can surface
	// the signer's name + email from the key's user IDs.
	const infoByKeyID = new Map<
		string,
		{ name?: string; email?: string; comment?: string; userID?: string; allUserIDs?: string[] }
	>();
	for (const k of verificationKeys) {
		try {
			const allUserIDs = k.getUserIDs();
			let primary: { name?: string; email?: string; comment?: string; userID?: string } = {};
			try {
				const p = await k.getPrimaryUser();
				if (p?.user?.userID) {
					const { parseUserID } = await import("@/lib/pgp/signer-info");
					primary = {
						...parseUserID(p.user.userID.userID ?? ""),
						userID: p.user.userID.userID,
					};
				}
			} catch {
				if (allUserIDs.length > 0) {
					const { parseUserID } = await import("@/lib/pgp/signer-info");
					primary = {
						...parseUserID(allUserIDs[0]),
						userID: allUserIDs[0],
					};
				}
			}
			// Index by every key ID this key advertises (primary + subkeys) so
			// a signature made by a subkey still finds the owner's info.
			for (const kid of k.getKeyIDs()) {
				infoByKeyID.set(keyIDToHex(kid), { ...primary, allUserIDs });
			}
		} catch {
			// ignore
		}
	}

	// Re-read the message for the second pass — the message object is consumed
	// by the first decrypt, so we need to re-parse it.
	const message2 = await openpgp.readMessage({
		armoredMessage: opts.armoredMessage,
	});

	const verified = await openpgp.decrypt({
		message: message2,
		decryptionKeys: [decryptionKey],
		verificationKeys,
	});

	// Resolve each signature's verified status, signer info, and timestamp.
	const finalSigs = await Promise.all(
		(verified.signatures ?? []).map(async (sig) => {
			const keyID = keyIDToHex(sig.keyID);
			let verifiedStatus: "valid" | "invalid" | "unknown" = "unknown";
			let error: string | undefined;
			try {
				await sig.verified;
				verifiedStatus = "valid";
			} catch (e) {
				const msg = (e as Error).message || "";
				if (/not present|could not verify|no key/i.test(msg)) {
					verifiedStatus = "unknown";
				} else {
					verifiedStatus = "invalid";
				}
				error = msg;
			}
			// Find the matching fetched key for fingerprint + username.
			const match = fetched.find((f) => f.allKeyIDs?.includes(keyID.toUpperCase()));
			const info = infoByKeyID.get(keyID);

			// Read the high-precision timestamp notation from the signature, if present.
			let timestampIso: string | undefined;
			try {
				const sigObj = await sig.signature;
				const packet = sigObj?.packets?.[0];
				if (packet?.rawNotations) {
					const { readTimestampNotation } = await import("@/lib/pgp/signer-info");
					timestampIso = readTimestampNotation(
						packet.rawNotations as unknown as Array<{
							name: string;
							value: Uint8Array;
							humanReadable: boolean;
							critical: boolean;
						}>,
					);
				}
			} catch {
				// ignore — timestamp is best-effort
			}

			return {
				keyID,
				fingerprint: match?.fingerprint,
				username: match?.username,
				self: match?.self,
				expiresAt: match?.expiresAt,
				resolvedFrom: match?.resolvedFrom,
				verified: verifiedStatus,
				error,
				name: info?.name,
				email: info?.email,
				comment: info?.comment,
				userID: info?.userID,
				allUserIDs: info?.allUserIDs,
				timestampIso,
			};
		}),
	);

	return { plaintext, signatures: finalSigs };
}

export async function signMessage(opts: SignOptions): Promise<string> {
	if (!opts.plaintext) throw new Error("Plaintext is required.");
	if (!opts.privateKey) throw new Error("A signer private key is required.");

	const signingKey =
		typeof opts.privateKey === "string"
			? await unlockPrivateKey(await readPrivateKey(opts.privateKey), opts.passphrase)
			: opts.privateKey;

	// Embed a high-precision timestamp as a human-readable notation data
	// subpacket. PGP's built-in signature creation time is only seconds
	// precision; this notation adds milliseconds so verifiers can display
	// an exact signing time.
	const { buildTimestampNotation } = await import("@/lib/pgp/signer-info");
	const signatureNotations = buildTimestampNotation();

	if (opts.detached) {
		// For detached signatures we sign the binary message and emit a separate
		// -----BEGIN PGP SIGNATURE----- block.
		const message = await openpgp.createMessage({ text: opts.plaintext });
		const sig = await openpgp.sign({
			message,
			signingKeys: [signingKey],
			detached: true,
			format: "armored",
			signatureNotations,
		});
		return sig as string;
	}

	// For inline (cleartext) signing, use createCleartextMessage so the output
	// is a human-readable -----BEGIN PGP SIGNED MESSAGE----- block.
	const cleartext = await openpgp.createCleartextMessage({ text: opts.plaintext });
	const signed = await openpgp.sign({
		message: cleartext,
		signingKeys: [signingKey],
		format: "armored",
		signatureNotations,
	});
	return signed as string;
}

export async function verifyMessage(opts: VerifyOptions): Promise<VerifyResult> {
	if (!opts.armoredSignature) throw new Error("Signature is required.");
	if (!opts.publicKeys.length)
		throw new Error("At least one public key is required for verification.");

	const verificationKeys: openpgp.PublicKey[] = [];
	for (const arm of opts.publicKeys) {
		try {
			verificationKeys.push(await readKey(arm));
		} catch {
			// skip
		}
	}

	if (opts.detached) {
		if (!opts.plaintext) throw new Error("Plaintext is required for detached verification.");
		const message = await openpgp.createMessage({ text: opts.plaintext });
		const signature = await openpgp.readSignature({ armoredSignature: opts.armoredSignature });
		const result = await openpgp.verify({
			message,
			signature,
			verificationKeys,
		});
		return await buildVerifyResult(result, verificationKeys);
	}

	// Try to read as a cleartext signed message first (most common case).
	// If that fails, fall back to reading as a regular armored message.
	try {
		const cleartext = await openpgp.readCleartextMessage({
			cleartextMessage: opts.armoredSignature,
		});
		const result = await openpgp.verify({
			message: cleartext,
			verificationKeys,
		});
		return await buildVerifyResult(result, verificationKeys);
	} catch {
		// Not a cleartext message - try as a regular signed message.
	}

	const message = await openpgp.readMessage({ armoredMessage: opts.armoredSignature });
	const result = await openpgp.verify({
		message,
		verificationKeys,
	});
	return await buildVerifyResult(result, verificationKeys);
}

async function buildVerifyResult(
	result: {
		signatures: {
			keyID: openpgp.KeyID;
			verified: Promise<true>;
			signature: Promise<openpgp.Signature>;
		}[];
	},
	verificationKeys: openpgp.PublicKey[],
): Promise<VerifyResult> {
	const fpByKeyID = new Map<string, string>();
	const infoByKeyID = new Map<
		string,
		{ name?: string; email?: string; comment?: string; userID?: string; allUserIDs?: string[] }
	>();
	for (const k of verificationKeys) {
		try {
			const fp = k.getFingerprint().toUpperCase();
			fpByKeyID.set(keyIDToHex(k.getKeyID()), fp);
			// Extract user IDs from the verification key so we can surface the
			// signer's name + email even when the signature was made with a
			// subkey whose key ID doesn't directly resolve to a Keybase username.
			const allUserIDs = k.getUserIDs();
			let primary: { name?: string; email?: string; comment?: string; userID?: string } = {};
			try {
				const p = await k.getPrimaryUser();
				if (p?.user?.userID) {
					const { parseUserID } = await import("@/lib/pgp/signer-info");
					primary = {
						...parseUserID(p.user.userID.userID ?? ""),
						userID: p.user.userID.userID,
					};
				}
			} catch {
				// getPrimaryUser throws on revoked / no self-cert; fall back to first UID.
				if (allUserIDs.length > 0) {
					const { parseUserID } = await import("@/lib/pgp/signer-info");
					primary = {
						...parseUserID(allUserIDs[0]),
						userID: allUserIDs[0],
					};
				}
			}
			infoByKeyID.set(keyIDToHex(k.getKeyID()), {
				...primary,
				allUserIDs,
			});
		} catch {
			// ignore
		}
	}

	const signatures = await Promise.all(
		(result.signatures || []).map(async (sig) => {
			const keyID = keyIDToHex(sig.keyID);
			const fingerprint = fpByKeyID.get(keyID);
			const info = infoByKeyID.get(keyID);

			// Read the high-precision timestamp notation from the signature, if present.
			let timestampIso: string | undefined;
			try {
				const sigObj = await sig.signature;
				const packet = sigObj?.packets?.[0];
				if (packet?.rawNotations) {
					const { readTimestampNotation } = await import("@/lib/pgp/signer-info");
					timestampIso = readTimestampNotation(
						packet.rawNotations as unknown as Array<{
							name: string;
							value: Uint8Array;
							humanReadable: boolean;
							critical: boolean;
						}>,
					);
				}
			} catch {
				// ignore — timestamp is best-effort
			}

			let verified: "valid" | "invalid" | "unknown" = "unknown";
			let error: string | undefined;
			try {
				await sig.verified;
				verified = "valid";
			} catch (e) {
				const msg = (e as Error).message || "";
				if (/not present|could not verify|no key/i.test(msg)) {
					verified = "unknown";
				} else {
					verified = "invalid";
				}
				error = msg;
			}
			return {
				keyID,
				fingerprint,
				verified,
				error,
				name: info?.name,
				email: info?.email,
				comment: info?.comment,
				userID: info?.userID,
				allUserIDs: info?.allUserIDs,
				timestampIso,
			};
		}),
	);

	const overall = signatures.find((s) => s.verified === "valid")
		? "valid"
		: signatures.find((s) => s.verified === "invalid")
			? "invalid"
			: "unknown";

	return { verified: overall, signatures };
}

/** Quick validity check on an armored key. Returns a friendly message. */
export async function validateArmoredKey(armored: string): Promise<{
	ok: boolean;
	error?: string;
	info?: AnyKeyInfo;
}> {
	try {
		const key = await readKey(armored);
		if (key.isPrivate()) {
			const info = await describePrivateKey(armored);
			return { ok: true, info };
		}
		const info = await describePublicKey(armored);
		return { ok: true, info };
	} catch (e) {
		return { ok: false, error: (e as Error).message };
	}
}

/** Format a fingerprint with spaces every 4 hex chars for readability. */
export function formatFingerprint(fp: string): string {
	return fp.replace(/(.{4})/g, "$1 ").trim();
}

/** Format a Date for display, or "never" / "unknown" for falsy values. */
export function formatKeyDate(d: Date | null | undefined): string {
	if (!d) return "never";
	return d.toLocaleString();
}

/** Detect the type of an armored PGP block from its headers. */
export type ArmoredFormat =
	| "cleartext-signed" // -----BEGIN PGP SIGNED MESSAGE-----
	| "detached-signature" // -----BEGIN PGP SIGNATURE-----
	| "encrypted-message" // -----BEGIN PGP MESSAGE-----  (could be encrypted+signed)
	| "public-key" // -----BEGIN PGP PUBLIC KEY BLOCK-----
	| "private-key" // -----BEGIN PGP PRIVATE KEY BLOCK-----
	| "unknown";

export function detectArmoredFormat(armored: string): ArmoredFormat {
	const t = armored.trim();
	if (t.startsWith("-----BEGIN PGP SIGNED MESSAGE-----")) return "cleartext-signed";
	if (t.startsWith("-----BEGIN PGP SIGNATURE-----")) return "detached-signature";
	if (t.startsWith("-----BEGIN PGP MESSAGE-----")) return "encrypted-message";
	if (t.startsWith("-----BEGIN PGP PUBLIC KEY BLOCK-----")) return "public-key";
	if (t.startsWith("-----BEGIN PGP PRIVATE KEY BLOCK-----")) return "private-key";
	return "unknown";
}

/* --------------------------- Message metadata (R9) ------------------------- */

/**
 * Inputs longer than this are skipped by describeEncryptedMessage. The
 * helper is called per keystroke from the Decrypt tab (no debounce, no
 * effect), so parsing is bounded: past this size the armor is likely a
 * huge batch job rather than an interactive paste, and the metadata strip
 * silently shows nothing (same as "not an encrypted message").
 */
export const MAX_ENCRYPTED_MESSAGE_META_CHARS = 200_000;

/** Human-friendly labels for the public-key algorithms a PKESK packet can
 *  reference (openpgp.enums.publicKey numeric values). Kept consistent with
 *  the humanized names used in the key-details panel (key-details.ts):
 *  e.g. "rsaEncryptSign" → "RSA", "eddsaLegacy" → "EdDSA (legacy)". Values
 *  missing from this map fall back to openpgp.enums.read, then to the raw
 *  number — display-only, never fed back into crypto. */
const PKESK_ALGORITHM_LABELS: ReadonlyMap<number, string> = new Map<number, string>([
	[openpgp.enums.publicKey.rsaEncryptSign, "RSA"],
	[openpgp.enums.publicKey.rsaEncrypt, "RSA"],
	[openpgp.enums.publicKey.rsaSign, "RSA"],
	[openpgp.enums.publicKey.elgamal, "ElGamal"],
	[openpgp.enums.publicKey.dsa, "DSA"],
	[openpgp.enums.publicKey.ecdh, "ECDH"],
	[openpgp.enums.publicKey.ecdsa, "ECDSA"],
	[openpgp.enums.publicKey.eddsaLegacy, "EdDSA (legacy)"],
	[openpgp.enums.publicKey.x25519, "X25519"],
	[openpgp.enums.publicKey.x448, "X448"],
	[openpgp.enums.publicKey.ed25519, "Ed25519"],
	[openpgp.enums.publicKey.ed448, "Ed448"],
	[openpgp.enums.publicKey.aedh, "AEDH"],
	[openpgp.enums.publicKey.aedsa, "AEDSA"],
]);

function describePkeskAlgorithm(value: number): string {
	const label = PKESK_ALGORITHM_LABELS.get(value);
	if (label) return label;
	try {
		return openpgp.enums.read(openpgp.enums.publicKey, value);
	} catch {
		return String(value);
	}
}

export interface EncryptedMessageMeta {
	/** How many PKESK (public-key encrypted session key) packets the message
	 *  carries — i.e. how many recipient keys it is encrypted to. */
	recipientKeyCount: number;
	/** Unique humanized public-key algorithm names across those packets, in
	 *  first-appearance order (e.g. ["ECDH"] or ["ECDH", "RSA"]). */
	publicKeyAlgorithms: string[];
	/** Recipient key IDs from the PKESK packet headers (uppercase hex) —
	 *  typically SUBKEY ids, since the encryption-capable key of a modern
	 *  key pair is its ECDH/RSA subkey. Callers match these against the full
	 *  id list of their own key (listPrivateKeyIds) to detect "encrypted to
	 *  me" BEFORE any passphrase is requested. */
	recipientKeyIDs: string[];
}

/**
 * Describe an armored encrypted message WITHOUT decrypting it (no key, no
 * passphrase, no secret material — only the packet headers are parsed).
 *
 * Returns null (never throws) whenever the metadata cannot be determined:
 * not an encrypted message, malformed armor, no PKESK packets (e.g. a
 * cleartext-signed block, which openpgp v6's readMessage happens to parse
 * instead of rejecting — count 0 → null), or input over the
 * MAX_ENCRYPTED_MESSAGE_META_CHARS size threshold.
 *
 * NOTE (verified against openpgp 6.3.1 at runtime): the PKESK packet's
 * public-key algorithm lives on `.publicKeyAlgorithm` (a numeric
 * enums.publicKey value); `.algorithm` is undefined on these packets.
 */
export async function describeEncryptedMessage(
	armored: string,
): Promise<EncryptedMessageMeta | null> {
	if (armored.length > MAX_ENCRYPTED_MESSAGE_META_CHARS) return null;
	try {
		const msg = await openpgp.readMessage({ armoredMessage: armored });
		const pkesks = msg.packets.filterByTag(openpgp.enums.packet.publicKeyEncryptedSessionKey);
		if (pkesks.length === 0) return null;
		const publicKeyAlgorithms: string[] = [];
		const recipientKeyIDs: string[] = [];
		for (const pkesk of pkesks) {
			const raw = (pkesk as { publicKeyAlgorithm?: unknown }).publicKeyAlgorithm;
			if (typeof raw === "number" && Number.isFinite(raw)) {
				const label = describePkeskAlgorithm(raw);
				if (!publicKeyAlgorithms.includes(label)) publicKeyAlgorithms.push(label);
			}
			// Recipient key ID (uppercase hex). openpgp 6.3.1 exposes it as
			// `publicKeyID` (a KeyID with .toHex()); guarded so a future shape
			// change degrades to an empty list instead of throwing.
			const id = (pkesk as { publicKeyID?: { toHex?: () => string } }).publicKeyID;
			if (typeof id?.toHex === "function") {
				const hex = id.toHex().toUpperCase();
				if (!recipientKeyIDs.includes(hex)) recipientKeyIDs.push(hex);
			}
		}
		return { recipientKeyCount: pkesks.length, publicKeyAlgorithms, recipientKeyIDs };
	} catch {
		// Not an encrypted message / malformed — metadata is best-effort only.
		return null;
	}
}

/**
 * List every key ID (primary + subkeys, uppercase hex) of an armored PRIVATE
 * key. Reads the key WITHOUT decrypting it — no passphrase, no secret
 * material touches the result. Used by the Decrypt tab to detect "this
 * message was encrypted to one of my keys" from the PKESK headers alone
 * (the PKESK carries the encryption SUBKEY's id, so the primary id alone is
 * not enough to match).
 *
 * Returns null (never throws) when the armored input cannot be parsed.
 */
export async function listPrivateKeyIds(armored: string): Promise<string[] | null> {
	try {
		const key = await readKey(armored);
		const ids = key
			.getKeys()
			.map((k) => k.getKeyID().toHex().toUpperCase())
			.filter((hex) => /^[0-9A-F]{16}$/.test(hex));
		return [...new Set(ids)];
	} catch {
		return null;
	}
}

/**
 * Verify any armored PGP block by auto-detecting its format.
 *
 * - Cleartext-signed: verify directly with the public keys.
 * - Detached signature: needs the original plaintext (opts.plaintext).
 * - Encrypted message: this won't be a signature-only flow; the caller should
 *   use decryptAndAutoVerify instead. We still try to extract signatures if
 *   the message is signed-then-encrypted (requires decryption first).
 */
export async function verifyAutoDetect(
	armored: string,
	publicKeys: Armored[],
	plaintext?: string,
): Promise<VerifyResult> {
	const format = detectArmoredFormat(armored);
	if (format === "cleartext-signed") {
		return verifyMessage({
			armoredSignature: armored,
			publicKeys,
			detached: false,
		});
	}
	if (format === "detached-signature") {
		if (!plaintext) {
			throw new Error(
				"A detached signature was detected. Please paste the original plaintext too.",
			);
		}
		return verifyMessage({
			armoredSignature: armored,
			publicKeys,
			plaintext,
			detached: true,
		});
	}
	if (format === "encrypted-message") {
		throw new Error(
			"This looks like an encrypted message. Use the Decrypt tab to decrypt and verify it (the signature is checked automatically).",
		);
	}
	if (format === "public-key" || format === "private-key") {
		throw new Error(
			"This looks like a key block, not a signature. Switch to the appropriate tab to load or use keys.",
		);
	}
	throw new Error(
		"Could not detect the format of the pasted block. Make sure it is an ASCII-armored PGP signature or cleartext-signed message.",
	);
}

/**
 * Verify any armored PGP block by auto-detecting its format AND auto-fetching
 * the signers' public keys by key ID via the provided lookup callback.
 *
 * - Cleartext-signed: extract signature key IDs, fetch keys, verify.
 * - Detached signature: needs the original plaintext (opts.plaintext).
 * - Encrypted message: redirect to decrypt flow.
 */
export async function verifyAutoDetectWithKeyFetch(
	armored: string,
	plaintext: string | undefined,
	fetchKeysByKeyID: (keyIDs: string[]) => Promise<
		Array<{
			armored: string;
			keyID: string;
			fingerprint: string;
			username?: string;
			allKeyIDs?: string[];
			/** True when the record came from the caller's own configured key. */
			self?: boolean;
			/** Expiration of the record's key as epoch-ms, when known (R9: only
			 *  locally-resolved records carry it). */
			expiresAt?: number | null;
			/** Which source resolved this key (local / Keybase / openpgp.org). */
			resolvedFrom?: "local" | "keybase" | "openpgp.org";
		}>
	>,
): Promise<{
	verified: "valid" | "invalid" | "unknown";
	signatures: Array<{
		keyID: string;
		fingerprint?: string;
		username?: string;
		verified: "valid" | "invalid" | "unknown";
		error?: string;
		name?: string;
		email?: string;
		comment?: string;
		userID?: string;
		allUserIDs?: string[];
		timestampIso?: string;
		/** True when the signer is the user's own locally-configured key. */
		self?: boolean;
		/** Expiration of the signer's key as epoch-ms, when known. */
		expiresAt?: number | null;
		/** Where the verification key came from. */
		resolvedFrom?: "local" | "keybase" | "openpgp.org";
	}>;
}> {
	const format = detectArmoredFormat(armored);

	if (format === "encrypted-message") {
		throw new Error(
			"This looks like an encrypted message. Use the Decrypt tab to decrypt and verify it (the signature is checked automatically).",
		);
	}
	if (format === "public-key" || format === "private-key") {
		throw new Error(
			"This looks like a key block, not a signature. Switch to the appropriate tab to load or use keys.",
		);
	}
	if (format === "unknown") {
		throw new Error(
			"Could not detect the format of the pasted block. Make sure it is an ASCII-armored PGP signature or cleartext-signed message.",
		);
	}

	if (format === "detached-signature" && !plaintext) {
		throw new Error("A detached signature was detected. Please paste the original plaintext too.");
	}

	// First pass: parse + extract signature key IDs without verification.
	let initialResult: {
		signatures: {
			keyID: openpgp.KeyID;
			verified: Promise<true>;
			signature: Promise<openpgp.Signature>;
		}[];
	};
	if (format === "detached-signature") {
		const message = await openpgp.createMessage({ text: plaintext as string });
		const signature = await openpgp.readSignature({ armoredSignature: armored });
		// openpgp.verify requires at least one verification key. Use an empty key
		// set to discover the signature's key IDs without verifying yet.
		try {
			const r = await openpgp.verify({
				message,
				signature,
				verificationKeys: [],
			});
			initialResult = r;
		} catch {
			// If verification throws because no keys were provided, we still have
			// the signature's keyID from the parsed signature object.
			initialResult = {
				signatures: [
					{
						keyID: signature.packets[0]?.issuerKeyID as openpgp.KeyID,
						verified: Promise.reject(new Error("no key")),
						signature: Promise.resolve(signature),
					},
				],
			};
		}
	} else {
		// Cleartext-signed message
		const cleartext = await openpgp.readCleartextMessage({
			cleartextMessage: armored,
		});
		try {
			const r = await openpgp.verify({
				message: cleartext,
				verificationKeys: [],
			});
			initialResult = r;
		} catch {
			// If verification throws because no keys were provided, fall back to
			// extracting signature key IDs from the cleartext message's signature
			// packets directly.
			const sigs =
				(
					cleartext as unknown as {
						signatures?: Array<{ keyID: openpgp.KeyID; signature: Promise<openpgp.Signature> }>;
					}
				).signatures ?? [];
			initialResult = {
				signatures: sigs.map((s) => ({
					keyID: s.keyID,
					verified: Promise.reject(new Error("no key")),
					signature: s.signature,
				})),
			};
		}
	}

	const initialSigs = initialResult.signatures ?? [];
	if (initialSigs.length === 0) {
		return { verified: "unknown", signatures: [] };
	}

	// Collect unique key IDs and fetch the corresponding public keys.
	const keyIDs = Array.from(new Set(initialSigs.map((s) => keyIDToHex(s.keyID)).filter(Boolean)));
	const fetched = keyIDs.length > 0 ? await fetchKeysByKeyID(keyIDs) : [];

	if (fetched.length === 0) {
		// No keys could be fetched — return unknown signatures with key IDs only.
		return {
			verified: "unknown",
			signatures: initialSigs.map((s) => ({
				keyID: keyIDToHex(s.keyID),
				verified: "unknown" as const,
			})),
		};
	}

	// Second pass: verify with the fetched keys.
	const verificationKeys: openpgp.PublicKey[] = [];
	for (const f of fetched) {
		try {
			verificationKeys.push(await readKey(f.armored));
		} catch {
			// skip invalid keys
		}
	}

	// Build a lookup of parsed PublicKey objects by key ID so we can surface
	// the signer's name + email from the key's user IDs.
	const infoByKeyID = new Map<
		string,
		{ name?: string; email?: string; comment?: string; userID?: string; allUserIDs?: string[] }
	>();
	for (const k of verificationKeys) {
		try {
			const allUserIDs = k.getUserIDs();
			let primary: { name?: string; email?: string; comment?: string; userID?: string } = {};
			try {
				const p = await k.getPrimaryUser();
				if (p?.user?.userID) {
					const { parseUserID } = await import("@/lib/pgp/signer-info");
					primary = {
						...parseUserID(p.user.userID.userID ?? ""),
						userID: p.user.userID.userID,
					};
				}
			} catch {
				if (allUserIDs.length > 0) {
					const { parseUserID } = await import("@/lib/pgp/signer-info");
					primary = {
						...parseUserID(allUserIDs[0]),
						userID: allUserIDs[0],
					};
				}
			}
			for (const kid of k.getKeyIDs()) {
				infoByKeyID.set(keyIDToHex(kid), { ...primary, allUserIDs });
			}
		} catch {
			// ignore
		}
	}

	let verifiedResult: {
		signatures: {
			keyID: openpgp.KeyID;
			verified: Promise<true>;
			signature: Promise<openpgp.Signature>;
		}[];
	};
	if (format === "detached-signature") {
		const message = await openpgp.createMessage({ text: plaintext as string });
		const signature = await openpgp.readSignature({ armoredSignature: armored });
		verifiedResult = await openpgp.verify({
			message,
			signature,
			verificationKeys,
		});
	} else {
		const cleartext = await openpgp.readCleartextMessage({
			cleartextMessage: armored,
		});
		verifiedResult = await openpgp.verify({
			message: cleartext,
			verificationKeys,
		});
	}

	const finalSigs = await Promise.all(
		(verifiedResult.signatures ?? []).map(async (sig) => {
			const keyID = keyIDToHex(sig.keyID);
			let verifiedStatus: "valid" | "invalid" | "unknown" = "unknown";
			let error: string | undefined;
			try {
				await sig.verified;
				verifiedStatus = "valid";
			} catch (e) {
				const msg = (e as Error).message || "";
				if (/not present|could not verify|no key/i.test(msg)) {
					verifiedStatus = "unknown";
				} else {
					verifiedStatus = "invalid";
				}
				error = msg;
			}
			const match = fetched.find((f) => f.allKeyIDs?.includes(keyID.toUpperCase()));
			const info = infoByKeyID.get(keyID);

			// Read the high-precision timestamp notation from the signature, if present.
			let timestampIso: string | undefined;
			try {
				const sigObj = await sig.signature;
				const packet = sigObj?.packets?.[0];
				if (packet?.rawNotations) {
					const { readTimestampNotation } = await import("@/lib/pgp/signer-info");
					timestampIso = readTimestampNotation(
						packet.rawNotations as unknown as Array<{
							name: string;
							value: Uint8Array;
							humanReadable: boolean;
							critical: boolean;
						}>,
					);
				}
			} catch {
				// ignore — timestamp is best-effort
			}

			return {
				keyID,
				fingerprint: match?.fingerprint,
				username: match?.username,
				self: match?.self,
				expiresAt: match?.expiresAt,
				resolvedFrom: match?.resolvedFrom,
				verified: verifiedStatus,
				error,
				name: info?.name,
				email: info?.email,
				comment: info?.comment,
				userID: info?.userID,
				allUserIDs: info?.allUserIDs,
				timestampIso,
			};
		}),
	);

	const overall = finalSigs.find((s) => s.verified === "valid")
		? "valid"
		: finalSigs.find((s) => s.verified === "invalid")
			? "invalid"
			: "unknown";

	return { verified: overall, signatures: finalSigs };
}

export { formatDate };
