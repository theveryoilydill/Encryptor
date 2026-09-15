/**
 * Quantum-sealed copies — an ML-KEM-768 (FIPS 203) outer layer for the
 * sender's own archive copy.
 *
 * # Mr. AI Acting on s183173's Behalf
 *
 * WHY
 *   OpenPGP public-key encryption rests on classical assumptions (X25519 /
 *   RSA). A "harvest now, decrypt later" attacker who records today's
 *   ciphertexts can decrypt them once a large quantum computer exists. The
 *   IETF OpenPGP PQ draft's answer is a HYBRID: classical + ML-KEM carried
 *   together. openpgp.js does not implement that draft yet, so this module
 *   adds the recommended mix as a SECOND, independent layer for the copy the
 *   sender keeps:
 *
 *     sealed = AES-256-GCM(classical armor, K)
 *     K      = HKDF-SHA256( ML-KEM-768.encapsulate(pqPublicKey) )
 *
 *   Unsealing needs BOTH the ML-KEM secret key AND the app passphrase (the
 *   secret key is stored in the config encrypted under a passphrase-derived
 *   AES-GCM key). The classical PGP message stays untouched for recipients —
 *   this layer only hardens the sender's own copy against the quantum
 *   adversary.
 *
 * STORAGE
 *   The ML-KEM keypair is generated in-app. The secret key never touches
 *   disk in the clear:
 *     wrapped = AES-256-GCM(PBKDF2-SHA256(passphrase, salt), secretKey)
 *   and the config carries { pk, wrappedSk, salt, nonce } as base64.
 *   For keys created WITHOUT a passphrase there is no key material to run
 *   PBKDF2 over (WebCrypto rejects zero-length input), so the secret half
 *   is instead wrapped under a random 32-byte DEVICE key stored in the
 *   clear in the config (deviceKey) — no new exposure, since the classical
 *   private key already sits in the clear in the very same config.
 *
 * All primitives: @noble/post-quantum (ml_kem768) + WebCrypto.
 */
import { ml_kem768 } from "@noble/post-quantum/ml-kem.js";

const PBKDF2_ITERATIONS = 310_000;
const HKDF_INFO = "encryptor-pq-seal-v1";
/** Armor markers (deliberately NOT "PGP" — this is an Encryptor-side layer,
 *  not part of the OpenPGP message; GnuPG must never try to parse it). */
export const PQ_ARMOR_BEGIN = "-----BEGIN ENCRYPTOR QUANTUM-SEALED-----";
export const PQ_ARMOR_END = "-----END ENCRYPTOR QUANTUM-SEALED-----";

/** The quantum-seal key material attached to a key config. */
export interface QuantumSealConfig {
	/** ML-KEM-768 public key (base64, 1184 bytes raw). */
	pk: string;
	/** ML-KEM-768 secret key encrypted with the passphrase-derived key
	 *  (base64; 2400 + 16 bytes raw). */
	wrappedSk: string;
	/** PBKDF2 salt (base64, 16 bytes raw). */
	salt: string;
	/** AES-GCM nonce for wrappedSk (base64, 12 bytes raw). */
	nonce: string;
	/** Random 32-byte device key (base64) for PASSPHRASE-LESS keys: the
	 *  ML-KEM secret is wrapped under THIS key (AES-GCM, `nonce` above)
	 *  instead of a passphrase-derived one. WebCrypto PBKDF2 rejects
	 *  zero-length key material, so a passphrase path cannot exist for
	 *  these keys — and storing the wrapping key adds no new exposure,
	 *  because the classical private key is already stored in the clear
	 *  in the same config. Absent for passphrase-wrapped keys. */
	deviceKey?: string;
}

/** b64 helpers (std alphabet, padding — matches btoa/atob usage elsewhere). */
function toB64(bytes: Uint8Array): string {
	let bin = "";
	for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
	return btoa(bin);
}

function fromB64(b64: string): Uint8Array {
	const bin = atob(b64);
	const out = new Uint8Array(bin.length);
	for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
	return out;
}

function assertCrypto(): SubtleCrypto {
	const c = globalThis.crypto;
	if (!c?.subtle) throw new Error("WebCrypto is unavailable in this browser.");
	return c.subtle;
}

/* ------------------------------ key material ------------------------------ */

/** Generate a fresh ML-KEM-768 keypair. Callers MUST wrap the returned secret
 *  key (wrapSealSecretAuto) before persisting anything. */
export function generateSealKeyPair(): { publicKey: Uint8Array; secretKey: Uint8Array } {
	return ml_kem768.keygen();
}

/** Derive the AES-GCM wrapping key from the passphrase + salt. */
async function deriveWrapKey(passphrase: string, salt: Uint8Array): Promise<CryptoKey> {
	const subtle = assertCrypto();
	const base = await subtle.importKey(
		"raw",
		new TextEncoder().encode(passphrase) as unknown as ArrayBuffer,
		"PBKDF2",
		false,
		["deriveKey"],
	);
	return subtle.deriveKey(
		{
			name: "PBKDF2",
			salt: salt as unknown as ArrayBuffer,
			iterations: PBKDF2_ITERATIONS,
			hash: "SHA-256",
		},
		base,
		{ name: "AES-GCM", length: 256 },
		false,
		["encrypt", "decrypt"],
	);
}

/** Wrap (encrypt) the raw ML-KEM secret key under the passphrase. Returns the
 *  persistable QuantumSealConfig fields. */
export async function wrapSealSecret(
	publicKey: Uint8Array,
	secretKey: Uint8Array,
	passphrase: string,
): Promise<QuantumSealConfig> {
	const subtle = assertCrypto();
	const salt = crypto.getRandomValues(new Uint8Array(16));
	const nonce = crypto.getRandomValues(new Uint8Array(12));
	const key = await deriveWrapKey(passphrase, salt);
	const wrapped = await subtle.encrypt(
		{ name: "AES-GCM", iv: nonce as unknown as ArrayBuffer },
		key,
		secretKey as unknown as ArrayBuffer,
	);
	return {
		pk: toB64(publicKey),
		wrappedSk: toB64(new Uint8Array(wrapped)),
		salt: toB64(salt),
		nonce: toB64(nonce),
	};
}

/** Unwrap the ML-KEM secret key with the passphrase. Throws when the
 *  passphrase is wrong or the record is corrupted. */
export async function unwrapSealSecret(
	seal: QuantumSealConfig,
	passphrase: string,
): Promise<Uint8Array> {
	const subtle = assertCrypto();
	const key = await deriveWrapKey(passphrase, fromB64(seal.salt));
	const plain = await subtle.decrypt(
		{ name: "AES-GCM", iv: fromB64(seal.nonce) as unknown as ArrayBuffer },
		key,
		fromB64(seal.wrappedSk) as unknown as ArrayBuffer,
	);
	return new Uint8Array(plain);
}

// # Mr. AI Acting on s183173's Behalf
/** Wrap (encrypt) the raw ML-KEM secret key, choosing the wrapping scheme
 *  from the passphrase:
 *   - non-empty passphrase → the classic PBKDF2 wrap (identical to
 *     `wrapSealSecret`, which stays exported for back-compat);
 *   - EMPTY passphrase → wrap under a random 32-byte device key stored in
 *     the clear in the config (`deviceKey`). WebCrypto PBKDF2 rejects
 *     zero-length key material, so the old code THREW here and a
 *     passphrase-less key silently lost its PQ layer at keygen. The device
 *     key adds no new exposure: the classical private key is already
 *     stored in the clear in the same config. The `salt` field still
 *     carries a fresh random salt for forward-compat; the PBKDF2 path is
 *     simply not used for these keys. */
export async function wrapSealSecretAuto(
	publicKey: Uint8Array,
	secretKey: Uint8Array,
	passphrase: string,
): Promise<QuantumSealConfig> {
	if (passphrase.length > 0) {
		return wrapSealSecret(publicKey, secretKey, passphrase);
	}
	const subtle = assertCrypto();
	const deviceKey = crypto.getRandomValues(new Uint8Array(32));
	const nonce = crypto.getRandomValues(new Uint8Array(12));
	const key = await subtle.importKey(
		"raw",
		deviceKey as unknown as ArrayBuffer,
		{ name: "AES-GCM" },
		false,
		["encrypt"],
	);
	const wrapped = await subtle.encrypt(
		{ name: "AES-GCM", iv: nonce as unknown as ArrayBuffer },
		key,
		secretKey as unknown as ArrayBuffer,
	);
	return {
		pk: toB64(publicKey),
		wrappedSk: toB64(new Uint8Array(wrapped)),
		salt: toB64(crypto.getRandomValues(new Uint8Array(16))),
		nonce: toB64(nonce),
		deviceKey: toB64(deviceKey),
	};
}

// # Mr. AI Acting on s183173's Behalf
/** Unwrap the ML-KEM secret key, opening whichever wrapping the config
 *  carries: the stored device key when present (passphrase-less keys — the
 *  passphrase is ignored entirely, so there is no "needs your passphrase"
 *  dead-end), otherwise the PBKDF2 passphrase wrap. Throws with a clear
 *  message when the record cannot be opened. */
export async function unwrapSealSecretAuto(
	seal: QuantumSealConfig,
	passphrase: string | null | undefined,
): Promise<Uint8Array> {
	const subtle = assertCrypto();
	if (seal.deviceKey) {
		const key = await subtle.importKey(
			"raw",
			fromB64(seal.deviceKey) as unknown as ArrayBuffer,
			{ name: "AES-GCM" },
			false,
			["decrypt"],
		);
		try {
			const plain = await subtle.decrypt(
				{ name: "AES-GCM", iv: fromB64(seal.nonce) as unknown as ArrayBuffer },
				key,
				fromB64(seal.wrappedSk) as unknown as ArrayBuffer,
			);
			return new Uint8Array(plain);
		} catch {
			throw new Error(
				"Couldn't open the quantum-seal secret with this device's key — the key config looks corrupted or was re-wrapped elsewhere.",
			);
		}
	}
	if (!passphrase) {
		throw new Error(
			"The quantum-sealed layer needs your passphrase (the one that protects this key), not just the key — enter it in the prompt and try again.",
		);
	}
	return unwrapSealSecret(seal, passphrase);
}

/* --------------------------------- seal ----------------------------------- */

/** HKDF-SHA256 over the ML-KEM shared secret → 256-bit AES key. */
async function aesKeyFromShared(shared: Uint8Array): Promise<CryptoKey> {
	const subtle = assertCrypto();
	const ikm = await subtle.importKey("raw", shared as unknown as ArrayBuffer, "HKDF", false, [
		"deriveKey",
	]);
	return subtle.deriveKey(
		{
			name: "HKDF",
			hash: "SHA-256",
			salt: new Uint8Array(0) as unknown as ArrayBuffer,
			info: new TextEncoder().encode(HKDF_INFO) as unknown as ArrayBuffer,
		},
		ikm,
		{ name: "AES-GCM", length: 256 },
		false,
		["encrypt", "decrypt"],
	);
}

export interface SealedPayload {
	v: 1;
	/** ML-KEM-768 ciphertext (base64). */
	ct: string;
	/** AES-GCM nonce for the body (base64). */
	n: string;
	/** AES-GCM ciphertext of the classical armor (base64). */
	body: string;
	/** Fingerprint of the owning key (uppercased hex, display only). */
	to?: string;
}

/** Seal a classical armored message for the given PQ public key. */
export async function sealForPublicKey(
	armored: string,
	pqPublicKey: Uint8Array,
	to?: string,
): Promise<string> {
	const subtle = assertCrypto();
	const { cipherText, sharedSecret } = ml_kem768.encapsulate(pqPublicKey);
	const key = await aesKeyFromShared(sharedSecret);
	const nonce = crypto.getRandomValues(new Uint8Array(12));
	const body = await subtle.encrypt(
		{ name: "AES-GCM", iv: nonce as unknown as ArrayBuffer },
		key,
		new TextEncoder().encode(armored) as unknown as ArrayBuffer,
	);
	const payload: SealedPayload = {
		v: 1,
		ct: toB64(cipherText),
		n: toB64(nonce),
		body: toB64(new Uint8Array(body)),
		...(to ? { to: to.toUpperCase() } : {}),
	};
	const json = JSON.stringify(payload);
	// Split the base64 JSON at 68 columns, like armor.
	const b64 = toB64(new TextEncoder().encode(json));
	const lines = (b64.match(/.{1,68}/g) ?? []).join("\n");
	return `${PQ_ARMOR_BEGIN}\nVersion: Encryptor PQ-1 (ML-KEM-768 + AES-256-GCM)\n\n${lines}\n${PQ_ARMOR_END}`;
}

/** Convenience for the Encrypt tab: seal using the QuantumSealConfig stored
 *  on the key config (public half only — no passphrase involved). */
export async function sealForConfig(
	armored: string,
	seal: QuantumSealConfig,
	to?: string,
): Promise<string> {
	return sealForPublicKey(armored, fromB64(seal.pk), to);
}

export function isQuantumSealed(text: string): boolean {
	return text.includes(PQ_ARMOR_BEGIN);
}

/** Parse + base64-decode a sealed armor block back into its payload. */
export function parseSealedArmor(text: string): SealedPayload {
	const start = text.indexOf(PQ_ARMOR_BEGIN);
	const end = text.indexOf(PQ_ARMOR_END);
	if (start < 0 || end < 0 || end <= start) {
		throw new Error("This quantum-sealed block is malformed (missing armor markers).");
	}
	const inner = text.slice(start + PQ_ARMOR_BEGIN.length, end);
	const b64 = inner
		.split("\n")
		.map((l) => l.trim())
		// Skip armor header lines AND an RFC-style CRC24 checksum line
		// ("=XXXX") — our own writer omits it, but a repaired or external
		// block may carry one; feeding "=" into atob would throw.
		.filter((l) => l && !l.includes(":") && !l.startsWith("="))
		.join("");
	let json: string;
	try {
		json = new TextDecoder().decode(fromB64(b64));
	} catch {
		throw new Error("This quantum-sealed block is malformed (bad base64).");
	}
	const payload = JSON.parse(json) as SealedPayload;
	if (payload.v !== 1 || !payload.ct || !payload.n || !payload.body) {
		throw new Error("This quantum-sealed block uses an unknown format.");
	}
	return payload;
}

/* -------------------------------- unseal ---------------------------------- */

/** Unseal a sealed payload back to the classical armored message.
 *  `secretKey` is the RAW ML-KEM secret (use unwrapSealSecret first). */
export async function unsealWithSecretKey(
	payload: SealedPayload,
	secretKey: Uint8Array,
): Promise<string> {
	const subtle = assertCrypto();
	const sharedSecret = ml_kem768.decapsulate(fromB64(payload.ct), secretKey);
	const key = await aesKeyFromShared(sharedSecret);
	const plain = await subtle.decrypt(
		{ name: "AES-GCM", iv: fromB64(payload.n) as unknown as ArrayBuffer },
		key,
		fromB64(payload.body) as unknown as ArrayBuffer,
	);
	const armored = new TextDecoder().decode(plain);
	if (!armored.includes("-----BEGIN PGP MESSAGE-----")) {
		throw new Error("The unsealed copy does not contain a PGP message.");
	}
	return armored;
}
