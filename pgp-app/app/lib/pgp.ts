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
  signerPrivateKey: Armored;
  signerPassphrase?: string;
  /** Sign as a separate detached signature file (false = inline signature in the encrypted message). */
  detached?: boolean;
}

export interface DecryptAndVerifyOptions {
  armoredMessage: string;
  decryptionPrivateKey: Armored;
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
  }[];
}

export interface SignOptions {
  plaintext: string;
  privateKey: Armored;
  passphrase?: string;
  /** Detached = separate signature block; inline = cleartext signed message. */
  detached?: boolean;
}

export interface VerifyOptions {
  /** The original plaintext. */
  plaintext: string;
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
  }[];
}

function keyIDToHex(keyID: openpgp.KeyID | undefined): string {
  if (!keyID) return "";
  return keyID.toHex().toUpperCase();
}

function fpToHex(fp: Uint8Array | string | null | undefined): string {
  if (!fp) return "";
  if (typeof fp === "string") return fp.toUpperCase();
  // Convert Uint8Array to hex
  return Array.from(fp)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("")
    .toUpperCase();
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
      throw new Error(
        "This private key is passphrase-protected. Please provide the passphrase.",
      );
    }
    try {
      return await openpgp.decryptKey({ privateKey: key, passphrase });
    } catch (e) {
      throw new Error(`Failed to unlock private key: ${(e as Error).message}`);
    }
  }
  return key;
}

export async function describePublicKey(armored: Armored): Promise<PublicKeyInfo> {
  const key = await readKey(armored);
  const primary = key.getAlgorithmInfo();
  const fp = key.getFingerprint().toUpperCase();
  const subkeyFPs = key
    .getSubkeys()
    .map((s) => s.getFingerprint().toUpperCase());

  // Try to find the most relevant encryption-capable subkey's expiration
  let expirationTime: Date | null = null;
  try {
    const exp = await key.getExpirationTime();
    if (exp instanceof Date) {
      expirationTime = exp;
    } else if (Array.isArray(exp)) {
      // openpgp can return arrays of Dates or numbers for multi-key cases.
      const first = exp[0];
      if (first instanceof Date) expirationTime = first;
      else if (typeof first === "number" && first > 0)
        expirationTime = new Date(first);
    } else if (typeof exp === "number" && exp > 0) {
      expirationTime = new Date(exp);
    }
  } catch {
    expirationTime = null;
  }

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
    // include subkey fingerprints for debugging/visibility (not part of type but useful)
    ...({ subkeyFingerprints: subkeyFPs } as object),
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

export async function generateKeyPair(
  opts: GenerateKeyOptions,
): Promise<GeneratedKeyPair> {
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

export async function encryptAndSign(
  opts: EncryptAndSignOptions,
): Promise<string> {
  if (!opts.plaintext) throw new Error("Plaintext is required.");
  if (!opts.recipientPublicKeys.length)
    throw new Error("At least one recipient public key is required.");
  if (!opts.signerPrivateKey) throw new Error("A signer private key is required.");

  const encryptionKeys: openpgp.PublicKey[] = [];
  for (const arm of opts.recipientPublicKeys) {
    encryptionKeys.push(await readKey(arm));
  }

  const signingKey = await unlockPrivateKey(
    await readPrivateKey(opts.signerPrivateKey),
    opts.signerPassphrase,
  );

  const message = await openpgp.createMessage({ text: opts.plaintext });

  const encrypted = await openpgp.encrypt({
    message,
    encryptionKeys,
    signingKeys: [signingKey],
    format: "armored",
  });

  return encrypted as string;
}

export async function decryptAndVerify(
  opts: DecryptAndVerifyOptions,
): Promise<DecryptAndVerifyResult> {
  if (!opts.armoredMessage) throw new Error("An encrypted message is required.");
  if (!opts.decryptionPrivateKey)
    throw new Error("A decryption private key is required.");

  const decryptionKey = await unlockPrivateKey(
    await readPrivateKey(opts.decryptionPrivateKey),
    opts.decryptionPassphrase,
  );

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
  // invalid signature or missing key. Build a fingerprint lookup from the
  // verification keys for richer reporting.
  const fpByKeyID = new Map<string, string>();
  for (const k of verificationKeys) {
    try {
      fpByKeyID.set(keyIDToHex(k.getKeyID()), k.getFingerprint().toUpperCase());
    } catch {
      // ignore
    }
  }

  const sigsWithV = await Promise.all(
    (result.signatures || []).map(async (sig) => {
      const keyID = keyIDToHex(sig.keyID);
      const fingerprint = fpByKeyID.get(keyID);
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
      return { keyID, fingerprint, verified, error };
    }),
  );

  return { plaintext, signatures: sigsWithV };
}

export async function signMessage(opts: SignOptions): Promise<string> {
  if (!opts.plaintext) throw new Error("Plaintext is required.");
  if (!opts.privateKey) throw new Error("A signer private key is required.");

  const signingKey = await unlockPrivateKey(
    await readPrivateKey(opts.privateKey),
    opts.passphrase,
  );

  if (opts.detached) {
    // For detached signatures we sign the binary message and emit a separate
    // -----BEGIN PGP SIGNATURE----- block.
    const message = await openpgp.createMessage({ text: opts.plaintext });
    const sig = await openpgp.sign({
      message,
      signingKeys: [signingKey],
      detached: true,
      format: "armored",
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
  result: { signatures: { keyID: openpgp.KeyID; verified: Promise<true>; signature: Promise<openpgp.Signature> }[] },
  verificationKeys: openpgp.PublicKey[],
): Promise<VerifyResult> {
  const fpByKeyID = new Map<string, string>();
  for (const k of verificationKeys) {
    try {
      fpByKeyID.set(keyIDToHex(k.getKeyID()), k.getFingerprint().toUpperCase());
    } catch {
      // ignore
    }
  }

  const signatures = await Promise.all(
    (result.signatures || []).map(async (sig) => {
      const keyID = keyIDToHex(sig.keyID);
      const fingerprint = fpByKeyID.get(keyID);
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
      return { keyID, fingerprint, verified, error };
    }),
  );

  const overall =
    signatures.find((s) => s.verified === "valid")
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

export { formatDate };
