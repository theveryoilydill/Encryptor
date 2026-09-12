/**
 * In-memory crypto self-test (DRY: composes the existing pgp.ts wrappers).
 *
 * Generates an ephemeral ECC key pair and round-trips encrypt+sign → decrypt
 * → cleartext sign → verify entirely in RAM. Nothing is persisted and no
 * network calls are made. Used by the footer "Run crypto self-test" action.
 */
import {
  decryptAndVerify,
  encryptAndSign,
  generateKeyPair,
  signMessage,
  verifyMessage,
  type AnyKeyInfo,
} from "./pgp";

export interface SelfTestStep {
  name: string;
  ok: boolean;
  ms: number;
  error?: string;
}

export interface SelfTestResult {
  ok: boolean;
  steps: SelfTestStep[];
  totalMs: number;
}

async function timed(name: string, fn: () => Promise<void>): Promise<SelfTestStep> {
  const start = performance.now();
  try {
    await fn();
    return { name, ok: true, ms: Math.round(performance.now() - start) };
  } catch (e) {
    return {
      name,
      ok: false,
      ms: Math.round(performance.now() - start),
      error: (e as Error).message,
    };
  }
}

export async function runCryptoSelfTest(): Promise<SelfTestResult> {
  const steps: SelfTestStep[] = [];
  const start = performance.now();

  // Hold generated material for later steps (scoped to this run only).
  let keyPair: { privateKey: string; publicKey: string; info: AnyKeyInfo } | null = null;
  let encrypted = "";
  let signed = "";

  steps.push(
    await timed("Generate ephemeral ECC key", async () => {
      keyPair = await generateKeyPair({
        name: "Encryptor Self-Test",
        email: "self-test@encryptor.local",
        type: "ecc",
        curve: "ed25519Legacy",
      });
      if (!keyPair.privateKey || !keyPair.publicKey) {
        throw new Error("Key pair came back empty.");
      }
    }),
  );

  steps.push(
    await timed("Encrypt + sign message", async () => {
      const kp = keyPair!;
      encrypted = await encryptAndSign({
        plaintext: "Encryptor self-test — the quick brown fox jumps over the lazy dog. 0123456789.",
        recipientPublicKeys: [kp.publicKey],
        signerPrivateKey: kp.privateKey,
        signerPassphrase: undefined,
      });
      if (!encrypted.includes("-----BEGIN PGP MESSAGE-----")) {
        throw new Error("Output is not an armored PGP message.");
      }
    }),
  );

  steps.push(
    await timed("Decrypt + verify signature", async () => {
      const kp = keyPair!;
      const result = await decryptAndVerify({
        armoredMessage: encrypted,
        decryptionPrivateKey: kp.privateKey,
        verificationPublicKeys: [kp.publicKey],
      });
      if (!result.plaintext.includes("quick brown fox")) {
        throw new Error("Decrypted plaintext does not match.");
      }
      if (result.signatures.length < 1 || result.signatures[0].verified !== "valid") {
        throw new Error("Embedded signature did not verify.");
      }
    }),
  );

  steps.push(
    await timed("Cleartext sign", async () => {
      const kp = keyPair!;
      signed = await signMessage({
        plaintext: "Encryptor self-test signature payload.",
        privateKey: kp.privateKey,
        detached: false,
      });
      if (!signed.includes("-----BEGIN PGP SIGNED MESSAGE-----")) {
        throw new Error("Output is not a cleartext signed message.");
      }
    }),
  );

  steps.push(
    await timed("Verify cleartext signature", async () => {
      const kp = keyPair!;
      const result = await verifyMessage({
        armoredSignature: signed,
        publicKeys: [kp.publicKey],
      });
      if (result.verified !== "valid") {
        throw new Error("Cleartext signature did not verify.");
      }
    }),
  );

  const totalMs = Math.round(performance.now() - start);
  return { ok: steps.every((s) => s.ok), steps, totalMs };
}
