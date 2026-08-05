/**
 * End-to-end PGP tests that verify the full sign → verify round-trip with
 * the new timestamp notation + signer info extraction.
 *
 * These tests generate a real key pair, sign a message, then verify the
 * signature and check that:
 *   1. The timestamp notation is present in the signature with ms precision
 *   2. The signer's name + email are extracted from the verification key
 *   3. The signature verifies as "valid"
 *
 * No network calls — everything runs against openpgp.js in-memory.
 */
import { describe, expect, it } from "vitest";
import { generateKeyPair, readKey, signMessage, verifyMessage } from "@/lib/pgp/pgp";
import { readTimestampNotation } from "@/lib/pgp/signer-info";

describe("PGP sign + verify round-trip with timestamp notation", () => {
  it("embeds a millisecond-precision timestamp notation in a cleartext signature", async () => {
    const kp = await generateKeyPair({
      name: "Test Signer",
      email: "test@example.com",
      passphrase: "test-pass",
      type: "ecc",
      expirationSeconds: 0,
    });

    const before = new Date();
    const signed = await signMessage({
      plaintext: "Hello, world!",
      privateKey: kp.privateKey,
      passphrase: "test-pass",
      detached: false,
    });
    const after = new Date();

    // The signed message should be a cleartext-signed PGP block.
    expect(signed).toContain("BEGIN PGP SIGNED MESSAGE");

    // Verify the signature and check the timestamp notation.
    const result = await verifyMessage({
      armoredSignature: signed,
      publicKeys: [kp.publicKey],
      detached: false,
    });

    expect(result.verified).toBe("valid");
    expect(result.signatures).toHaveLength(1);
    const sig = result.signatures[0];
    expect(sig.verified).toBe("valid");

    // The timestamp notation should be present and parse as a date within
    // the [before, after] window.
    expect(sig.timestampIso).toBeTruthy();
    const ts = new Date(sig.timestampIso!);
    expect(ts.getTime()).toBeGreaterThanOrEqual(before.getTime());
    expect(ts.getTime()).toBeLessThanOrEqual(after.getTime());

    // The timestamp should have millisecond precision (3 digits after the dot).
    expect(sig.timestampIso!).toMatch(/\.\d{3}Z$/);
  });

  it("embeds a timestamp notation in a detached signature", async () => {
    const kp = await generateKeyPair({
      name: "Detached Tester",
      email: "detached@test.com",
      passphrase: "pass",
      type: "ecc",
      expirationSeconds: 0,
    });

    const plaintext = "Detached signature test message.";
    const sig = await signMessage({
      plaintext,
      privateKey: kp.privateKey,
      passphrase: "pass",
      detached: true,
    });

    expect(sig).toContain("BEGIN PGP SIGNATURE");

    const result = await verifyMessage({
      armoredSignature: sig,
      publicKeys: [kp.publicKey],
      plaintext,
      detached: true,
    });

    expect(result.verified).toBe("valid");
    expect(result.signatures[0].timestampIso).toBeTruthy();
    expect(result.signatures[0].timestampIso!).toMatch(/\.\d{3}Z$/);
  });

  it("extracts the signer's name + email from the verification key", async () => {
    const kp = await generateKeyPair({
      name: "Alice Signer",
      email: "alice@example.com",
      passphrase: "pass",
      type: "ecc",
      expirationSeconds: 0,
    });

    const signed = await signMessage({
      plaintext: "Signed by Alice",
      privateKey: kp.privateKey,
      passphrase: "pass",
      detached: false,
    });

    const result = await verifyMessage({
      armoredSignature: signed,
      publicKeys: [kp.publicKey],
      detached: false,
    });

    expect(result.signatures[0].name).toBe("Alice Signer");
    expect(result.signatures[0].email).toBe("alice@example.com");
    expect(result.signatures[0].userID).toContain("Alice Signer");
    expect(result.signatures[0].userID).toContain("alice@example.com");
  });

  it("exposes allUserIDs when the key has multiple user IDs", async () => {
    // Generate a key with one UID, then sign + verify.
    // (openpgp.js v6 generateKey only supports one UID at generation time,
    // so we just verify allUserIDs has the single UID here. The multi-UID
    // path is exercised in the E2E tests.)
    const kp = await generateKeyPair({
      name: "Single UID",
      email: "single@test.com",
      passphrase: "pass",
      type: "ecc",
      expirationSeconds: 0,
    });

    const signed = await signMessage({
      plaintext: "test",
      privateKey: kp.privateKey,
      passphrase: "pass",
      detached: false,
    });

    const result = await verifyMessage({
      armoredSignature: signed,
      publicKeys: [kp.publicKey],
      detached: false,
    });

    expect(result.signatures[0].allUserIDs).toBeDefined();
    expect(result.signatures[0].allUserIDs!.length).toBeGreaterThanOrEqual(1);
    expect(result.signatures[0].allUserIDs![0]).toContain("single@test.com");
  });

  it("reads the timestamp notation directly from the signature packets", async () => {
    const kp = await generateKeyPair({
      name: "Raw Packet Reader",
      email: "raw@test.com",
      passphrase: "pass",
      type: "ecc",
      expirationSeconds: 0,
    });

    const sig = await signMessage({
      plaintext: "raw packet test",
      privateKey: kp.privateKey,
      passphrase: "pass",
      detached: true,
    });

    // Parse the signature directly and read the notation from the packet.
    const openpgp = await import("openpgp");
    const parsed = await openpgp.readSignature({ armoredSignature: sig });
    const packet = parsed.packets[0];
    expect(packet?.rawNotations).toBeDefined();
    const ts = readTimestampNotation(
      packet.rawNotations as unknown as Array<{
        name: string;
        value: Uint8Array;
        humanReadable: boolean;
        critical: boolean;
      }>,
    );
    expect(ts).toBeTruthy();
    expect(ts!).toMatch(/\.\d{3}Z$/);
  });

  it("works with RSA keys too", async () => {
    const kp = await generateKeyPair({
      name: "RSA Signer",
      email: "rsa@test.com",
      passphrase: "pass",
      type: "rsa",
      rsaBits: 2048,
      expirationSeconds: 0,
    });

    const signed = await signMessage({
      plaintext: "RSA test",
      privateKey: kp.privateKey,
      passphrase: "pass",
      detached: false,
    });

    const result = await verifyMessage({
      armoredSignature: signed,
      publicKeys: [kp.publicKey],
      detached: false,
    });

    expect(result.verified).toBe("valid");
    expect(result.signatures[0].name).toBe("RSA Signer");
    expect(result.signatures[0].email).toBe("rsa@test.com");
    expect(result.signatures[0].timestampIso).toMatch(/\.\d{3}Z$/);
  });
});

describe("PGP encrypt + decrypt with timestamp notation", () => {
  it("embeds a timestamp notation on the signing signature inside an encrypted message", async () => {
    // Generate a key pair to use as both signer and recipient.
    const kp = await generateKeyPair({
      name: "Self Encryptor",
      email: "self@test.com",
      passphrase: "pass",
      type: "ecc",
      expirationSeconds: 0,
    });

    const { encryptAndSign, decryptAndVerify } = await import("@/lib/pgp/pgp");

    const encrypted = await encryptAndSign({
      plaintext: "Encrypted + signed message",
      recipientPublicKeys: [kp.publicKey],
      signerPrivateKey: kp.privateKey,
      signerPassphrase: "pass",
    });

    expect(encrypted).toContain("BEGIN PGP MESSAGE");

    // Decrypt + verify.
    const result = await decryptAndVerify({
      armoredMessage: encrypted,
      decryptionPrivateKey: kp.privateKey,
      decryptionPassphrase: "pass",
      verificationPublicKeys: [kp.publicKey],
    });

    expect(result.plaintext).toBe("Encrypted + signed message");
    expect(result.signatures).toHaveLength(1);
    expect(result.signatures[0].verified).toBe("valid");
    expect(result.signatures[0].timestampIso).toBeTruthy();
    expect(result.signatures[0].timestampIso!).toMatch(/\.\d{3}Z$/);
    expect(result.signatures[0].name).toBe("Self Encryptor");
    expect(result.signatures[0].email).toBe("self@test.com");
  });
});
