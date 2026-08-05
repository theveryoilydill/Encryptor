/**
 * Unit tests for the ZIP bundle helpers in `src/lib/pgp/zip-bundle.ts`.
 *
 * Verifies that buildZipBundle produces a valid ZIP blob containing the
 * expected files (output.txt, metadata.json, files/<name>), and that the
 * metadata.json has the correct structure.
 */
import { describe, expect, it } from "vitest";
import {
  base64ToUint8Array,
  buildZipBundle,
  zipFilename,
  type ZipMetadata,
} from "@/lib/pgp/zip-bundle";

describe("zip-bundle", () => {
  describe("base64ToUint8Array", () => {
    it("decodes a base64 string to a Uint8Array", () => {
      const result = base64ToUint8Array("SGVsbG8=");
      expect(result).toBeInstanceOf(Uint8Array);
      expect(Array.from(result)).toEqual([72, 101, 108, 108, 111]); // "Hello"
    });

    it("decodes an empty string to an empty Uint8Array", () => {
      const result = base64ToUint8Array("");
      expect(result).toBeInstanceOf(Uint8Array);
      expect(result.length).toBe(0);
    });

    it("handles binary data correctly", () => {
      // 4 zero bytes
      const result = base64ToUint8Array("AAAA");
      expect(result.length).toBe(3);
      for (const b of result) {
        expect(b).toBe(0);
      }
    });
  });

  describe("zipFilename", () => {
    it("generates a filename with the operation + timestamp", () => {
      const name = zipFilename("encrypt", new Date("2026-08-05T12:34:56.789Z"));
      expect(name).toBe("encryptor-encrypt-2026-08-05_12-34-56.zip");
    });

    it("replaces colons in the timestamp with dashes", () => {
      const name = zipFilename("sign", new Date("2026-08-05T12:34:56.789Z"));
      // Colons are replaced (so the filename works on Windows).
      expect(name).not.toContain(":");
      // The .zip extension is the only dot allowed.
      const dotCount = (name.match(/\./g) || []).length;
      expect(dotCount).toBe(1);
      expect(name).toContain("2026-08-05_12-34-56");
    });

    it("includes the operation name", () => {
      const name = zipFilename("decrypt", new Date("2026-08-05T12:34:56.789Z"));
      expect(name).toContain("decrypt");
    });

    it("always ends with .zip", () => {
      const name = zipFilename("verify", new Date("2026-08-05T12:34:56.789Z"));
      expect(name.endsWith(".zip")).toBe(true);
    });
  });

  describe("buildZipBundle", () => {
    it("produces a Blob", async () => {
      const blob = await buildZipBundle([], {
        operation: "test",
        generatedAt: "2026-08-05T12:34:56.789Z",
      });
      expect(blob).toBeInstanceOf(Blob);
      expect(blob.size).toBeGreaterThan(0);
    });

    it("contains output.txt when output is provided", async () => {
      const JSZip = (await import("jszip")).default;
      const blob = await buildZipBundle([], {
        operation: "test",
        generatedAt: "2026-08-05T12:34:56.789Z",
        output: "Hello, world!",
      });
      const zip = await JSZip.loadAsync(await blob.arrayBuffer());
      const outputContent = await zip.file("output.txt")?.async("string");
      expect(outputContent).toBe("Hello, world!");
    });

    it("contains metadata.json with the correct structure", async () => {
      const JSZip = (await import("jszip")).default;
      const metadata: ZipMetadata = {
        operation: "decrypt",
        generatedAt: "2026-08-05T12:34:56.789Z",
        output: "decrypted text",
        signers: [
          {
            keyID: "ABCDEF12",
            username: "alice",
            name: "Alice",
            email: "alice@test.com",
            verified: "valid",
            timestampIso: "2026-08-05T12:34:56.789Z",
          },
        ],
        verificationResult: "valid",
        fileCount: 2,
      };
      const blob = await buildZipBundle([], metadata);
      const zip = await JSZip.loadAsync(await blob.arrayBuffer());
      const metaContent = await zip.file("metadata.json")?.async("string");
      expect(metaContent).toBeTruthy();
      const parsed = JSON.parse(metaContent!);
      expect(parsed.operation).toBe("decrypt");
      expect(parsed.generatedAt).toBe("2026-08-05T12:34:56.789Z");
      expect(parsed.output).toBe("decrypted text");
      expect(parsed.signers).toHaveLength(1);
      expect(parsed.signers[0]).toMatchObject({
        username: "alice",
        name: "Alice",
        email: "alice@test.com",
        verified: "valid",
        timestampIso: "2026-08-05T12:34:56.789Z",
      });
      expect(parsed.verificationResult).toBe("valid");
      expect(parsed.fileCount).toBe(2);
    });

    it("includes attached files under files/", async () => {
      const JSZip = (await import("jszip")).default;
      const entries = [
        { name: "test.txt", data: new TextEncoder().encode("text file content") },
        { name: "binary.bin", data: new Uint8Array([0, 1, 2, 3, 4, 5]) },
      ];
      const blob = await buildZipBundle(entries, {
        operation: "decrypt",
        generatedAt: "2026-08-05T12:34:56.789Z",
        fileCount: 2,
      });
      const zip = await JSZip.loadAsync(await blob.arrayBuffer());
      const textContent = await zip.file("files/test.txt")?.async("string");
      expect(textContent).toBe("text file content");
      const binaryContent = await zip.file("files/binary.bin")?.async("uint8array");
      expect(Array.from(binaryContent!)).toEqual([0, 1, 2, 3, 4, 5]);
    });

    it("auto-fills generatedAt if missing", async () => {
      const JSZip = (await import("jszip")).default;
      const before = new Date();
      const blob = await buildZipBundle([], {
        operation: "test",
        // generatedAt intentionally omitted
      } as ZipMetadata);
      const after = new Date();
      const zip = await JSZip.loadAsync(await blob.arrayBuffer());
      const metaContent = await zip.file("metadata.json")?.async("string");
      const parsed = JSON.parse(metaContent!);
      const ts = new Date(parsed.generatedAt);
      expect(ts.getTime()).toBeGreaterThanOrEqual(before.getTime());
      expect(ts.getTime()).toBeLessThanOrEqual(after.getTime());
    });

    it("auto-fills fileCount from entries if missing", async () => {
      const JSZip = (await import("jszip")).default;
      const entries = [
        { name: "a.txt", data: new TextEncoder().encode("a") },
        { name: "b.txt", data: new TextEncoder().encode("b") },
        { name: "c.txt", data: new TextEncoder().encode("c") },
      ];
      const blob = await buildZipBundle(entries, {
        operation: "test",
        generatedAt: "2026-08-05T12:34:56.789Z",
        // fileCount intentionally omitted
      } as ZipMetadata);
      const zip = await JSZip.loadAsync(await blob.arrayBuffer());
      const metaContent = await zip.file("metadata.json")?.async("string");
      const parsed = JSON.parse(metaContent!);
      expect(parsed.fileCount).toBe(3);
    });

    it("produces a valid ZIP that can be re-loaded", async () => {
      const JSZip = (await import("jszip")).default;
      const blob = await buildZipBundle(
        [{ name: "hello.txt", data: new TextEncoder().encode("hi") }],
        {
          operation: "roundtrip",
          generatedAt: "2026-08-05T12:34:56.789Z",
          output: "output text",
        },
      );
      // Re-load the blob as a ZIP and verify all expected files are present.
      const zip = await JSZip.loadAsync(await blob.arrayBuffer());
      expect(zip.file("output.txt")).not.toBeNull();
      expect(zip.file("metadata.json")).not.toBeNull();
      expect(zip.file("files/hello.txt")).not.toBeNull();
    });
  });
});
