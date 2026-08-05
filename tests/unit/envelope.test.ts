/**
 * Unit tests for the envelope helpers in `src/lib/pgp/envelope.ts`.
 *
 * These tests verify the wire-format round-trip:
 *   plaintext + files → buildPlaintextForEncryption → parseDecryptedPlaintext
 * and the backward-compatibility path (no attachments → no envelope marker).
 */
import { describe, expect, it } from "vitest";
import {
  ENVELOPE_MARKER,
  buildPlaintextForEncryption,
  envelopeFileToDataUrl,
  formatFileSize,
  parseDecryptedPlaintext,
} from "@/lib/pgp/envelope";

describe("envelope", () => {
  describe("buildPlaintextForEncryption", () => {
    it("returns the plaintext verbatim when there are no files (backward compat)", () => {
      const result = buildPlaintextForEncryption("hello world", []);
      expect(result).toBe("hello world");
      expect(result).not.toContain(ENVELOPE_MARKER);
    });

    it("wraps the plaintext in an envelope when files are present", () => {
      const result = buildPlaintextForEncryption("hello", [
        { name: "a.txt", type: "text/plain", data: "SGVsbG8=", size: 5 },
      ]);
      expect(result.startsWith(ENVELOPE_MARKER + "\n")).toBe(true);
      const json = result.slice(ENVELOPE_MARKER.length + 1);
      const parsed = JSON.parse(json);
      expect(parsed.text).toBe("hello");
      expect(parsed.files).toHaveLength(1);
      expect(parsed.files[0]).toMatchObject({
        name: "a.txt",
        type: "text/plain",
        data: "SGVsbG8=",
        size: 5,
      });
    });

    it("preserves multiple files and their order", () => {
      const files = [
        { name: "1.png", type: "image/png", data: "AAAA", size: 4 },
        { name: "2.pdf", type: "application/pdf", data: "BBBB", size: 4 },
        { name: "3.txt", type: "text/plain", data: "CCCC", size: 4 },
      ];
      const result = buildPlaintextForEncryption("text", files);
      const json = result.slice(ENVELOPE_MARKER.length + 1);
      const parsed = JSON.parse(json);
      expect(parsed.files.map((f: { name: string }) => f.name)).toEqual([
        "1.png",
        "2.pdf",
        "3.txt",
      ]);
    });

    it("handles empty plaintext with files", () => {
      const result = buildPlaintextForEncryption("", [
        { name: "a.txt", type: "text/plain", data: "QQ==", size: 1 },
      ]);
      const json = result.slice(ENVELOPE_MARKER.length + 1);
      const parsed = JSON.parse(json);
      expect(parsed.text).toBe("");
      expect(parsed.files).toHaveLength(1);
    });
  });

  describe("parseDecryptedPlaintext", () => {
    it("returns plain text when there is no envelope marker", () => {
      const result = parseDecryptedPlaintext("just a regular message");
      expect(result.kind).toBe("text");
      if (result.kind === "text") {
        expect(result.text).toBe("just a regular message");
      }
    });

    it("parses a well-formed envelope", () => {
      const envelope = {
        text: "the message",
        files: [{ name: "x.bin", type: "application/octet-stream", data: "AA==", size: 1 }],
      };
      const raw = `${ENVELOPE_MARKER}\n${JSON.stringify(envelope)}`;
      const result = parseDecryptedPlaintext(raw);
      expect(result.kind).toBe("envelope");
      if (result.kind === "envelope") {
        expect(result.envelope.text).toBe("the message");
        expect(result.envelope.files).toHaveLength(1);
        expect(result.envelope.files[0].name).toBe("x.bin");
      }
    });

    it("falls back to raw text on malformed JSON after the marker", () => {
      const raw = `${ENVELOPE_MARKER}\nnot valid json`;
      const result = parseDecryptedPlaintext(raw);
      expect(result.kind).toBe("text");
      if (result.kind === "text") {
        expect(result.text).toBe(raw);
      }
    });

    it("falls back to raw text when envelope is missing required fields", () => {
      const raw = `${ENVELOPE_MARKER}\n${JSON.stringify({ text: "no files field" })}`;
      const result = parseDecryptedPlaintext(raw);
      expect(result.kind).toBe("text");
    });

    it("normalizes missing file fields", () => {
      const raw = `${ENVELOPE_MARKER}\n${JSON.stringify({
        text: "hi",
        files: [{ name: "x" }], // missing type, data, size
      })}`;
      const result = parseDecryptedPlaintext(raw);
      expect(result.kind).toBe("envelope");
      if (result.kind === "envelope") {
        expect(result.envelope.files[0]).toMatchObject({
          name: "x",
          type: "application/octet-stream",
          data: "",
          size: 0,
        });
      }
    });

    it("round-trips through build + parse", () => {
      const text = "round trip text";
      const files = [
        { name: "a.png", type: "image/png", data: "iVBOR=", size: 5 },
        { name: "b.txt", type: "text/plain", data: "aGVsbG8=", size: 5 },
      ];
      const wire = buildPlaintextForEncryption(text, files);
      const parsed = parseDecryptedPlaintext(wire);
      expect(parsed.kind).toBe("envelope");
      if (parsed.kind === "envelope") {
        expect(parsed.envelope.text).toBe(text);
        expect(parsed.envelope.files).toEqual(files);
      }
    });
  });

  describe("envelopeFileToDataUrl", () => {
    it("builds a data URL with the correct mime type", () => {
      const url = envelopeFileToDataUrl({
        name: "x.png",
        type: "image/png",
        data: "iVBORw==",
        size: 5,
      });
      expect(url).toBe("data:image/png;base64,iVBORw==");
    });

    it("uses application/octet-stream for unknown types", () => {
      const url = envelopeFileToDataUrl({
        name: "x.bin",
        type: "application/octet-stream",
        data: "AAAA",
        size: 3,
      });
      expect(url).toBe("data:application/octet-stream;base64,AAAA");
    });
  });

  describe("formatFileSize", () => {
    it("formats bytes", () => {
      expect(formatFileSize(0)).toBe("0 B");
      expect(formatFileSize(500)).toBe("500 B");
      expect(formatFileSize(1023)).toBe("1023 B");
    });

    it("formats kilobytes", () => {
      expect(formatFileSize(1024)).toBe("1.0 KB");
      expect(formatFileSize(1536)).toBe("1.5 KB");
    });

    it("formats megabytes", () => {
      expect(formatFileSize(1024 * 1024)).toBe("1.0 MB");
      expect(formatFileSize(1024 * 1024 * 5)).toBe("5.0 MB");
    });

    it("formats gigabytes", () => {
      expect(formatFileSize(1024 * 1024 * 1024 * 2)).toBe("2.00 GB");
    });
  });
});
