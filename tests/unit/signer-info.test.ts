/**
 * Unit tests for the signer-info + timestamp helpers in
 * `src/lib/pgp/signer-info.ts`.
 *
 * Covers:
 *  - parseUserID: extracts name/email/comment from RFC 4880 UserID strings
 *  - buildTimestampNotation: produces the correct openpgp RawNotation shape
 *  - readTimestampNotation: round-trips the notation back to an ISO string
 *  - formatTimestamp: displays with millisecond precision
 */
import { describe, expect, it } from "vitest";
import {
  TIMESTAMP_NOTATION_NAME,
  buildTimestampNotation,
  formatTimestamp,
  parseUserID,
  readTimestampNotation,
} from "@/lib/pgp/signer-info";

describe("signer-info", () => {
  describe("parseUserID", () => {
    it("parses the standard 'Name <email> (comment)' format", () => {
      const r = parseUserID("Alice Smith <alice@example.com> (work key)");
      expect(r.name).toBe("Alice Smith");
      expect(r.email).toBe("alice@example.com");
      expect(r.comment).toBe("work key");
    });

    it("parses 'Name <email>' without a comment", () => {
      const r = parseUserID("Bob Jones <bob@example.com>");
      expect(r.name).toBe("Bob Jones");
      expect(r.email).toBe("bob@example.com");
      expect(r.comment).toBeUndefined();
    });

    it("parses an email-only user ID", () => {
      const r = parseUserID("<carol@example.com>");
      expect(r.email).toBe("carol@example.com");
      expect(r.name).toBeUndefined();
    });

    it("parses a name-only user ID", () => {
      const r = parseUserID("Dave Doe");
      expect(r.name).toBe("Dave Doe");
      expect(r.email).toBeUndefined();
      expect(r.comment).toBeUndefined();
    });

    it("parses a comment-only user ID", () => {
      const r = parseUserID("(backup key)");
      expect(r.comment).toBe("backup key");
      expect(r.name).toBeUndefined();
      expect(r.email).toBeUndefined();
    });

    it("returns an empty object for an empty string", () => {
      const r = parseUserID("");
      expect(r).toEqual({});
    });

    it("handles extra whitespace around fields", () => {
      const r = parseUserID("  Eve  <eve@example.com>  (mobile)  ");
      expect(r.name).toBe("Eve");
      expect(r.email).toBe("eve@example.com");
      expect(r.comment).toBe("mobile");
    });

    it("handles an email with a display name containing angle-like chars", () => {
      // Tricky case: '<' inside the name. The regex matches the FIRST <...>.
      // The parser takes name = everything before the first '<'.
      const r = parseUserID("Frank <smith> <frank@example.com>");
      expect(r.email).toBe("smith"); // first <...> wins
      expect(r.name).toBe("Frank");
    });
  });

  describe("buildTimestampNotation", () => {
    it("produces a single notation with the correct name", () => {
      const notations = buildTimestampNotation(new Date("2026-08-05T12:34:56.789Z"));
      expect(notations).toHaveLength(1);
      expect(notations[0].name).toBe(TIMESTAMP_NOTATION_NAME);
    });

    it("marks the notation as human-readable and non-critical", () => {
      const notations = buildTimestampNotation();
      expect(notations[0].humanReadable).toBe(true);
      expect(notations[0].critical).toBe(false);
    });

    it("encodes the ISO timestamp as UTF-8 bytes", () => {
      const iso = "2026-08-05T12:34:56.789Z";
      const notations = buildTimestampNotation(new Date(iso));
      const decoded = new TextDecoder().decode(notations[0].value);
      expect(decoded).toBe(iso);
    });

    it("includes millisecond precision in the timestamp", () => {
      const notations = buildTimestampNotation(new Date("2026-08-05T12:34:56.123Z"));
      const decoded = new TextDecoder().decode(notations[0].value);
      expect(decoded).toContain(".123Z");
    });

    it("pads milliseconds to 3 digits", () => {
      // Date.toISOString() always pads, so 5ms becomes 005.
      const notations = buildTimestampNotation(new Date("2026-08-05T12:34:56.005Z"));
      const decoded = new TextDecoder().decode(notations[0].value);
      expect(decoded).toContain(".005Z");
    });
  });

  describe("readTimestampNotation", () => {
    it("returns the ISO string when the timestamp notation is present", () => {
      const iso = "2026-08-05T12:34:56.789Z";
      const notations = [
        {
          name: "other@notation.example",
          value: new TextEncoder().encode("ignored"),
          humanReadable: true,
          critical: false,
        },
        {
          name: TIMESTAMP_NOTATION_NAME,
          value: new TextEncoder().encode(iso),
          humanReadable: true,
          critical: false,
        },
      ];
      expect(readTimestampNotation(notations)).toBe(iso);
    });

    it("returns undefined when the timestamp notation is absent", () => {
      const notations = [
        {
          name: "other@notation.example",
          value: new TextEncoder().encode("ignored"),
          humanReadable: true,
          critical: false,
        },
      ];
      expect(readTimestampNotation(notations)).toBeUndefined();
    });

    it("returns undefined for an empty array", () => {
      expect(readTimestampNotation([])).toBeUndefined();
    });

    it("returns undefined for null/undefined input", () => {
      expect(readTimestampNotation(null as unknown as never[])).toBeUndefined();
      expect(readTimestampNotation(undefined as unknown as never[])).toBeUndefined();
    });

    it("round-trips through build + read", () => {
      const iso = "2026-08-05T12:34:56.789Z";
      const notations = buildTimestampNotation(new Date(iso));
      expect(readTimestampNotation(notations)).toBe(iso);
    });
  });

  describe("formatTimestamp", () => {
    it("formats an ISO timestamp with millisecond precision", () => {
      const r = formatTimestamp("2026-08-05T12:34:56.789Z");
      expect(r).toContain("2026-08-05");
      expect(r).toContain("12:34:56");
      expect(r).toContain(".789");
      expect(r).toContain("UTC");
    });

    it("returns 'unknown' for undefined", () => {
      expect(formatTimestamp(undefined)).toBe("unknown");
    });

    it("returns 'unknown' for an empty string", () => {
      expect(formatTimestamp("")).toBe("unknown");
    });

    it("returns the raw string if it can't be parsed as a date", () => {
      expect(formatTimestamp("not a date")).toBe("not a date");
    });

    it("handles a timestamp with 0 milliseconds", () => {
      const r = formatTimestamp("2026-08-05T12:34:56.000Z");
      expect(r).toContain(".000");
    });
  });
});
