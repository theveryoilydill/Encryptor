/**
 * Unit tests for the V2 mode-aware envelope helpers in `src/lib/pgp/envelope.ts`.
 *
 * Covers `buildPlaintextForEncryptionV2` (plaintext / rich / graph) and the
 * V2-aware `parseDecryptedPlaintext` union, including backward compatibility
 * with V1 envelopes and raw plaintext.
 */
import { describe, expect, it } from "vitest";
import {
  ENVELOPE_MARKER,
  ENVELOPE_MARKER_V2,
  buildPlaintextForEncryption,
  buildPlaintextForEncryptionV2,
  parseDecryptedPlaintext,
  type EnvelopeFile,
  type GraphBoard,
} from "@/lib/pgp/envelope";

const file = (name: string, data = "QUJD"): EnvelopeFile => ({
  name,
  type: "image/png",
  data,
  size: 3,
});

describe("buildPlaintextForEncryptionV2", () => {
  it("plaintext mode returns the text verbatim with no envelope marker", () => {
    const out = buildPlaintextForEncryptionV2({ mode: "plaintext", text: "hello keybase", files: [] });
    expect(out).toBe("hello keybase");
    expect(out).not.toContain(ENVELOPE_MARKER);
    expect(out).not.toContain(ENVELOPE_MARKER_V2);
  });

  it("plaintext mode ignores files (interop-friendliness: never wraps)", () => {
    const out = buildPlaintextForEncryptionV2({
      mode: "plaintext",
      text: "plain only",
      files: [file("a.png")],
    });
    expect(out).toBe("plain only");
    expect(out).not.toContain(ENVELOPE_MARKER);
  });

  it("rich mode with no files returns the Markdown text verbatim (portable)", () => {
    const md = "# Title\n\n**bold** and _italic_";
    const out = buildPlaintextForEncryptionV2({ mode: "rich", text: md, files: [] });
    expect(out).toBe(md);
    expect(out).not.toContain(ENVELOPE_MARKER_V2);
  });

  it("rich mode with files wraps in a V2 envelope with kind:'rich'", () => {
    const md = "**bold**";
    const out = buildPlaintextForEncryptionV2({ mode: "rich", text: md, files: [file("a.png")] });
    expect(out.startsWith(ENVELOPE_MARKER_V2 + "\n")).toBe(true);
    const parsed = JSON.parse(out.slice(ENVELOPE_MARKER_V2.length + 1));
    expect(parsed.kind).toBe("rich");
    expect(parsed.text).toBe(md);
    expect(parsed.files).toHaveLength(1);
    expect(parsed.files[0].name).toBe("a.png");
  });

  it("graph mode always wraps in a V2 envelope with kind:'graph'", () => {
    const out = buildPlaintextForEncryptionV2({ mode: "graph", text: "ignored", files: [] });
    expect(out.startsWith(ENVELOPE_MARKER_V2 + "\n")).toBe(true);
    const parsed = JSON.parse(out.slice(ENVELOPE_MARKER_V2.length + 1));
    expect(parsed.kind).toBe("graph");
    expect(parsed.text).toBe("");
    expect(parsed.board).toEqual({ nodes: [], edges: [] });
  });

  it("graph mode serializes a provided board", () => {
    const board: GraphBoard = {
      nodes: [
        { id: "n1", type: "sticky", x: 10, y: 20, w: 200, h: 160, text: "hello" },
        { id: "n2", type: "rect", x: 300, y: 100, w: 160, h: 80, text: "world" },
      ],
      edges: [{ id: "e1", from: "n1", to: "n2", label: "rel" }],
    };
    const out = buildPlaintextForEncryptionV2({ mode: "graph", text: "", files: [], board });
    const parsed = JSON.parse(out.slice(ENVELOPE_MARKER_V2.length + 1));
    expect(parsed.kind).toBe("graph");
    expect(parsed.board.nodes).toHaveLength(2);
    expect(parsed.board.edges[0]).toMatchObject({ from: "n1", to: "n2", label: "rel" });
  });
});

describe("parseDecryptedPlaintext (V2 + backward compat)", () => {
  it("parses a V2 rich envelope", () => {
    const body = JSON.stringify({ kind: "rich", text: "# Hi\n\n**b**", files: [file("x.png")] });
    const raw = `${ENVELOPE_MARKER_V2}\n${body}`;
    const result = parseDecryptedPlaintext(raw);
    expect(result.kind).toBe("rich");
    if (result.kind === "rich") {
      expect(result.text).toBe("# Hi\n\n**b**");
      expect(result.files).toHaveLength(1);
    }
  });

  it("parses a V2 graph envelope and round-trips the board", () => {
    const board: GraphBoard = {
      nodes: [
        { id: "n1", type: "sticky", x: 1, y: 2, w: 200, h: 160, text: "a" },
        { id: "n2", type: "ellipse", x: 5, y: 6, w: 100, h: 100, text: "b" },
      ],
      edges: [{ id: "e1", from: "n1", to: "n2" }],
    };
    const raw = buildPlaintextForEncryptionV2({ mode: "graph", text: "", files: [], board });
    const result = parseDecryptedPlaintext(raw);
    expect(result.kind).toBe("graph");
    if (result.kind === "graph") {
      expect(result.board.nodes).toHaveLength(2);
      expect(result.board.nodes[0]).toMatchObject({ id: "n1", type: "sticky", text: "a" });
      expect(result.board.edges[0].from).toBe("n1");
    }
  });

  it("parses a V2 text envelope as kind:'text'", () => {
    const body = JSON.stringify({ kind: "text", text: "plain", files: [] });
    const raw = `${ENVELOPE_MARKER_V2}\n${body}`;
    const result = parseDecryptedPlaintext(raw);
    expect(result.kind).toBe("text");
    if (result.kind === "text") expect(result.text).toBe("plain");
  });

  it("falls back to raw text when a V2 envelope has malformed JSON", () => {
    const raw = `${ENVELOPE_MARKER_V2}\nnot json`;
    const result = parseDecryptedPlaintext(raw);
    expect(result.kind).toBe("text");
    if (result.kind === "text") expect(result.text).toBe(raw);
  });

  it("falls back to raw text when a V2 envelope is missing the kind field", () => {
    const raw = `${ENVELOPE_MARKER_V2}\n${JSON.stringify({ text: "no kind" })}`;
    const result = parseDecryptedPlaintext(raw);
    expect(result.kind).toBe("text");
  });

  it("falls back to raw text when a V2 graph envelope has an unparseable board", () => {
    const raw = `${ENVELOPE_MARKER_V2}\n${JSON.stringify({ kind: "graph", board: "not-an-object" })}`;
    const result = parseDecryptedPlaintext(raw);
    expect(result.kind).toBe("text");
  });

  it("still parses a legacy V1 envelope as kind:'text' with files", () => {
    const raw = `${ENVELOPE_MARKER}\n${JSON.stringify({
      text: "legacy body",
      files: [{ name: "old.txt", type: "text/plain", data: "QQ==", size: 1 }],
    })}`;
    const result = parseDecryptedPlaintext(raw);
    expect(result.kind).toBe("text");
    if (result.kind === "text") {
      expect(result.text).toBe("legacy body");
      expect(result.files[0].name).toBe("old.txt");
    }
  });

  it("returns raw text with no marker as kind:'text'", () => {
    const result = parseDecryptedPlaintext("just a message from gpg");
    expect(result.kind).toBe("text");
    if (result.kind === "text") expect(result.text).toBe("just a message from gpg");
  });

  it("rich round-trips through build + parse when files are present", () => {
    const md = "**bold** and _italic_";
    const files = [file("a.png"), file("b.png", "ZWY=")];
    const wire = buildPlaintextForEncryptionV2({ mode: "rich", text: md, files });
    const parsed = parseDecryptedPlaintext(wire);
    expect(parsed.kind).toBe("rich");
    if (parsed.kind === "rich") {
      expect(parsed.text).toBe(md);
      expect(parsed.files).toEqual(files);
    }
  });

  it("graph round-trips through build + parse", () => {
    const board: GraphBoard = {
      nodes: [{ id: "n1", type: "text", x: 0, y: 0, w: 120, h: 60, text: "label" }],
      edges: [],
    };
    const wire = buildPlaintextForEncryptionV2({ mode: "graph", text: "", files: [], board });
    const parsed = parseDecryptedPlaintext(wire);
    expect(parsed.kind).toBe("graph");
    if (parsed.kind === "graph") {
      expect(parsed.board.nodes[0].text).toBe("label");
    }
  });

  it("graph image node round-trips through build + parse, carrying the file", () => {
    const imgFile = file("photo.png", "QUJD");
    const board: GraphBoard = {
      nodes: [
        { id: "n1", type: "sticky", x: 10, y: 10, w: 120, h: 80, text: "around it" },
        { id: "n2", type: "image", x: 50, y: 200, w: 200, h: 200, text: "", image: { filename: "photo.png", scale: 80 } },
      ],
      edges: [],
    };
    const wire = buildPlaintextForEncryptionV2({ mode: "graph", text: "", files: [imgFile], board });
    const parsed = parseDecryptedPlaintext(wire);
    expect(parsed.kind).toBe("graph");
    if (parsed.kind === "graph") {
      const imageNode = parsed.board.nodes.find((n) => n.id === "n2");
      expect(imageNode).toBeDefined();
      expect(imageNode!.type).toBe("image");
      expect(imageNode!.image).toEqual({ filename: "photo.png", scale: 80 });
      // The image file travels in files[].
      const carried = parsed.files.find((f) => f.name === "photo.png");
      expect(carried).toBeDefined();
      expect(carried!.data).toBe("QUJD");
    }
  });

  it("drops a graph image node whose filename is missing, but keeps the file", () => {
    const raw = `${ENVELOPE_MARKER_V2}\n${JSON.stringify({
      kind: "graph",
      files: [file("lonely.png")],
      board: {
        nodes: [
          { id: "n1", type: "image", x: 0, y: 0, w: 100, h: 100, text: "", image: { scale: 50 } }, // no filename
          { id: "n2", type: "sticky", x: 10, y: 10, w: 120, h: 80, text: "survives" },
        ],
        edges: [],
      },
    })}`;
    const parsed = parseDecryptedPlaintext(raw);
    expect(parsed.kind).toBe("graph");
    if (parsed.kind === "graph") {
      expect(parsed.board.nodes).toHaveLength(1);
      expect(parsed.board.nodes[0].id).toBe("n2"); // the malformed image node is dropped
      expect(parsed.files.find((f) => f.name === "lonely.png")).toBeDefined();
    }
  });

  it("V1 buildPlaintextForEncryption is still exported and returns text verbatim when no files", () => {
    expect(buildPlaintextForEncryption("bare", [])).toBe("bare");
  });
});
