/**
 * Encrypted-message envelope helpers.
 *
 * When a user attaches files (or pastes images) to a message, we wrap the
 *plaintext + attachments in a JSON envelope before encrypting. The envelope
 * is prefixed with a marker so the decryptor can detect it unambiguously and
 * fall back to plain-text mode for messages encrypted by older clients that
 * didn't use the envelope format.
 *
 * ## V1 wire format (plain text + files)
 *
 *   X-Encryptor-Envelope-V1\n
 *   {"text":"...","files":[{"name":"foo.png","type":"image/png","data":"<b64>"}]}
 *
 * The marker is a literal newline-terminated header line. Everything after
 * the first newline is the JSON payload. A V1 envelope always represents
 * plain text — it carries no content-kind signal.
 *
 * ## V2 wire format (mode-aware: text / rich / graph)
 *
 *   X-Encryptor-Envelope-V2\n
 *   {"kind":"text"|"rich"|"graph","text":"...","files":[...],"board":{...}}
 *
 * V2 adds an explicit `kind` so the decryptor can render rich (Markdown) or
 * graph/whiteboard content correctly. `board` is present only for graph
 * messages. Graph nodes include an optional `image` node type (see `NodeType`):
 * an image node references one of the envelope `files[]` by filename and is
 * dropped by older clients that don't recognize the type (its file stays in
 * `files[]`). V2 is fully backward compatible: V1 and raw (no-marker) messages
 * still parse as `kind:"text"`, and the robust fallback to raw text on any
 * malformed payload is preserved.
 *
 * Note: `plaintext` mode (legacy / Keybase interop) NEVER wraps an envelope —
 * it emits the raw `text` verbatim, byte-identical to the pre-modes app, so it
 * interops with gpg/Keybase consumers that expect a plain PGP message.
 */

export const ENVELOPE_MARKER = "X-Encryptor-Envelope-V1";
export const ENVELOPE_VERSION = 1;

/** V2 marker + version. A V2 envelope carries a `kind` field. */
export const ENVELOPE_MARKER_V2 = "X-Encryptor-Envelope-V2";
export const ENVELOPE_VERSION_V2 = 2;

export interface EnvelopeFile {
  /** Original file name, e.g. "screenshot.png". */
  name: string;
  /** MIME type, e.g. "image/png". Unknown types use "application/octet-stream". */
  type: string;
  /** Base64-encoded file contents (no data: prefix). */
  data: string;
  /** Original size in bytes (for display). */
  size: number;
}

export interface Envelope {
  text: string;
  files: EnvelopeFile[];
}

/* ----------------------------- V2: graph board ---------------------------- */
// A serializable whiteboard carried inside the V2 envelope (kind:"graph").

export type NodeType = "sticky" | "rect" | "ellipse" | "text" | "image";

export interface GraphNode {
  /** Stable unique id (uuid). */
  id: string;
  type: NodeType;
  /** Top-left position in canvas pixel space. */
  x: number;
  y: number;
  /** Width / height in canvas pixels. */
  w: number;
  h: number;
  /** Inline editable text (Markdown not required — plain multiline text). */
  text: string;
  /** Optional color override keyed off the Encryptor blue palette. */
  color?: string;
  /**
   * Only present when `type === "image"`. The filename references an entry in
   * the envelope `files[]` (resolved to a data URL for rendering). `scale` is an
   * optional percentage in the same range as inline images (see inline-image.ts).
   */
  image?: { filename: string; scale?: number };
}

export interface GraphEdge {
  id: string;
  /** Source GraphNode.id. */
  from: string;
  /** Target GraphNode.id. */
  to: string;
  /** Optional edge label. */
  label?: string;
}

export interface GraphBoard {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

/* --------------------------- V2: content kinds ---------------------------- */

/** The encryption content mode the user has selected in the UI. */
export type Mode = "plaintext" | "rich" | "graph";

/** What the Encrypt side hands to the V2 builder. */
export interface ContentToEncrypt {
  mode: Mode;
  /** For plaintext/rich: the (Markdown for rich) text. For graph: ignored. */
  text: string;
  /** Attachments in the envelope (used by rich; empty for graph in v1). */
  files: EnvelopeFile[];
  /** The board (only meaningful when mode === "graph"). */
  board?: GraphBoard;
}

/**
 * What the Decrypt side gets after parsing a decrypted payload.
 *
 * `kind:"text"` covers BOTH raw/no-marker payloads AND those encrypted in
 * `plaintext` mode — they're indistinguishable on the wire (by design, for
 * Keybase/gpg interop), and a V1 envelope is plain text too. `kind:"rich"`
 * carries Markdown in `text`; `kind:"graph"` carries the board.
 */
export type ParsedContent =
  | { kind: "text"; text: string; files: EnvelopeFile[] }
  | { kind: "rich"; text: string; files: EnvelopeFile[] }
  | { kind: "graph"; board: GraphBoard; files: EnvelopeFile[] };

/**
 * Build the wire-format string that gets passed to openpgp.encrypt.
 *
 * If there are no attachments we return the plaintext directly, preserving
 * backward compatibility with messages encrypted by older versions of the app.
 */
export function buildPlaintextForEncryption(text: string, files: EnvelopeFile[]): string {
  if (!files || files.length === 0) {
    return text;
  }
  const envelope: Envelope = { text, files };
  return `${ENVELOPE_MARKER}\n${JSON.stringify(envelope)}`;
}

/**
 * Normalize a (possibly-partial) parsed file list into well-typed EnvelopeFile
 * entries, filling defaults for missing fields. Mirrors the V1 tolerance.
 */
function normalizeFiles(files: unknown): EnvelopeFile[] {
  if (!Array.isArray(files)) return [];
  return files.map((f) => {
    const file = (f ?? {}) as Partial<EnvelopeFile>;
    return {
      name: file.name ?? "unnamed",
      type: file.type ?? "application/octet-stream",
      data: file.data ?? "",
      size: file.size ?? 0,
    };
  });
}

/**
 * Build the V2 wire-format string for a given content mode.
 *
 * - `plaintext` → raw `text` verbatim, no envelope (Keybase/gpg interop).
 * - `rich` with no files → raw `text` (Markdown) verbatim for portability;
 *   with files → a V2 envelope with `kind:"rich"`.
 * - `graph` → always a V2 envelope with `kind:"graph"` + the board (empty
 *   board if none provided — a board has no portable plain-text form).
 *
 * V1's `buildPlaintextForEncryption` above is unchanged; V2 is additive.
 */
export function buildPlaintextForEncryptionV2(content: ContentToEncrypt): string {
  const { mode, text, files = [], board } = content;

  if (mode === "plaintext") {
    return text;
  }

  if (mode === "rich") {
    if (!files || files.length === 0) {
      return text;
    }
    const body = JSON.stringify({ kind: "rich", text, files });
    return `${ENVELOPE_MARKER_V2}\n${body}`;
  }

  // mode === "graph"
  const safeBoard: GraphBoard = board ?? { nodes: [], edges: [] };
  const body = JSON.stringify({
    kind: "graph",
    text: "",
    files,
    board: safeBoard,
  });
  return `${ENVELOPE_MARKER_V2}\n${body}`;
}

/**
 * Parse a parsed graph board defensively: accept whatever shape the JSON
 * gave us and coerce to `{ nodes, edges }`, dropping anything malformed.
 */
function normalizeBoard(board: unknown): GraphBoard | null {
  if (!board || typeof board !== "object") return null;
  const b = board as { nodes?: unknown; edges?: unknown };

  const num = (v: unknown, fallback: number) =>
    typeof v === "number" && Number.isFinite(v) ? v : fallback;

  const nodes: GraphNode[] = [];
  if (Array.isArray(b.nodes)) {
    for (const n of b.nodes) {
      const node = (n ?? {}) as Partial<GraphNode>;
      if (typeof node.id !== "string") continue;
      const type: NodeType =
        node.type === "sticky" ||
        node.type === "rect" ||
        node.type === "ellipse" ||
        node.type === "text" ||
        node.type === "image"
          ? node.type
          : "text";
      // Image nodes reference a file by filename and are dropped if it's
      // missing — the file itself still travels in `files[]` so an older
      // client that doesn't know the `image` type loses nothing essential.
      if (type === "image") {
        const img = node.image;
        if (!img || typeof img.filename !== "string" || !img.filename) continue;
        const scale =
          typeof img.scale === "number" && Number.isFinite(img.scale)
            ? img.scale
            : undefined;
        nodes.push({
          id: node.id,
          type: "image",
          x: num(node.x, 0),
          y: num(node.y, 0),
          w: num(node.w, 160),
          h: num(node.h, 100),
          text: typeof node.text === "string" ? node.text : "",
          color: typeof node.color === "string" ? node.color : undefined,
          image: { filename: img.filename, ...(scale !== undefined ? { scale } : {}) },
        });
        continue;
      }
      nodes.push({
        id: node.id,
        type,
        x: num(node.x, 0),
        y: num(node.y, 0),
        w: num(node.w, 160),
        h: num(node.h, 100),
        text: typeof node.text === "string" ? node.text : "",
        color: typeof node.color === "string" ? node.color : undefined,
      });
    }
  }

  const edges: GraphEdge[] = [];
  if (Array.isArray(b.edges)) {
    for (const e of b.edges) {
      const edge = (e ?? {}) as Partial<GraphEdge>;
      if (
        typeof edge.id !== "string" ||
        typeof edge.from !== "string" ||
        typeof edge.to !== "string"
      ) {
        continue;
      }
      edges.push({
        id: edge.id,
        from: edge.from,
        to: edge.to,
        label: typeof edge.label === "string" ? edge.label : undefined,
      });
    }
  }

  return { nodes, edges };
}

/**
 * Parse a decrypted plaintext into a mode-aware `ParsedContent`.
 *
 * Dispatch order:
 *   1. V2 marker  → `kind:"rich"|"graph"` (or `"text"` if V2 kind was text),
 *                   falling back to raw text on any malformed payload.
 *   2. V1 marker → plain text + files (`kind:"text"`); falls back to raw text
 *                   on a malformed V1 body. A V1 envelope is never rich/graph.
 *   3. No marker → raw text (`kind:"text"`).
 *
 * The robust "fall back to raw text so the user still sees output" guarantee
 * from the V1 implementation is preserved for every path.
 */
export function parseDecryptedPlaintext(raw: string): ParsedContent {
  // --- V2: mode-aware envelope (text / rich / graph) ---
  if (raw.startsWith(ENVELOPE_MARKER_V2 + "\n")) {
    const jsonPart = raw.slice(ENVELOPE_MARKER_V2.length + 1);
    try {
      const parsed = JSON.parse(jsonPart) as {
        kind?: unknown;
        text?: unknown;
        files?: unknown;
        board?: unknown;
      };
      const files = normalizeFiles(parsed.files);
      if (parsed.kind === "rich" && typeof parsed.text === "string") {
        return { kind: "rich", text: parsed.text, files };
      }
      if (parsed.kind === "graph") {
        const board = normalizeBoard(parsed.board);
        if (board) return { kind: "graph", board, files };
        // graph board unparseable — fall through to raw-text fallback below.
      }
      if (parsed.kind === "text" && typeof parsed.text === "string") {
        return { kind: "text", text: parsed.text, files };
      }
    } catch {
      // fall through to raw-text fallback
    }
    return { kind: "text", text: raw, files: [] };
  }

  // --- V1: plain-text envelope (legacy, no kind field) ---
  if (raw.startsWith(ENVELOPE_MARKER + "\n")) {
    const jsonPart = raw.slice(ENVELOPE_MARKER.length + 1);
    try {
      const parsed = JSON.parse(jsonPart) as Partial<Envelope>;
      if (parsed && typeof parsed.text === "string" && Array.isArray(parsed.files)) {
        return { kind: "text", text: parsed.text, files: normalizeFiles(parsed.files) };
      }
    } catch {
      // fall through
    }
    return { kind: "text", text: raw, files: [] };
  }

  // --- No marker: raw plaintext ---
  return { kind: "text", text: raw, files: [] };
}

/** Read a File/Blob as base64 (no data: prefix). */
export function readFileAsBase64(file: Blob): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => {
      const result = reader.result;
      if (typeof result !== "string") {
        reject(new Error("Failed to read file as data URL"));
        return;
      }
      // Strip the "data:<mime>;base64," prefix.
      const commaIdx = result.indexOf(",");
      resolve(commaIdx >= 0 ? result.slice(commaIdx + 1) : result);
    };
    reader.onerror = () => reject(reader.error ?? new Error("FileReader error"));
    reader.readAsDataURL(file);
  });
}

/** Build a `data:` URL suitable for an <a download> link or <img> preview. */
export function envelopeFileToDataUrl(file: EnvelopeFile): string {
  return `data:${file.type};base64,${file.data}`;
}

/** Human-readable file size, e.g. "1.4 MB". */
export function formatFileSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}
