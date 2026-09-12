/**
 * Encrypted-message envelope helpers.
 *
 * When a user attaches files (or pastes images) to a message, we wrap the
 * plaintext + attachments in a JSON envelope before encrypting. The envelope
 * is prefixed with a marker so the decryptor can detect it unambiguously and
 * fall back to plain-text mode for messages encrypted by older clients that
 * didn't use the envelope format.
 *
 * Wire format:
 *
 *   X-Encryptor-Envelope-V1\n
 *   {"text":"...","files":[{"name":"foo.png","type":"image/png","data":"<b64>"}]}
 *
 * The marker is a literal newline-terminated header line. Everything after
 * the first newline is the JSON payload.
 */

export const ENVELOPE_MARKER = "X-Encryptor-Envelope-V1";
export const ENVELOPE_VERSION = 1;

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
 * Detect whether a decrypted plaintext is an envelope and, if so, parse it.
 * Returns `{ kind: "envelope", envelope }` or `{ kind: "text", text }`.
 */
export function parseDecryptedPlaintext(
  raw: string,
): { kind: "envelope"; envelope: Envelope } | { kind: "text"; text: string } {
  if (!raw.startsWith(ENVELOPE_MARKER + "\n")) {
    return { kind: "text", text: raw };
  }
  const jsonPart = raw.slice(ENVELOPE_MARKER.length + 1);
  try {
    const parsed = JSON.parse(jsonPart) as Partial<Envelope>;
    if (parsed && typeof parsed.text === "string" && Array.isArray(parsed.files)) {
      return {
        kind: "envelope",
        envelope: {
          text: parsed.text,
          files: parsed.files.map((f) => ({
            name: f?.name ?? "unnamed",
            type: f?.type ?? "application/octet-stream",
            data: f?.data ?? "",
            size: f?.size ?? 0,
          })),
        },
      };
    }
  } catch {
    // fall through
  }
  // Malformed envelope — fall back to raw text so the user still sees output.
  return { kind: "text", text: raw };
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

/**
 * Strict allow-list for any file- or message-derived URL that reaches an
 * <img src> (defense in depth against CodeQL js/xss-through-dom on the URL
 * sink). Permitted, and only rendered:
 *   - `data:image/<png|jpeg|jpg|gif|webp|bmp|avif|svg+xml>;base64,<b64>`
 *     with the payload charset enforced (a decrypted, attacker-controlled
 *     message can therefore never inject e.g. data:text/html or a
 *     javascript: URL into an <img>),
 *   - `blob:` URLs (same-document object URLs minted by URL.createObjectURL),
 *   - `https:` URLs (remote avatars, e.g. Keybase profile pictures).
 * Everything else - and anything that is not an absolute URL - returns null
 * so the caller can render a non-image fallback instead.
 */
export function isSafeImageUrl(url: string): string | null {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return null;
  }
  if (parsed.protocol === "https:" || parsed.protocol === "blob:") return url;
  if (parsed.protocol === "data:") {
    return /^data:image\/(?:png|jpe?g|gif|webp|bmp|avif|svg\+xml);base64,[A-Za-z0-9+/=]+$/.test(url)
      ? url
      : null;
  }
  return null;
}

/** Human-readable file size, e.g. "1.4 MB". */
export function formatFileSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}
