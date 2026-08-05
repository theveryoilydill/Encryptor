/**
 * Inline image marker helpers for the Encryptor message envelope.
 *
 * Pasted images are embedded INLINE in the message text using a markdown-like
 * syntax:
 *
 *   ![displayName|scale%](envelope://filename.png)
 *
 * The `envelope://` URI scheme is fictional — it's a stable handle that the
 * Decrypt-side renderer resolves to the actual base64 data URL by looking up
 * `filename.png` in the envelope's `files` array. The optional `|scale%`
 * suffix in the alt text controls the rendered width (e.g. `|50%` → 50% of
 * the container width).
 *
 * This keeps the image bytes inside the encrypted envelope (as a regular
 * attachment) while ALSO positioning the image inline in the message body so
 * the recipient sees it where the sender placed it, at the sender's chosen
 * size.
 */

/** Regex matching `![alt|scale%](envelope://filename)` markers.
 *  - Group 1: alt text (may contain `|NN%` suffix)
 *  - Group 2: URI-encoded filename */
export const INLINE_IMAGE_RE = /!\[([^\]]*)\]\(envelope:\/\/([^)\s]+)\)/g;

/** Default scale (in percent) for newly-pasted images. */
export const DEFAULT_INLINE_IMAGE_SCALE = 50;

/** Minimum and maximum scale percentages accepted by the slider. */
export const MIN_INLINE_IMAGE_SCALE = 10;
export const MAX_INLINE_IMAGE_SCALE = 200;

/** Parse an inline image alt string into `{ displayName, scale }`.
 *
 *  Examples:
 *    `"cat.png|50%"` → `{ displayName: "cat.png", scale: 50 }`
 *    `"cat.png"`     → `{ displayName: "cat.png", scale: 100 }`
 *    `"|75%"`        → `{ displayName: "",         scale: 75 }`
 */
export function parseInlineImageAlt(alt: string): {
  displayName: string;
  scale: number;
} {
  const m = alt.match(/\|(\d+)%$/);
  if (m) {
    return {
      displayName: alt.slice(0, -m[0].length),
      scale: parseInt(m[1], 10),
    };
  }
  return { displayName: alt, scale: 100 };
}

/** Information about a single inline image marker found in a text block. */
export interface InlineImageMarker {
  /** Start index of the marker in the source text (inclusive). */
  startIndex: number;
  /** End index of the marker in the source text (exclusive). */
  endIndex: number;
  /** Full marker text, e.g. `![cat.png|50%](envelope://cat.png)`. */
  fullMatch: string;
  /** Raw alt text (may contain `|NN%` suffix). */
  alt: string;
  /** Decoded filename from the `envelope://` URI. */
  filename: string;
  /** Parsed scale percentage (1–200, default 100). */
  scale: number;
  /** Display name (alt text without the `|NN%` suffix). */
  displayName: string;
}

/** Find every inline image marker in `text`. Returns an empty array if
 *  there are none. Markers are returned in order of appearance. */
export function findInlineImageMarkers(text: string): InlineImageMarker[] {
  const out: InlineImageMarker[] = [];
  // Reset regex state (INLINE_IMAGE_RE is a /g module-level constant and
  // therefore carries lastIndex between calls — always reset it).
  INLINE_IMAGE_RE.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = INLINE_IMAGE_RE.exec(text)) !== null) {
    const alt = m[1];
    const filename = decodeURIComponent(m[2]);
    const { displayName, scale } = parseInlineImageAlt(alt);
    out.push({
      startIndex: m.index,
      endIndex: m.index + m[0].length,
      fullMatch: m[0],
      alt,
      filename,
      scale,
      displayName,
    });
  }
  return out;
}

/** Build an inline image marker string.
 *
 *  `buildInlineImageMarker("cat.png", 50)` →
 *  `"![cat.png|50%](envelope://cat.png)"`
 *
 *  If `displayName` differs from `filename` (e.g. the user renamed the file),
 *  pass it explicitly so the marker shows a friendly name in the alt text
 *  while still referencing the actual attachment filename in the URI.
 */
export function buildInlineImageMarker(
  filename: string,
  scale: number,
  displayName?: string,
): string {
  const clamped = Math.max(
    MIN_INLINE_IMAGE_SCALE,
    Math.min(MAX_INLINE_IMAGE_SCALE, scale),
  );
  const alt = `${displayName ?? filename}|${clamped}%`;
  return `![${alt}](envelope://${encodeURIComponent(filename)})`;
}

/** Replace the marker at `index` in `text` with one using `newScale`.
 *  Returns the new text. If `index` is out of bounds, returns `text` unchanged.
 *  Preserves the marker's displayName and filename. */
export function updateMarkerScale(
  text: string,
  index: number,
  newScale: number,
): string {
  const markers = findInlineImageMarkers(text);
  const m = markers[index];
  if (!m) return text;
  const newMarker = buildInlineImageMarker(m.filename, newScale, m.displayName);
  return text.slice(0, m.startIndex) + newMarker + text.slice(m.endIndex);
}

/** Remove the marker at `index` from `text`, along with a single newline
 *  pair immediately before OR after it (so we don't leave a blank gap where
 *  the image used to be, but we also don't collapse the paragraph
 *  separation when the marker sat between two paragraphs).
 *
 *  Preference order:
 *    1. Strip a trailing newline pair (`\n\n` or single `\n`) if present.
 *    2. Otherwise, strip a leading newline pair.
 *
 *  Examples:
 *    `"a\n\n![m]\n\nb"` → `"a\n\nb"`  (trailing pair stripped, leading kept)
 *    `"a![m]\nb"`        → `"ab"`       (only trailing single newline)
 *    `"a\n![m]b"`        → `"ab"`       (only leading single newline)
 *    `"![m]"`            → `""`         (no surrounding whitespace)
 */
export function removeMarker(text: string, index: number): string {
  const markers = findInlineImageMarkers(text);
  const m = markers[index];
  if (!m) return text;

  // Strip the trailing newline pair (or single newline) if present.
  let end = m.endIndex;
  let strippedTrailing = false;
  if (text.slice(end, end + 2) === "\n\n") {
    end += 2;
    strippedTrailing = true;
  } else if (text.slice(end, end + 1) === "\n") {
    end += 1;
    strippedTrailing = true;
  }

  // Only strip the leading newline pair if we didn't strip a trailing one.
  // This preserves paragraph separation when the marker sat between two
  // paragraphs (e.g. "Para 1\n\n![m]\n\nPara 2" → "Para 1\n\nPara 2").
  let start = m.startIndex;
  if (!strippedTrailing) {
    if (text.slice(start - 2, start) === "\n\n") start -= 2;
    else if (text.slice(start - 1, start) === "\n") start -= 1;
  }

  return text.slice(0, start) + text.slice(end);
}
