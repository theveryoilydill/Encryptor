/**
 * Inline image marker helpers for the Encryptor message envelope.
 *
 * Pasted images are embedded INLINE in the message text using a markdown-like
 * syntax:
 *
 *   ![displayName|scale%@dx,dy](envelope://filename.png)
 *
 * The `envelope://` URI scheme is fictional — it's a stable handle that the
 * renderer resolves to the actual base64 data URL by looking up `filename.png`
 * in the envelope's `files` array.
 *
 * Fields:
 *   - displayName: shown as alt text + in the image controls
 *   - scale: rendered width as a percentage of the container (10–200)
 *   - dx, dy: pixel offset from the natural inline position (can be negative)
 *
 * The `@dx,dy` suffix is optional — markers without it default to (0, 0),
 * which keeps backward compatibility with messages encrypted by older
 * versions of the app.
 */

/** Regex matching `![alt|scale%@dx,dy](envelope://filename)` markers.
 *  - Group 1: alt text (may contain `|NN%` and `@dx,dy` suffixes)
 *  - Group 2: URI-encoded filename */
export const INLINE_IMAGE_RE = /!\[([^\]]*)\]\(envelope:\/\/([^)\s]+)\)/g;

/** Default scale (in percent) for newly-pasted images. */
export const DEFAULT_INLINE_IMAGE_SCALE = 50;

/** Minimum and maximum scale percentages accepted. */
export const MIN_INLINE_IMAGE_SCALE = 10;
export const MAX_INLINE_IMAGE_SCALE = 200;

/** Step sizes for keyboard adjustments. */
/** Normal arrow-key move step (pixels). */
export const MOVE_STEP_NORMAL = 10;
/** Shift+arrow micro-adjustment step (pixels). */
export const MOVE_STEP_MICRO = 1;
/** Normal alt+arrow scale step (percentage points). */
export const SCALE_STEP_NORMAL = 5;
/** Shift+alt+arrow micro scale step (percentage points). */
export const SCALE_STEP_MICRO = 1;

/** Parse an inline image alt string into `{ displayName, scale, dx, dy }`.
 *
 *  Accepted alt formats (all optional after the display name):
 *    `"cat.png"`                  → scale=100, dx=0,  dy=0
 *    `"cat.png|50%"`              → scale=50,  dx=0,  dy=0
 *    `"cat.png|50%@10,-5"`        → scale=50,  dx=10, dy=-5
 *    `"cat.png@10,-5"`            → scale=100, dx=10, dy=-5
 *    `"|75%"`                     → scale=75,  dx=0,  dy=0  (empty display name)
 */
export function parseInlineImageAlt(alt: string): {
  displayName: string;
  scale: number;
  dx: number;
  dy: number;
} {
  // Try to match the full `displayName|scale%@dx,dy` form first.
  let fullName = alt;
  let scale = 100;
  let dx = 0;
  let dy = 0;

  // Match `@dx,dy` position suffix (must be at the end).
  const posMatch = fullName.match(/@(-?\d+),(-?\d+)$/);
  if (posMatch) {
    dx = parseInt(posMatch[1], 10);
    dy = parseInt(posMatch[2], 10);
    fullName = fullName.slice(0, -posMatch[0].length);
  }

  // Match `|scale%` scale suffix (must be at the end after position stripping).
  const scaleMatch = fullName.match(/\|(\d+)%$/);
  if (scaleMatch) {
    scale = parseInt(scaleMatch[1], 10);
    fullName = fullName.slice(0, -scaleMatch[0].length);
  }

  return { displayName: fullName, scale, dx, dy };
}

/** Information about a single inline image marker found in a text block. */
export interface InlineImageMarker {
  /** Start index of the marker in the source text (inclusive). */
  startIndex: number;
  /** End index of the marker in the source text (exclusive). */
  endIndex: number;
  /** Full marker text, e.g. `![cat.png|50%@10,-5](envelope://cat.png)`. */
  fullMatch: string;
  /** Raw alt text (may contain `|NN%` and `@dx,dy` suffixes). */
  alt: string;
  /** Decoded filename from the `envelope://` URI. */
  filename: string;
  /** Parsed scale percentage (10–200, default 100). */
  scale: number;
  /** Display name (alt text without the `|NN%` and `@dx,dy` suffixes). */
  displayName: string;
  /** Horizontal pixel offset from the natural inline position. */
  dx: number;
  /** Vertical pixel offset from the natural inline position. */
  dy: number;
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
    const { displayName, scale, dx, dy } = parseInlineImageAlt(alt);
    out.push({
      startIndex: m.index,
      endIndex: m.index + m[0].length,
      fullMatch: m[0],
      alt,
      filename,
      scale,
      displayName,
      dx,
      dy,
    });
  }
  return out;
}

/** Build an inline image marker string.
 *
 *  `buildInlineImageMarker("cat.png", 50, 10, -5)` →
 *  `"![cat.png|50%@10,-5](envelope://cat.png)"`
 *
 *  If `displayName` differs from `filename` (e.g. the user renamed the file),
 *  pass it explicitly so the marker shows a friendly name in the alt text
 *  while still referencing the actual attachment filename in the URI.
 *
 *  If both dx and dy are 0, the `@0,0` suffix is omitted for brevity and
 *  backward compatibility with older markers.
 */
export function buildInlineImageMarker(
  filename: string,
  scale: number,
  dx = 0,
  dy = 0,
  displayName?: string,
): string {
  const clamped = Math.max(MIN_INLINE_IMAGE_SCALE, Math.min(MAX_INLINE_IMAGE_SCALE, scale));
  const name = displayName ?? filename;
  const posSuffix = dx === 0 && dy === 0 ? "" : `@${dx},${dy}`;
  const alt = `${name}|${clamped}%${posSuffix}`;
  return `![${alt}](envelope://${encodeURIComponent(filename)})`;
}

/** Replace the marker at `index` in `text` with one using the given scale
 *  and position. Returns the new text. If `index` is out of bounds, returns
 *  `text` unchanged. Preserves the marker's displayName and filename. */
export function updateMarkerTransform(
  text: string,
  index: number,
  next: { scale?: number; dx?: number; dy?: number },
): string {
  const markers = findInlineImageMarkers(text);
  const m = markers[index];
  if (!m) return text;
  const newMarker = buildInlineImageMarker(
    m.filename,
    next.scale ?? m.scale,
    next.dx ?? m.dx,
    next.dy ?? m.dy,
    m.displayName,
  );
  return text.slice(0, m.startIndex) + newMarker + text.slice(m.endIndex);
}

/** Backward-compatible alias: updates only the scale. */
export function updateMarkerScale(text: string, index: number, newScale: number): string {
  return updateMarkerTransform(text, index, { scale: newScale });
}

/** Remove the marker at `index` from `text`, along with a single newline
 *  pair immediately before OR after it (so we don't leave a blank gap where
 *  the image used to be, but we also don't collapse the paragraph
 *  separation when the marker sat between two paragraphs).
 *
 *  Preference order:
 *    1. Strip a trailing newline pair (`\n\n` or single `\n`) if present.
 *    2. Otherwise, strip a leading newline pair.
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
  let start = m.startIndex;
  if (!strippedTrailing) {
    if (text.slice(start - 2, start) === "\n\n") start -= 2;
    else if (text.slice(start - 1, start) === "\n") start -= 1;
  }

  return text.slice(0, start) + text.slice(end);
}
