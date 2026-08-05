/**
 * Helpers for extracting rich signer metadata from a PGP public key and for
 * embedding / reading high-precision timestamps in signatures.
 *
 * PGP signatures only store a 4-byte Unix-seconds creation time. To carry
 * millisecond precision we add a "notation data" subpacket (RFC 4880 §5.2.3.16)
 * named `timestamp@encryptor.dev` whose value is an ISO 8601 string with
 * millisecond precision. The notation is human-readable and non-critical so
 * older verifiers simply ignore it.
 */

export const TIMESTAMP_NOTATION_NAME = "timestamp@encryptor.dev";

export interface SignerInfo {
  /** Keybase username if the key was fetched from Keybase. */
  username?: string;
  /** Full name from the key's primary user ID (e.g. "Alice Smith"). */
  name?: string;
  /** Email address from the key's primary user ID (e.g. "alice@example.com"). */
  email?: string;
  /** Comment field from the key's primary user ID, if present. */
  comment?: string;
  /** Raw user ID string (e.g. "Alice Smith <alice@example.com> (work)"). */
  userID?: string;
  /** All user IDs on the key, in case the primary doesn't have an email. */
  allUserIDs?: string[];
}

/**
 * Parse a raw PGP user ID string like "Alice Smith <alice@example.com> (work)"
 * into its component parts. Tolerant of missing fields.
 */
export function parseUserID(raw: string): {
  name?: string;
  email?: string;
  comment?: string;
} {
  // "Name <email> (comment)" — standard RFC 4880 UserID format.
  const result: { name?: string; email?: string; comment?: string } = {};
  if (!raw) return result;

  // Extract comment first: (...)
  const commentMatch = raw.match(/\(([^)]*)\)/);
  if (commentMatch) {
    result.comment = commentMatch[1].trim();
  }

  // Extract email: <...>
  const emailMatch = raw.match(/<([^>]+)>/);
  if (emailMatch) {
    result.email = emailMatch[1].trim();
  }

  // Name is everything before the email (or comment if no email).
  let nameEnd = raw.length;
  if (emailMatch && emailMatch.index !== undefined) {
    nameEnd = emailMatch.index;
  } else if (commentMatch && commentMatch.index !== undefined) {
    nameEnd = commentMatch.index;
  }
  const name = raw.slice(0, nameEnd).trim();
  if (name) {
    result.name = name;
  }

  return result;
}

/**
 * Build the signatureNotations array for openpgp.sign().
 *
 * Returns a single notation with the current time as an ISO 8601 string
 * with millisecond precision, e.g. "2026-08-05T12:34:56.789Z".
 */
export function buildTimestampNotation(now: Date = new Date()): Array<{
  name: string;
  value: Uint8Array;
  humanReadable: boolean;
  critical: boolean;
}> {
  const iso = now.toISOString(); // always milliseconds + Z
  return [
    {
      name: TIMESTAMP_NOTATION_NAME,
      value: new TextEncoder().encode(iso),
      humanReadable: true,
      critical: false,
    },
  ];
}

/**
 * Read the high-precision timestamp notation from a signature's rawNotations.
 * Returns the ISO string if present, or undefined.
 */
export function readTimestampNotation(
  rawNotations: Array<{
    name: string;
    value: Uint8Array;
    humanReadable: boolean;
    critical: boolean;
  }>,
): string | undefined {
  for (const n of rawNotations ?? []) {
    if (n.name === TIMESTAMP_NOTATION_NAME) {
      try {
        return new TextDecoder().decode(n.value);
      } catch {
        return undefined;
      }
    }
  }
  return undefined;
}

/**
 * Format an ISO timestamp string for display, preserving millisecond precision.
 * Returns "unknown" if the input is missing or unparseable.
 */
export function formatTimestamp(iso: string | undefined): string {
  if (!iso) return "unknown";
  try {
    const d = new Date(iso);
    if (isNaN(d.getTime())) return iso; // show raw string if unparseable
    // e.g. "2026-08-05 12:34:56.789 UTC"
    const ms = String(d.getUTCMilliseconds()).padStart(3, "0");
    const date = d.toISOString().slice(0, 10);
    const time = d.toISOString().slice(11, 19);
    return `${date} ${time}.${ms} UTC`;
  } catch {
    return iso;
  }
}
