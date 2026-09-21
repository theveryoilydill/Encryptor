/**
 * Client-side helper that fetches public keys for signature verification
 * and recipient picking, merging results from EVERY directory (DRY: shared
 * by the RecipientPicker, DecryptTab and VerifyTab flows).
 *
 * Lookup order (owner feedback: Encryptor Registry results FIRST for
 * everything):
 *   1. The Encryptor Registry (built-in, exact key-ID index, armor included
 *      in the response — no second fetch).
 *   2. Keybase (returns the owning username).
 *   3. keys.openpgp.org (fallback without usernames).
 *
 * Results are deduplicated by fingerprint.
 */
import * as openpgp from "openpgp";

import type { KeySource } from "@/components/pgp/contracts";
import {
	fetchKeyByKeyIDClient,
	fetchKeyFromOpenPGP_orgClient,
	type KeybaseKeyByIDResult,
	type KeySearchResult,
} from "./keybase";
import { registryLookup, type RegistryLookupKey } from "@/lib/registry/client";
import { validateArmoredKey } from "@/lib/pgp/pgp";

/**
 * A locally-configured key that can be tried for signature verification
 * WITHOUT any network lookup. Locally generated / manually imported keys are
 * never published to keyservers, so signatures made with them would
 * otherwise permanently show "unknown signer" — even though the signature is
 * cryptographically valid against the local key's public half.
 */
export interface LocalVerificationKey {
	/** The ENCRYPTED armored private key. READING it (openpgp.readKey) does
	 *  not require the passphrase — only USING the private material does. */
	encryptedArmored?: string;
	/** Display label of the configured key (informational). */
	label: string;
}

/** A verification-key lookup result (remote or local), with the optional
 *  marker for records resolved from the locally-configured key. */
export type VerificationKeyLookupResult = KeybaseKeyByIDResult & {
	/** True when this record came from the user's own configured key. */
	self?: boolean;
	/** Expiration of the record's key as epoch-ms (R9). Populated ONLY on the
	 *  local-match path, where the public half is already parsed; remote
	 *  lookups never carry it (the field stays absent — not fabricated). */
	expiresAt?: number | null;
	/** Which source resolved this key (local / Keybase / keys.openpgp.org) —
	 *  surfaced on signature cards so the user can see where the signature
	 *  verification came from. */
	resolvedFrom?: KeySource;
};

/**
 * Normalize a PGP key ID for comparison: uppercase, leading "0x" stripped.
 */
function normalizeKeyID(id: string): string {
	return id.replace(/^0x/i, "").toUpperCase();
}

/** Loose email shape — enough to decide when a query should ALSO hit the
 *  Encryptor Registry's exact-match email index. */
const EMAIL_SUGGEST_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

/** Map a live registry record to a recipient-suggestion result. The armor
 *  ships with the lookup, so adding a recipient needs no second fetch.
 *  Shared by every registry-backed search (owner DRY requirement). */
async function registryKeyToSuggestion(k: RegistryLookupKey): Promise<KeySearchResult> {
	let label = k.fingerprint;
	try {
		const described = await validateArmoredKey(k.armored);
		const first = described.info?.userIDs?.[0];
		if (first?.name && first?.email) label = `${first.name} <${first.email}>`;
		else if (first?.email) label = first.email;
		else if (first?.name) label = first.name;
	} catch {
		// label falls back to the fingerprint
	}
	return {
		source: "encryptor" as const,
		label,
		fingerprint: k.fingerprint,
		keyID: k.fingerprint.slice(-16),
		armored: k.armored,
	};
}

/** Query the Encryptor Registry for email / 40-hex / 16-hex queries and map
 *  live keys to suggestion results (owner feedback: surface Encryptor keys
 *  in the recipients box like the other key directories, so keys published
 *  on Encryptor are discoverable). Revoked keys are never suggested.
 *  Non-matching query shapes resolve to []. */
export async function registrySuggestResults(q: string): Promise<KeySearchResult[]> {
	const trimmed = q.trim();
	let keys: Awaited<ReturnType<typeof registryLookup>> = [];
	const flat = trimmed.replace(/\s+/g, "");
	if (EMAIL_SUGGEST_RE.test(trimmed)) {
		keys = await registryLookup({ email: trimmed.toLowerCase() });
	} else if (/^[0-9A-Fa-f]{40}$/.test(flat)) {
		keys = await registryLookup({ fingerprint: flat.toUpperCase() });
	} else if (/^(0x)?[0-9A-Fa-f]{16}$/.test(flat)) {
		keys = await registryLookup({ keyId: flat.replace(/^0x/i, "").toUpperCase() });
	} else {
		return [];
	}
	const live = keys.filter((k) => !k.revoked).slice(0, 5);
	return Promise.all(live.map(registryKeyToSuggestion));
}

/** Resolve signature key IDs against the Encryptor Registry (owner feedback:
 *  verify must search the registry too — same directory the recipient search
 *  uses, through this one shared module). One lookup per requested ID;
 *  revoked keys never satisfy a verification. Best-effort: failures resolve
 *  to nothing and never block the other sources. */
async function registryVerificationResults(
	keyIDs: string[],
): Promise<VerificationKeyLookupResult[]> {
	const found = await Promise.all(
		keyIDs.map(async (rawID): Promise<VerificationKeyLookupResult | null> => {
			const id = normalizeKeyID(rawID);
			try {
				const keys = await registryLookup({ keyId: id });
				const live = keys.find((k) => !k.revoked);
				if (!live) return null;
				return {
					armored: live.armored,
					keyID: id,
					fingerprint: live.fingerprint.toUpperCase(),
					allKeyIDs: [id],
					resolvedFrom: "encryptor" as const,
				};
			} catch {
				return null;
			}
		}),
	);
	return found.filter((r): r is VerificationKeyLookupResult => r !== null);
}

export async function fetchKeysFromAllSources(
	keyIDs: string[],
	keybaseProxy: string,
	opgProxy: string,
): Promise<VerificationKeyLookupResult[]> {
	// 1. The Encryptor Registry FIRST (owner feedback) — its exact key-ID
	//    index answers in one request and returns the armor directly.
	const registryResults = await registryVerificationResults(keyIDs).catch(() => []);
	for (const k of registryResults) k.resolvedFrom = "encryptor";

	// 2. Keybase for the IDs the registry didn't resolve.
	const registryFound = new Set(registryResults.flatMap((k) => k.allKeyIDs ?? [k.keyID]));
	const notOnRegistry = keyIDs.filter((id) => {
		const upper = id.toUpperCase();
		return !registryFound.has(upper) && !registryFound.has(upper.toLowerCase());
	});
	const keybaseResults = (
		await fetchKeyByKeyIDClient(notOnRegistry, keybaseProxy).catch(() => [])
	) as VerificationKeyLookupResult[];
	for (const k of keybaseResults) k.resolvedFrom = "keybase";

	// 3. keys.openpgp.org for the rest.
	const foundKeyIDs = new Set([
		...registryFound,
		...keybaseResults.flatMap((k) => k.allKeyIDs ?? [k.keyID]),
	]);
	const missingKeyIDs = notOnRegistry.filter((id) => {
		const upper = id.toUpperCase();
		return !foundKeyIDs.has(upper) && !foundKeyIDs.has(upper.toLowerCase());
	});
	const opgResults =
		missingKeyIDs.length > 0
			? ((await fetchKeyFromOpenPGP_orgClient(missingKeyIDs, opgProxy).catch(
					() => [],
				)) as VerificationKeyLookupResult[])
			: [];
	for (const k of opgResults) k.resolvedFrom = "openpgp.org";

	// Merge registry-first and deduplicate by fingerprint.
	const seen = new Set<string>();
	const merged: VerificationKeyLookupResult[] = [];
	for (const k of [...registryResults, ...keybaseResults, ...opgResults]) {
		const fp = k.fingerprint.toUpperCase();
		if (!seen.has(fp)) {
			seen.add(fp);
			merged.push(k);
		}
	}
	return merged;
}

/**
 * fetchKeysFromAllSources, extended with LOCAL signer recognition (R7):
 *
 *  1. If a locally-configured key with an `encryptedArmored` half is given,
 *     read it (passphrase NOT required for reading), take its public half,
 *     and try to satisfy the requested signature key IDs from it — matching
 *     against ALL of the key's IDs (primary + subkeys, case-insensitive).
 *     Matched key IDs are returned as `self: true` records, so the UI can
 *     badge them with a "you" pill.
 *  2. Key IDs already satisfied locally are NOT sent to the remote proxies
 *     (saves round-trips); the rest are fetched exactly as today via
 *     fetchKeysFromAllSources.
 *  3. Results are merged local-first and deduplicated by fingerprint (if the
 *     local key happens to also exist on a keyserver, the local record wins).
 *
 * Any error in the local path (parse failure, etc.) silently falls back to
 * the remote-only behavior — local matching never throws.
 */
export async function fetchKeysFromAllSourcesWithLocal(
	keyIDs: string[],
	keybaseProxy: string,
	opgProxy: string,
	local?: LocalVerificationKey | null,
): Promise<VerificationKeyLookupResult[]> {
	const localMatches: VerificationKeyLookupResult[] = [];
	const locallyMatched = new Set<string>();

	if (local?.encryptedArmored) {
		try {
			const key = await openpgp.readKey({ armoredKey: local.encryptedArmored });
			const publicKey = key.isPrivate() ? key.toPublic() : key;
			const allKeyIDs = publicKey.getKeyIDs().map((kid) => kid.toHex().toUpperCase());
			const allKeyIDsNorm = new Set(allKeyIDs.map(normalizeKeyID));
			const fingerprint = publicKey.getFingerprint().toUpperCase();
			// R9: best-effort expiry of the signer's key — the public half is
			// already parsed, so no extra material is needed. Guard posture
			// mirrors describePublicKey (pgp.ts): a real Date with a valid time
			// wins; openpgp v6 reports Infinity (a plain number) for keys it
			// considers non-expiring, and any other shape (or a throw) → null.
			// Best-effort by construction — never blocks or fails the matching.
			let expiresAt: number | null = null;
			try {
				const exp = await publicKey.getExpirationTime();
				if (exp instanceof Date && !Number.isNaN(exp.getTime())) {
					expiresAt = exp.getTime();
				} else if (Array.isArray(exp)) {
					const first = exp[0];
					if (first instanceof Date && !Number.isNaN(first.getTime())) {
						expiresAt = first.getTime();
					} else if (typeof first === "number" && Number.isFinite(first) && first > 0) {
						expiresAt = first;
					}
				} else if (typeof exp === "number" && Number.isFinite(exp) && exp > 0) {
					expiresAt = exp;
				}
			} catch {
				expiresAt = null;
			}
			for (const requested of keyIDs) {
				const norm = normalizeKeyID(requested);
				if (!allKeyIDsNorm.has(norm)) continue;
				locallyMatched.add(norm);
				localMatches.push({
					// Public half only — armor() works on an encrypted private key's
					// public part without ever decrypting the private material.
					armored: publicKey.armor(),
					// The requested signature key ID (uppercase), as the tabs display.
					keyID: norm,
					fingerprint,
					allKeyIDs,
					self: true,
					expiresAt,
					resolvedFrom: "local",
				});
			}
		} catch {
			// Local matching is best-effort — fall back to remote-only behavior.
		}
	}

	// Skip the proxies ONLY for key IDs the local key already resolved.
	const remainingKeyIDs = keyIDs.filter((id) => !locallyMatched.has(normalizeKeyID(id)));
	const remoteResults: VerificationKeyLookupResult[] =
		remainingKeyIDs.length > 0
			? await fetchKeysFromAllSources(remainingKeyIDs, keybaseProxy, opgProxy)
			: [];

	// Merge local-first and deduplicate by fingerprint (same rule as the
	// remote-only merge inside fetchKeysFromAllSources).
	const seen = new Set<string>();
	const merged: VerificationKeyLookupResult[] = [];
	for (const k of [...localMatches, ...remoteResults]) {
		const fp = k.fingerprint.toUpperCase();
		if (!seen.has(fp)) {
			seen.add(fp);
			merged.push(k);
		}
	}
	return merged;
}
