/**
 * Client-side helper that fetches public keys for signature verification
 * from BOTH Keybase and keys.openpgp.org, merging the results. (DRY: shared
 * by the RecipientPicker, DecryptTab and VerifyTab flows.)
 *
 * Keybase is tried first because it returns the owning username. If a key
 * isn't found on Keybase, we fall back to keys.openpgp.org (which doesn't
 * have usernames but still allows signature verification).
 *
 * Results are deduplicated by fingerprint.
 */
import * as openpgp from "openpgp";

import {
	fetchKeyByKeyIDClient,
	fetchKeyFromOpenPGP_orgClient,
	type KeybaseKeyByIDResult,
} from "./keybase";

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
};

/**
 * Normalize a PGP key ID for comparison: uppercase, leading "0x" stripped.
 */
function normalizeKeyID(id: string): string {
	return id.replace(/^0x/i, "").toUpperCase();
}

export async function fetchKeysFromAllSources(
	keyIDs: string[],
	keybaseProxy: string,
	opgProxy: string,
): Promise<KeybaseKeyByIDResult[]> {
	// Try Keybase first.
	const keybaseResults = await fetchKeyByKeyIDClient(keyIDs, keybaseProxy).catch(() => []);

	// Find key IDs that Keybase didn't resolve.
	const foundKeyIDs = new Set(keybaseResults.flatMap((k) => k.allKeyIDs ?? [k.keyID]));
	const missingKeyIDs = keyIDs.filter((id) => {
		const upper = id.toUpperCase();
		return !foundKeyIDs.has(upper) && !foundKeyIDs.has(upper.toLowerCase());
	});

	// Try keys.openpgp.org for the missing ones.
	const opgResults =
		missingKeyIDs.length > 0
			? await fetchKeyFromOpenPGP_orgClient(missingKeyIDs, opgProxy).catch(() => [])
			: [];

	// Merge and deduplicate by fingerprint.
	const seen = new Set<string>();
	const merged: KeybaseKeyByIDResult[] = [];
	for (const k of [...keybaseResults, ...opgResults]) {
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
				});
			}
		} catch {
			// Local matching is best-effort — fall back to remote-only behavior.
		}
	}

	// Skip the proxies ONLY for key IDs the local key already resolved.
	const remainingKeyIDs = keyIDs.filter((id) => !locallyMatched.has(normalizeKeyID(id)));
	const remoteResults: KeybaseKeyByIDResult[] =
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
