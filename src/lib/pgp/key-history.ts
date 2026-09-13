/**
 * Previously-configured-keys ring — the "switch back" feature.
 *
 * # Mr. AI Acting on s183173's Behalf
 *
 * WHY
 *   Users bounce between identities: a locally generated key for personal
 *   mail, a Keybase key for public proof-backed identity, a work key… The
 *   Your-key dialog always supported RE-configuring, but switching back meant
 *   a full Keybase re-login or re-pasting armor. This module keeps a small
 *   ring (newest 4) of previously configured keys so the dialog can offer
 *   one-click restore.
 *
 * SECURITY (unchanged posture)
 *   Only key METADATA and the ENCRYPTED armored private key are stored — the
 *   exact same payload the active config already keeps in localStorage. The
 *   decrypted key and any passphrase are NEVER persisted. Keybase entries
 *   carry their key encrypted under the Keybase password (password itself is
 *   discarded at login), so restoring one still requires the passphrase —
 *   switching is convenient, not weaker.
 */
import { STORAGE_KEYS } from "@/lib/constants";
import type { PrivateKeyConfig } from "@/components/pgp/contracts";

/** Newest-first ring of previously configured keys. */
export type KeyHistory = PrivateKeyConfig[];

const MAX_HISTORY = 4;

function readHistory(): KeyHistory {
	try {
		const raw = localStorage.getItem(STORAGE_KEYS.keyHistory);
		if (!raw) return [];
		const parsed = JSON.parse(raw) as unknown;
		if (!Array.isArray(parsed)) return [];
		// Same acceptance rule PgpApp uses for the active config: valid
		// metadata AND either a Keybase handle or encrypted armor.
		return parsed.filter(
			(c): c is PrivateKeyConfig =>
				!!c &&
				typeof c === "object" &&
				!!(c as PrivateKeyConfig).info &&
				((c as PrivateKeyConfig).source === "keybase" ||
					!!(c as PrivateKeyConfig).encryptedArmored),
		);
	} catch {
		return [];
	}
}

function writeHistory(history: KeyHistory): void {
	try {
		localStorage.setItem(STORAGE_KEYS.keyHistory, JSON.stringify(history.slice(0, MAX_HISTORY)));
	} catch {
		// ignore
	}
}

export function loadKeyHistory(): KeyHistory {
	return readHistory();
}

/** Record that `previous` is no longer the active key (it was replaced by one
 *  with a different fingerprint, or cleared). Newest-first, deduped by
 *  fingerprint, capped at MAX_HISTORY. */
export function pushKeyHistory(previous: PrivateKeyConfig): void {
	const fp = previous.info?.fingerprint;
	if (!fp) return;
	const rest = readHistory().filter((c) => c.info?.fingerprint !== fp);
	writeHistory([previous, ...rest].slice(0, MAX_HISTORY));
}

/** Remove an entry (restored or explicitly dismissed by the user). */
export function removeKeyHistory(fingerprint: string): KeyHistory {
	const next = readHistory().filter((c) => c.info?.fingerprint !== fingerprint);
	writeHistory(next);
	return next;
}

/** After a key becomes ACTIVE, drop it from the history (it now lives in the
 *  primary config slot — no duplicate offer). Returns the updated history. */
export function scrubKeyHistory(activeFingerprint: string | undefined): KeyHistory {
	if (!activeFingerprint) return readHistory();
	const next = readHistory().filter((c) => c.info?.fingerprint !== activeFingerprint);
	writeHistory(next);
	return next;
}
