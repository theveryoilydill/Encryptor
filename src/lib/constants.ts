/**
 * Shared constants for the whole app — single source of truth (DRY).
 */
export const BRAND = {
	/** Keybase blue — the app's accent color. */
	accent: "#0055dc",
	accentSoft: "#0055dc/10",
} as const;

export const LIMITS = {
	/** Hard cap per attached file in the envelope. */
	maxFileBytes: 25 * 1024 * 1024,
	maxFileLabel: "25 MB",
	/** Keybase lookup / key-id fetch caps enforced by the API routes. */
	maxUsernamesPerRequest: 50,
	maxKeyIDsPerRequest: 50,
} as const;

export const STORAGE_KEYS = {
	config: "encryptor.config.v1",
	/** Ring of previously configured keys (metadata + encrypted armor) for
	 *  one-click switching — see lib/pgp/key-history.ts. */
	keyHistory: "encryptor.keyHistory.v1",
	/** Per-fingerprint dismissal of the post-quantum onboarding banner. */
	pqBannerDismissed: "encryptor.pq-banner-dismissed",
	includeSelf: "encryptor.include-self.v1",
	lastTab: "encryptor.lastTab",
	recentRecipients: "encryptor.recentRecipients",
	settings: "encryptor.settings.v1",
} as const;

/** Shared Keybase username grammar (2–15 chars: a-z, 0-9, _). */
export const KEYBASE_USERNAME_RE = /^[a-z0-9_]{2,15}$/;
