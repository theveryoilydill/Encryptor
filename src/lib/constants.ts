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
	/** Key registry caps (server-enforced, see src/lib/registry). */
	registryMaxArmorBytes: 64 * 1024,
	registryMaxEmails: 10,
	registryMaxLookupResults: 10,
	registryMaxReasonChars: 200,
	registryMaxBodyBytes: 192 * 1024,
	/** Escrowed ENCRYPTED private keys (passphrase-protected backups). */
	registryMaxPrivateArmorBytes: 64 * 1024,
	registryPrivateKeyLimit: 30,
	registryPrivateKeyWindowSec: 3600,
	/** Fixed-window rate limits per client IP (window = seconds). */
	registryPublishLimit: 5,
	registryPublishWindowSec: 3600,
	registryChallengeLimit: 10,
	registryChallengeWindowSec: 3600,
	registryRevokeLimit: 10,
	registryRevokeWindowSec: 3600,
	registryLookupLimit: 120,
	registryLookupWindowSec: 3600,
	/** Challenge nonces expire after this many seconds (one-time use). */
	registryChallengeTtlSec: 600,
	/** Email-squatting budget: max keys claiming one email address. */
	registryMaxKeysPerEmail: 5,
	/** Hard cap on stored keys (free-tier storage budget guard). */
	registryStorageCapKeys: 50000,
} as const;

export const STORAGE_KEYS = {
	config: "encryptor.config.v1",
	includeSelf: "encryptor.include-self.v1",
	lastTab: "encryptor.lastTab",
	recentRecipients: "encryptor.recentRecipients",
	settings: "encryptor.settings.v1",
	tourDone: "encryptor.tour.done.v1",
} as const;

/** Shared Keybase username grammar (2–15 chars: a-z, 0-9, _). */
export const KEYBASE_USERNAME_RE = /^[a-z0-9_]{2,15}$/;
