/**
 * Browser client for the public key registry (/api/registry/*).
 *
 * One place for request shapes, error text, and the local "my published
 * keys" bookkeeping so the Keys tab stays declarative. Challenges are
 * signed in-browser via lib/pgp signMessage — the passphrase and decrypted
 * key never leave this module's call scope.
 *
 * # Mr. AI Acting on s183173's Behalf
 */
import { STORAGE_KEYS } from "@/lib/constants";
import { signMessage } from "@/lib/pgp/pgp";
import { getKeySighting, noteKeySighted } from "@/lib/registry/watch";

/** One key record as returned by the public lookup endpoint. */
export interface RegistryLookupKey {
	fingerprint: string;
	armored: string;
	revoked: boolean;
	revokedAt: number | null;
	revokeReason: string | null;
	createdAt: number;
	updatedAt: number;
}

/** Response of POST /api/registry/publish. */
export interface RegistryPublishResult {
	fingerprint: string;
	keyId: string;
	subkeyIds: string[];
	emails: string[];
	replaced: boolean;
	revocationToken?: string;
	warning?: string;
}

/** Locally persisted metadata for a key this browser published. */
export interface MyRegistryKey {
	fingerprint: string;
	keyId: string;
	emails: string[];
	label: string;
	publishedAt: number;
	/** Shown-once revocation token, kept here because offline copies can
            be lost; the registry only stores its SHA-256 hash. */
	revocationToken?: string;
	escrowed: boolean;
	/** Human algorithm label captured at publish time (e.g. "Ed25519",
	 *  "RSA · 3072-bit") so the list can badge keys without re-parsing
	 *  armor from the network. Absent on pre-existing local records. */
	algo?: string;
	/** Last local change to this record (publish/replace/escrow update). */
	updatedAt?: number;
}

/** Thrown for non-2xx registry responses; carries the server's error text. */
export class RegistryClientError extends Error {
	status: number;
	/** Seconds until the rate-limit window rolls over (429s only, from
	 *  the server's Retry-After header); null for every other status. */
	retryAfterSeconds: number | null;
	constructor(message: string, status: number, retryAfterSeconds: number | null = null) {
		super(message);
		this.name = "RegistryClientError";
		this.status = status;
		this.retryAfterSeconds = retryAfterSeconds;
	}
}

/**
 * Human-friendly message for any registry failure. Rate-limited requests
 * surface the exact retry horizon ("resets in 42s") instead of an opaque
 * "try again later", and cap the precision to keep the UI calm.
 */
export function formatRegistryError(e: unknown, fallback: string): string {
	if (e instanceof RegistryClientError) {
		if (e.status === 429 && e.retryAfterSeconds != null) {
			const s = e.retryAfterSeconds;
			const when =
				s < 90
					? `resets in ${s}s`
					: s < 3600
						? `resets in ${Math.ceil(s / 60)} min`
						: `resets in ${Math.ceil(s / 3600)} h`;
			return `${e.message} (${when}).`;
		}
		return e.message;
	}
	return e instanceof Error ? e.message : fallback;
}

async function parseJson(res: Response): Promise<Record<string, unknown>> {
	try {
		return (await res.json()) as Record<string, unknown>;
	} catch {
		throw new RegistryClientError("Registry returned a non-JSON response", res.status);
	}
}

async function expectOk(res: Response, fallback: string): Promise<Record<string, unknown>> {
	const body = await parseJson(res);
	if (!res.ok) {
		const message = typeof body.error === "string" ? body.error : fallback;
		// 429s carry Retry-After (seconds) so the UI can show a live
		// back-off horizon instead of a dead end.
		const retryHeader = res.headers.get("Retry-After");
		const retryAfterSeconds =
			res.status === 429 && retryHeader && /^\d{1,6}$/.test(retryHeader)
				? Number(retryHeader)
				: null;
		throw new RegistryClientError(message, res.status, retryAfterSeconds);
	}
	return body;
}

/** Health probe result from GET /api/registry/health. */
export interface RegistryHealth {
	ok: boolean;
	db: boolean;
	schema?: { applied: string[]; pending: string[] };
	turnstile?: "enforced" | "disabled";
	error?: string;
}

/**
 * GET /api/registry/health — schema + capability probe. Hitting it also
 * triggers the worker's self-migration, so a fresh (never migrated) remote
 * D1 database heals simply by checking health.
 */
export async function registryHealth(): Promise<RegistryHealth> {
	const res = await fetch("/api/registry/health", { cache: "no-store" });
	return parseJson(res) as unknown as Promise<RegistryHealth>;
}

/** GET /api/registry/lookup — accepts fingerprint, key ID, or email. */
export async function registryLookup(query: {
	fingerprint?: string;
	keyId?: string;
	email?: string;
}): Promise<RegistryLookupKey[]> {
	const params = new URLSearchParams();
	if (query.fingerprint) params.set("fingerprint", query.fingerprint);
	else if (query.keyId) params.set("key_id", query.keyId);
	else if (query.email) params.set("email", query.email);
	const res = await fetch(`/api/registry/lookup?${params.toString()}`);
	const body = await expectOk(res, "Lookup failed");
	return (body.keys as RegistryLookupKey[]) ?? [];
}

/** POST /api/registry/publish — publish a public key (escrow optional). */
export async function registryPublish(input: {
	armored: string;
	encryptedPrivate?: string;
	/** Cloudflare Turnstile token; required on deployments that enforce it. */
	turnstileToken?: string;
}): Promise<RegistryPublishResult> {
	const res = await fetch("/api/registry/publish", {
		method: "POST",
		headers: { "Content-Type": "application/json" },
		body: JSON.stringify({
			armored: input.armored,
			...(input.encryptedPrivate ? { encryptedPrivate: input.encryptedPrivate } : {}),
			...(input.turnstileToken ? { turnstileToken: input.turnstileToken } : {}),
		}),
	});
	const body = await expectOk(res, "Publish failed");
	return body as unknown as RegistryPublishResult;
}

/** GET /api/registry/challenge — one-time nonce for possession proofs. */
export async function registryChallenge(fingerprint: string): Promise<{
	nonce: string;
	message: string;
	expiresAt: number;
}> {
	const res = await fetch(`/api/registry/challenge?fingerprint=${encodeURIComponent(fingerprint)}`);
	const body = await expectOk(res, "Could not fetch a challenge");
	return body as unknown as { nonce: string; message: string; expiresAt: number };
}

/**
 * The canonical challenge message — MUST byte-match the server's
 * challengeMessage() in src/lib/registry/keys.ts (the e2e suite also
 * mirrors it; keep all three in sync).
 */
function challengeMessage(fingerprint: string, nonce: string): string {
	return `encryptor key registry\naction: prove-key-possession\nfingerprint: ${fingerprint}\nnonce: ${nonce}\n`;
}

/** Cleartext-sign the canonical challenge message with a private key. */
export function signChallenge(
	privateKeyArmored: string,
	passphrase: string,
	fingerprint: string,
	nonce: string,
): Promise<string> {
	return signMessage({
		plaintext: challengeMessage(fingerprint, nonce),
		privateKey: privateKeyArmored,
		passphrase,
		detached: false,
	});
}

/** GET /api/registry/private-key — fetch the escrowed blob (null when none). */
export async function registryFetchEscrow(fingerprint: string): Promise<{
	fingerprint: string;
	encryptedPrivate: string | null;
	updatedAt: number | null;
}> {
	const res = await fetch(
		`/api/registry/private-key?fingerprint=${encodeURIComponent(fingerprint)}`,
	);
	const body = await expectOk(res, "Escrow fetch failed");
	return body as unknown as {
		fingerprint: string;
		encryptedPrivate: string | null;
		updatedAt: number | null;
	};
}

/** POST /api/registry/private-key — store (encryptedPrivate) or delete escrow. */
async function registryMutateEscrow(input: {
	fingerprint: string;
	privateKeyArmored: string;
	passphrase: string;
	encryptedPrivate?: string;
	turnstileToken?: string;
}): Promise<void> {
	const challenge = await registryChallenge(input.fingerprint);
	const signature = await signChallenge(
		input.privateKeyArmored,
		input.passphrase,
		input.fingerprint,
		challenge.nonce,
	);
	const res = await fetch("/api/registry/private-key", {
		method: "POST",
		headers: { "Content-Type": "application/json" },
		body: JSON.stringify({
			fingerprint: input.fingerprint,
			nonce: challenge.nonce,
			signature,
			...(input.encryptedPrivate ? { encryptedPrivate: input.encryptedPrivate } : {}),
			...(input.turnstileToken ? { turnstileToken: input.turnstileToken } : {}),
		}),
	});
	await expectOk(res, "Escrow update failed");
}

export function registryStoreEscrow(input: {
	fingerprint: string;
	privateKeyArmored: string;
	passphrase: string;
	encryptedPrivate: string;
}): Promise<void> {
	return registryMutateEscrow({ ...input });
}

export function registryDeleteEscrow(input: {
	fingerprint: string;
	privateKeyArmored: string;
	passphrase: string;
}): Promise<void> {
	return registryMutateEscrow({ ...input });
}

/** POST /api/registry/revoke — permanent retraction via the offline token. */
export async function registryRevokeByToken(
	fingerprint: string,
	token: string,
	reason?: string,
): Promise<void> {
	const res = await fetch("/api/registry/revoke", {
		method: "POST",
		headers: { "Content-Type": "application/json" },
		body: JSON.stringify({ fingerprint, token, ...(reason ? { reason } : {}) }),
	});
	const body = await expectOk(res, "Revocation failed");
	if (body.alreadyRevoked === true) return;
}

/* ------------------------- local "my keys" bookkeeping ------------------------ */

export function listMyKeys(): MyRegistryKey[] {
	try {
		const raw = localStorage.getItem(STORAGE_KEYS.registryKeys);
		if (!raw) return [];
		const parsed = JSON.parse(raw);
		return Array.isArray(parsed) ? (parsed as MyRegistryKey[]) : [];
	} catch {
		return [];
	}
}

function saveMyKeys(keys: MyRegistryKey[]): void {
	try {
		localStorage.setItem(STORAGE_KEYS.registryKeys, JSON.stringify(keys));
	} catch {
		// Storage may be unavailable (private mode); the registry state
		// lives server-side, this list is only a convenience.
	}
}

/** Fingerprints must match case-insensitively: the registry/backup use
 *  mixed-case hex, and treating "ABC…" and "abc…" as two keys would
 *  duplicate rows and strand revocation tokens on the wrong record. */
function sameFpr(a: string, b: string): boolean {
	return a.toLowerCase() === b.toLowerCase();
}

export function rememberMyKey(key: MyRegistryKey): void {
	const keys = listMyKeys().filter((k) => !sameFpr(k.fingerprint, key.fingerprint));
	saveMyKeys([key, ...keys].slice(0, 50));
}

export function updateMyKey(
	fingerprint: string,
	patch: Partial<
		Pick<MyRegistryKey, "escrowed" | "revocationToken" | "label" | "algo" | "updatedAt">
	>,
): void {
	saveMyKeys(
		listMyKeys().map((k) => (sameFpr(k.fingerprint, fingerprint) ? { ...k, ...patch } : k)),
	);
}

export function forgetMyKey(fingerprint: string): void {
	saveMyKeys(listMyKeys().filter((k) => !sameFpr(k.fingerprint, fingerprint)));
}

/**
 * Build a portable JSON backup of the locally-known published keys.
 *
 * Revocation tokens are the ONE thing the registry cannot recover (only
 * their hash is stored server-side), so the backup deliberately includes
 * them: an offline copy is the emergency brake for every key this browser
 * published. Everything in the file is already on this device — exporting
 * leaks nothing new, but the FILE must be stored carefully (tokens grant
 * revocation power).
 */
export function exportMyKeys(): string {
	return JSON.stringify(
		{
			format: "encryptor-keys-backup",
			version: 1,
			exportedAt: new Date().toISOString(),
			keys: listMyKeys(),
		},
		null,
		2,
	);
}

/* --------------------------- backup import/restore -------------------------- */

/** Result of validating a backup file's contents. */
export interface ParsedBackup {
	/** ISO timestamp copied from the file, when present. */
	exportedAt: string | null;
	/** Structurally valid records, fingerprints normalized lowercase. */
	keys: MyRegistryKey[];
	/** Entries dropped because they failed structural validation. */
	invalid: number;
}

const FPR_RE = /^[0-9a-f]{40}$/;

/** Coerce one raw backup entry into a MyRegistryKey, or null if unusable. */
function sanitizeBackupKey(raw: unknown): MyRegistryKey | null {
	if (!raw || typeof raw !== "object") return null;
	const r = raw as Record<string, unknown>;
	const fpr = typeof r.fingerprint === "string" ? r.fingerprint.trim().toLowerCase() : "";
	if (!FPR_RE.test(fpr)) return null;
	const emails = Array.isArray(r.emails)
		? r.emails.filter((e): e is string => typeof e === "string" && e.length > 0).slice(0, 10)
		: [];
	const publishedAt =
		typeof r.publishedAt === "number" && Number.isFinite(r.publishedAt)
			? r.publishedAt
			: Date.now();
	return {
		fingerprint: fpr,
		keyId:
			typeof r.keyId === "string" && /^[0-9a-f]{8,16}$/i.test(r.keyId)
				? r.keyId.toUpperCase()
				: fpr.slice(-16).toUpperCase(),
		emails,
		label:
			typeof r.label === "string" && r.label.trim()
				? r.label.trim()
				: (emails[0] ?? "Imported key"),
		publishedAt,
		...(typeof r.revocationToken === "string" && r.revocationToken
			? { revocationToken: r.revocationToken }
			: {}),
		escrowed: r.escrowed === true,
		...(typeof r.algo === "string" && r.algo ? { algo: r.algo } : {}),
		...(typeof r.updatedAt === "number" && Number.isFinite(r.updatedAt)
			? { updatedAt: r.updatedAt }
			: {}),
	};
}

/**
 * Validate a keys-backup file's text. Throws with a human explanation for
 * wrong files (bad JSON, foreign format, unknown version) so the UI can
 * show exactly why a restore was refused; per-entry problems are counted
 * instead of fatal — one corrupt record shouldn't block the other 49.
 */
export function parseKeysBackup(text: string): ParsedBackup {
	let data: unknown;
	try {
		data = JSON.parse(text);
	} catch {
		throw new Error("That file is not valid JSON.");
	}
	if (!data || typeof data !== "object" || Array.isArray(data)) {
		throw new Error("Not an Encryptor keys backup.");
	}
	const d = data as Record<string, unknown>;
	if (d.format !== "encryptor-keys-backup") {
		throw new Error("Not an Encryptor keys backup (missing format marker).");
	}
	if (d.version !== 1) {
		throw new Error(`Unsupported backup version (${String(d.version)}). This app reads version 1.`);
	}
	if (!Array.isArray(d.keys)) throw new Error("Backup has no keys array.");
	const keys: MyRegistryKey[] = [];
	let invalid = 0;
	for (const raw of d.keys.slice(0, 200)) {
		const k = sanitizeBackupKey(raw);
		if (k) keys.push(k);
		else invalid += 1;
	}
	return { exportedAt: typeof d.exportedAt === "string" ? d.exportedAt : null, keys, invalid };
}

export interface RestoreReport {
	added: number;
	updated: number;
	skipped: number;
}

const stampOf = (k: MyRegistryKey): number => k.updatedAt ?? k.publishedAt;

/**
 * Shared merge accounting: applies the newest-wins-by-fingerprint policy to
 * a working map (without touching storage) and reports what happened. Used
 * by both the confirmation-dialog preview and the actual merge so the two
 * can never disagree about what a restore will do.
 */
function accountMerge(
	incoming: MyRegistryKey[],
	current: MyRegistryKey[],
): { map: Map<string, MyRegistryKey>; report: RestoreReport } {
	const byFpr = new Map(current.map((k) => [k.fingerprint.toLowerCase(), k]));
	let added = 0;
	let updated = 0;
	let skipped = 0;
	for (const inc of incoming) {
		const cur = byFpr.get(inc.fingerprint.toLowerCase());
		if (!cur) {
			byFpr.set(inc.fingerprint.toLowerCase(), inc);
			added += 1;
			continue;
		}
		if (stampOf(inc) > stampOf(cur)) {
			byFpr.set(inc.fingerprint, {
				...inc,
				...(inc.revocationToken || !cur.revocationToken
					? {}
					: { revocationToken: cur.revocationToken }),
			});
			updated += 1;
		} else {
			if (!cur.revocationToken && inc.revocationToken) {
				byFpr.set(inc.fingerprint, { ...cur, revocationToken: inc.revocationToken });
			}
			skipped += 1;
		}
	}
	return { map: byFpr, report: { added, updated, skipped } };
}

/**
 * What a restore WOULD do, without mutating anything — shown in the
 * confirmation dialog so "N new · M updated · K already current" is never a
 * guess.
 */
export function previewRestore(incoming: MyRegistryKey[]): RestoreReport {
	return accountMerge(incoming, listMyKeys()).report;
}

/** Apply the merge computed by accountMerge and persist it (cap 50). */
export function mergeMyKeys(incoming: MyRegistryKey[]): RestoreReport {
	const { map, report } = accountMerge(incoming, listMyKeys());
	saveMyKeys([...map.values()].sort((a, b) => stampOf(b) - stampOf(a)).slice(0, 50));
	return report;
}

/* --------------------------- registry status audit -------------------------- */

export type MyKeyAuditOutcome = "ok" | "changed" | "revoked" | "missing" | "error";

export interface MyKeyAudit {
	fingerprint: string;
	outcome: MyKeyAuditOutcome;
	/** Human explanation rendered as the badge tooltip / summary. */
	detail: string;
}

/**
 * Bulk re-verification of the keys this device published: re-fetch each
 * fingerprint from the registry and compare it with the last sighting the
 * watch layer recorded — the same change-detection memory the lookup flow
 * uses, applied to one's own keys. Sequential with a small gap so a full
 * sweep stays friendly to the shared rate bucket; individual failures
 * become "error" rows instead of aborting. Sightings are refreshed as the
 * sweep goes, so the next lookup of the same key won't re-flag.
 */
export async function auditMyKeysOnRegistry(
	keys: MyRegistryKey[],
	opts: { max?: number; onResult?: (a: MyKeyAudit) => void } = {},
): Promise<MyKeyAudit[]> {
	const max = opts.max ?? 12;
	const targets = keys.slice(0, max);
	const results: MyKeyAudit[] = [];
	for (let i = 0; i < targets.length; i += 1) {
		const k = targets[i];
		let audit: MyKeyAudit;
		try {
			const row = (await registryLookup({ fingerprint: k.fingerprint }))[0];
			if (!row) {
				audit = {
					fingerprint: k.fingerprint,
					outcome: "missing",
					detail:
						"Not on the registry — published from another device, purged, or never published.",
				};
			} else {
				const prior = getKeySighting(k.fingerprint);
				noteKeySighted(k.fingerprint, { updatedAt: row.updatedAt, revoked: row.revoked });
				if (row.revoked) {
					audit = {
						fingerprint: k.fingerprint,
						outcome: "revoked",
						detail: row.revokeReason
							? `Revoked on the registry: ${row.revokeReason}`
							: "Revoked on the registry.",
					};
				} else if (prior && (prior.revoked || row.updatedAt > prior.updatedAt)) {
					audit = {
						fingerprint: k.fingerprint,
						outcome: "changed",
						detail: `Key material changed on the registry since ${new Date(prior.seenAt).toLocaleString()} — re-verify out of band.`,
					};
				} else if (prior) {
					audit = {
						fingerprint: k.fingerprint,
						outcome: "ok",
						detail: `Unchanged since ${new Date(prior.seenAt).toLocaleString()}.`,
					};
				} else {
					audit = {
						fingerprint: k.fingerprint,
						outcome: "ok",
						detail: "On the registry and healthy — baseline recorded.",
					};
				}
			}
		} catch (e) {
			audit = {
				fingerprint: k.fingerprint,
				outcome: "error",
				detail: e instanceof Error ? e.message : "Lookup failed.",
			};
		}
		results.push(audit);
		opts.onResult?.(audit);
		if (i < targets.length - 1) await new Promise((r) => setTimeout(r, 150));
	}
	return results;
}
