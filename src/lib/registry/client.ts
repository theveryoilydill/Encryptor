/**
 * Browser client for the public key registry (/api/registry/*).
 *
 * One place for request shapes and error text. Challenges are signed
 * in-browser via lib/pgp signMessage — the passphrase and decrypted key
 * never leave this module's call scope.
 *
 * Simplified for the login-gate UI (PR #25 review round): the "my published
 * keys" bookkeeping, backup import/export, watch layer, and the admin
 * revoke helper are gone — publishing now lives in the Encryptor Registry
 * login card, which surfaces the one-time revocation token at publish time.
 * Admin revocation remains a BACKEND-ONLY path (ADMIN_REVOKE_TOKEN via
 * curl/wrangler) per the owner's request to keep it out of the public UI.
 *
 * # Mr. AI Acting on s183173's Behalf
 */
import { signMessage } from "@/lib/pgp/pgp";

/** One key record as returned by the public lookup endpoint. */
export interface RegistryLookupKey {
	fingerprint: string;
	armored: string;
	revoked: boolean;
	revokedAt: number | null;
	revokeReason: string | null;
	createdAt: number;
	updatedAt: number;
	/** Base64 ML-KEM-768 public key when the owner published a quantum-seal
	 *  pair — lets correspondents seal archive copies to this key. */
	pqSealPk?: string | null;
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
	/** False when D1 writes fail while reads work (quota/full/account) —
	 *  every mutation route will 503 until the operator intervenes. */
	limiterWrite?: boolean;
	/** Always true since migration 0004 (self-provisioned salt); kept for
	 *  dashboard compatibility. See saltSource for how it was provisioned. */
	saltConfigured?: boolean;
	/** "env" = the RE_SALT secret was adopted on first boot; "generated" =
	 *  a random CSPRNG salt was provisioned automatically. */
	saltSource?: "env" | "generated";
	schema?: { applied: string[]; pending: string[] };
	turnstile?: "enforced" | "disabled";
	/** REGISTRY_PROD_ORIGIN when configured (null = writes unlocked). */
	writesLockedTo?: string | null;
	/** Whether THIS deployment (request host) may mutate under the lock. */
	writesAllowedHere?: boolean;
	error?: string;
}

/**
 * GET /api/registry/health — schema + capability probe. Hitting it also
 * triggers the worker's self-migration (and salt provisioning), so a fresh
 * remote D1 database heals simply by checking health.
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
	/** ML-KEM-768 public key (base64) stored with the record (optional). */
	pqSealPk?: string;
	/** Cloudflare Turnstile token; required on deployments that enforce it. */
	turnstileToken?: string;
	/** Possession proof for REPLACING an already-published fingerprint:
	 *  nonce from GET /api/registry/challenge + cleartext signature of the
	 *  canonical challenge message made with the stored key's private half. */
	nonce?: string;
	signature?: string;
}): Promise<RegistryPublishResult> {
	const res = await fetch("/api/registry/publish", {
		method: "POST",
		headers: { "Content-Type": "application/json" },
		body: JSON.stringify({
			armored: input.armored,
			...(input.encryptedPrivate ? { encryptedPrivate: input.encryptedPrivate } : {}),
			...(input.pqSealPk ? { pqSealPk: input.pqSealPk } : {}),
			...(input.turnstileToken ? { turnstileToken: input.turnstileToken } : {}),
			...(input.nonce && input.signature ? { nonce: input.nonce, signature: input.signature } : {}),
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
