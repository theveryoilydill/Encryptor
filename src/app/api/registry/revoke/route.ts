import { NextRequest, NextResponse } from "next/server";

import { LIMITS } from "@/lib/constants";
import {
	RegistryError,
	auditSafe,
	getCloudflareEnv,
	getRegistryDBReady,
	nowSeconds,
	rateLimitSafe,
	sha256Hex,
	timingSafeHexEqual,
} from "@/lib/registry/db";
import { normalizeFingerprint, verifyChallengeSignature } from "@/lib/registry/keys";
import {
	clientIP,
	readJsonBody,
	registryErrorResponse,
	sanitizeReason,
	stringField,
} from "@/lib/registry/routes";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/**
 * POST /api/registry/revoke — retract a published key (permanent).
 *
 * Three authorized paths, checked in order of least privilege:
 *
 * 1. Offline revocation token (from publish):
 *      { "fingerprint": "...", "token": "...", "reason": "optional" }
 *    Works WITHOUT the private key — the emergency brake when a machine
 *    or the key itself is compromised. Tokens are only stored as hashes.
 *
 * 2. Key-signed challenge (possession proof):
 *      { "fingerprint": "...", "nonce": "...", "signature": "...", "reason": "..." }
 *    The nonce from /api/registry/challenge signed by the stored private
 *    key. Consumes the nonce (one-time).
 *
 * 3. Admin override (service-compromise / abuse response):
 *      { "fingerprint": "...", "adminToken": "...", "reason": "..." }
 *    ADMIN_REVOKE_TOKEN env secret, compared timing-safely.
 *
 * Revocation is PERMANENT: lookups keep returning the record with
 * revoked: true so clients learn the key must not be used, and
 * re-publishing the same fingerprint is refused.
 */
export async function POST(req: NextRequest) {
	try {
		const db = await getRegistryDBReady();
		if (
			!(await rateLimitSafe(
				db,
				"revoke",
				clientIP(req),
				LIMITS.registryRevokeLimit,
				LIMITS.registryRevokeWindowSec,
				false,
			))
		) {
			throw new RegistryError("Too many revoke requests — try again later", 429);
		}

		const body = await readJsonBody(req);
		const rawFpr = stringField(body, "fingerprint", 64);
		if (!rawFpr) throw new RegistryError("The 'fingerprint' field is required", 400);
		const fingerprint = normalizeFingerprint(rawFpr);
		if (!fingerprint) throw new RegistryError("fingerprint must be 40 hex characters", 400);
		const reason = sanitizeReason(stringField(body, "reason", LIMITS.registryMaxReasonChars));

		const key = await db
			.prepare("SELECT revoked, token_hash FROM registry_keys WHERE fingerprint = ?1")
			.bind(fingerprint)
			.first<{ revoked: number; token_hash: string }>();
		if (!key) throw new RegistryError("Key not found", 404);
		if (key.revoked === 1) {
			return NextResponse.json(
				{ ok: true, alreadyRevoked: true },
				{ headers: { "Cache-Control": "no-store" } },
			);
		}

		const viaToken = await revokeByToken(db, body, key.token_hash, fingerprint, reason);
		if (viaToken) return viaToken;

		const viaSignature = await revokeBySignature(db, body, fingerprint, reason);
		if (viaSignature) return viaSignature;

		const viaAdmin = await revokeByAdmin(db, body, fingerprint, reason);
		if (viaAdmin) return viaAdmin;

		throw new RegistryError(
			"Authorization failed — provide a valid revocation token, a signed challenge, or an admin token",
			403,
		);
	} catch (e) {
		return registryErrorResponse(e);
	}
}

type RevokeResult = NextResponse | null;

async function revokeByToken(
	db: Awaited<ReturnType<typeof getRegistryDBReady>>,
	body: Record<string, unknown>,
	tokenHash: string,
	fingerprint: string,
	reason: string | null,
): Promise<RevokeResult> {
	const token = stringField(body, "token", 128);
	if (!token) return null;
	const providedHash = await sha256Hex(token);
	if (!timingSafeHexEqual(providedHash, tokenHash)) {
		throw new RegistryError("Invalid revocation token", 403);
	}
	await markRevoked(db, fingerprint, reason);
	await auditSafe(db, "revoke-token", fingerprint, "offline token");
	return NextResponse.json(
		{ ok: true, via: "token" },
		{ headers: { "Cache-Control": "no-store" } },
	);
}

async function revokeBySignature(
	db: Awaited<ReturnType<typeof getRegistryDBReady>>,
	body: Record<string, unknown>,
	fingerprint: string,
	reason: string | null,
): Promise<RevokeResult> {
	const nonce = stringField(body, "nonce", 128);
	const signature = stringField(body, "signature", 16 * 1024);
	if (!nonce || !signature) return null;

	// Consume the nonce FIRST (atomic delete) so a replayed request — even
	// one racing itself — can never pass twice.
	const consumed = await db
		.prepare(
			"DELETE FROM registry_challenges WHERE nonce = ?1 AND fingerprint = ?2 AND expires_at > ?3",
		)
		.bind(nonce, fingerprint, nowSeconds())
		.run();
	if (!consumed.meta || Number(consumed.meta.changes ?? 0) === 0) {
		throw new RegistryError("Challenge is invalid, expired, or already used", 403);
	}

	const row = await db
		.prepare("SELECT armored FROM registry_keys WHERE fingerprint = ?1")
		.bind(fingerprint)
		.first<{ armored: string }>();
	if (!row) throw new RegistryError("Key not found", 404);

	const valid = await verifyChallengeSignature(row.armored, fingerprint, nonce, signature);
	if (!valid) {
		throw new RegistryError("Challenge signature is invalid", 403);
	}
	await markRevoked(db, fingerprint, reason);
	await auditSafe(db, "revoke-signed", fingerprint, "key-signed challenge");
	return NextResponse.json(
		{ ok: true, via: "signature" },
		{ headers: { "Cache-Control": "no-store" } },
	);
}

async function revokeByAdmin(
	db: Awaited<ReturnType<typeof getRegistryDBReady>>,
	body: Record<string, unknown>,
	fingerprint: string,
	reason: string | null,
): Promise<RevokeResult> {
	const adminToken = stringField(body, "adminToken", 256);
	if (!adminToken) return null;
	const env = getCloudflareEnv();
	const expected = env?.ADMIN_REVOKE_TOKEN;
	// Unconfigured deployments fall through to the generic 403 below — an
	// unauthenticated caller must never be able to trigger a 5xx or learn
	// configuration state.
	if (!expected) return null;
	const ok = timingSafeHexEqual(await sha256Hex(adminToken), await sha256Hex(expected));
	if (!ok) {
		throw new RegistryError("Invalid admin token", 403);
	}
	await markRevoked(db, fingerprint, reason);
	await auditSafe(db, "revoke-admin", fingerprint, "admin override");
	return NextResponse.json(
		{ ok: true, via: "admin" },
		{ headers: { "Cache-Control": "no-store" } },
	);
}

/**
 * Flip the revoked flag permanently, drop any live challenge nonces, purge
 * the escrowed encrypted private key, and RELEASE the email + subkey
 * indexes. Revocation stays visible by fingerprint lookup; releasing the
 * indexes frees scarce namespaces (email claims, 64-bit key IDs). A revoked
 * record keeps only its public revocation information — escrowed private
 * material must not outlive an active key.
 */
async function markRevoked(
	db: Awaited<ReturnType<typeof getRegistryDBReady>>,
	fingerprint: string,
	reason: string | null,
): Promise<void> {
	await db.batch([
		db
			.prepare(
				"UPDATE registry_keys SET revoked = 1, revoked_at = ?2, revoke_reason = ?3, encrypted_private = NULL, private_updated_at = NULL, updated_at = ?2 WHERE fingerprint = ?1",
			)
			.bind(fingerprint, nowSeconds(), reason),
		db.prepare("DELETE FROM registry_challenges WHERE fingerprint = ?1").bind(fingerprint),
		db.prepare("DELETE FROM registry_emails WHERE fingerprint = ?1").bind(fingerprint),
		db.prepare("DELETE FROM registry_subkeys WHERE fingerprint = ?1").bind(fingerprint),
	]);
}
