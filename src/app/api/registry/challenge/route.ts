import { NextRequest, NextResponse } from "next/server";

import { LIMITS } from "@/lib/constants";
import {
	RegistryError,
	auditSafe,
	getRegistryDB,
	nowSeconds,
	randomHex,
	rateLimitSafe,
} from "@/lib/registry/db";
import { challengeMessage, normalizeFingerprint } from "@/lib/registry/keys";
import { clientIP, registryErrorResponse } from "@/lib/registry/routes";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/**
 * GET /api/registry/challenge?fingerprint=<40 hex>
 *
 * Issues a one-time nonce (10 minute TTL) that must be cleartext-signed
 * with the CURRENTLY stored private key and posted to /api/registry/revoke
 * (token-less revocation) or /api/registry/publish (authorized replacement).
 * Nonces are single-use: the signed replay is rejected because the row is
 * consumed on first successful use.
 */
export async function GET(req: NextRequest) {
	try {
		const db = getRegistryDB();
		if (
			!(await rateLimitSafe(
				db,
				"challenge",
				clientIP(req),
				LIMITS.registryChallengeLimit,
				LIMITS.registryChallengeWindowSec,
				false,
			))
		) {
			throw new RegistryError("Too many challenge requests — try again later", 429);
		}

		const url = new URL(req.url);
		const raw = url.searchParams.get("fingerprint");
		if (!raw) throw new RegistryError("Missing 'fingerprint' query parameter", 400);
		const fingerprint = normalizeFingerprint(raw);
		if (!fingerprint) throw new RegistryError("fingerprint must be 40 hex characters", 400);

		const key = await db
			.prepare("SELECT revoked FROM registry_keys WHERE fingerprint = ?1")
			.bind(fingerprint)
			.first<{ revoked: number }>();
		if (!key) throw new RegistryError("Key not found", 404);
		if (key.revoked === 1) throw new RegistryError("Key is already revoked", 409);

		const now = nowSeconds();
		// Purge ONLY expired nonces (indexed on expires_at). Live nonces are
		// never swept here: deleting a victim's outstanding nonce would hand
		// anyone who can fetch challenges a nuisance invalidation vector.
		// Live rows stay bounded by the 10-minute TTL + per-IP rate limit.
		await db.prepare("DELETE FROM registry_challenges WHERE expires_at < ?1").bind(now).run();

		const nonce = randomHex(32);
		const expiresAt = now + LIMITS.registryChallengeTtlSec;
		await db
			.prepare(
				"INSERT INTO registry_challenges (nonce, fingerprint, created_at, expires_at) VALUES (?1, ?2, ?3, ?4)",
			)
			.bind(nonce, fingerprint, now, expiresAt)
			.run();
		await auditSafe(db, "challenge", fingerprint, null);

		return NextResponse.json(
			{ fingerprint, nonce, expiresAt, message: challengeMessage(fingerprint, nonce) },
			{ headers: { "Cache-Control": "no-store" } },
		);
	} catch (e) {
		return registryErrorResponse(e);
	}
}
