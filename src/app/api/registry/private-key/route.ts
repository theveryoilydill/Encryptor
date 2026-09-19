import { NextRequest, NextResponse } from "next/server";

import { LIMITS } from "@/lib/constants";
import {
	RegistryError,
	auditSafe,
	getRegistryDBReady,
	nowSeconds,
	enforceRateLimit,
} from "@/lib/registry/db";
import {
	normalizeFingerprint,
	parseEncryptedPrivateArmored,
	verifyChallengeSignature,
} from "@/lib/registry/keys";
import {
	assertWriteOrigin,
	clientIP,
	readJsonBody,
	registryErrorResponse,
	stringField,
} from "@/lib/registry/routes";
import { requireTurnstile } from "@/lib/registry/turnstile";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/**
 * POST /api/registry/private-key — manage the ESCROWED encrypted private key
 * of an already-published key.
 *
 * Storing or deleting requires proof of possession: a one-time nonce from
 * /api/registry/challenge, cleartext-signed with the CURRENT private key.
 * The uploaded blob must be an armored private key whose secret packets are
 * ALL passphrase-encrypted (parseEncryptedPrivateArmored enforces this and
 * binds it to the exact fingerprint), so the database never receives usable
 * private key bytes.
 *
 * Body (store):    { "fingerprint": "...", "nonce": "...", "signature": "...",
 *                    "encryptedPrivate": "<armored encrypted private key>",
 *                    "turnstileToken": "..." (when Turnstile is enforced) }
 * Body (delete):   { "fingerprint": "...", "nonce": "...", "signature": "..." }
 *                    — no encryptedPrivate field means "remove the escrow".
 */
export async function POST(req: NextRequest) {
	try {
		assertWriteOrigin(req); // origin write-lock BEFORE any D1 access
		const db = await getRegistryDBReady();
		await enforceRateLimit(
			db,
			"private-key",
			clientIP(req),
			LIMITS.registryPrivateKeyLimit,
			LIMITS.registryPrivateKeyWindowSec,
			"Too many private-key requests — try again later",
		);

		const body = await readJsonBody(req);
		const rawFpr = stringField(body, "fingerprint", 64);
		if (!rawFpr) throw new RegistryError("The 'fingerprint' field is required", 400);
		const fingerprint = normalizeFingerprint(rawFpr);
		if (!fingerprint) throw new RegistryError("fingerprint must be 40 hex characters", 400);
		const nonce = stringField(body, "nonce", 128);
		const signature = stringField(body, "signature", 16 * 1024);
		if (!nonce || !signature) {
			throw new RegistryError(
				"Authorization required — fetch a challenge from /api/registry/challenge and sign it with the stored key (send nonce + signature).",
				403,
			);
		}

		const key = await db
			.prepare("SELECT revoked, armored FROM registry_keys WHERE fingerprint = ?1")
			.bind(fingerprint)
			.first<{ revoked: number; armored: string }>();
		if (!key) throw new RegistryError("Key not found", 404);
		if (key.revoked === 1) {
			throw new RegistryError("This fingerprint is revoked", 409);
		}

		// Consume the nonce FIRST (atomic delete scoped to THIS fingerprint),
		// mirroring the publish/revoke routes: challenges are single-use and
		// can never authorize a mutation of a different key.
		const consumed = await db
			.prepare(
				"DELETE FROM registry_challenges WHERE nonce = ?1 AND fingerprint = ?2 AND expires_at > ?3",
			)
			.bind(nonce, fingerprint, nowSeconds())
			.run();
		if (!consumed.meta || Number(consumed.meta.changes ?? 0) === 0) {
			throw new RegistryError("Challenge is invalid, expired, or already used", 403);
		}
		const ok = await verifyChallengeSignature(key.armored, fingerprint, nonce, signature);
		if (!ok) {
			throw new RegistryError("Challenge signature is invalid", 403);
		}

		const encryptedPrivate = stringField(
			body,
			"encryptedPrivate",
			LIMITS.registryMaxPrivateArmorBytes,
		);
		if (encryptedPrivate) {
			// Storing a NEW escrow blob is a database write, so it is
			// Turnstile-gated like publishing (deletion stays open to the
			// key owner — it only removes bytes and cannot create spam).
			await requireTurnstile(
				typeof body.turnstileToken === "string" ? body.turnstileToken : undefined,
				clientIP(req),
			);
			const parsed = await parseEncryptedPrivateArmored(
				encryptedPrivate,
				LIMITS.registryMaxPrivateArmorBytes,
				fingerprint,
			);
			await db
				.prepare(
					"UPDATE registry_keys SET encrypted_private = ?2, private_updated_at = ?3, updated_at = ?3 WHERE fingerprint = ?1 AND revoked = 0",
				)
				.bind(fingerprint, parsed.armored, nowSeconds())
				.run();
			await auditSafe(db, "private-store", fingerprint, null);
			return NextResponse.json(
				{ ok: true, fingerprint, escrowed: true },
				{ headers: { "Cache-Control": "no-store" } },
			);
		}

		await db
			.prepare(
				"UPDATE registry_keys SET encrypted_private = NULL, private_updated_at = NULL, updated_at = ?2 WHERE fingerprint = ?1 AND revoked = 0",
			)
			.bind(fingerprint, nowSeconds())
			.run();
		await auditSafe(db, "private-delete", fingerprint, null);
		return NextResponse.json(
			{ ok: true, fingerprint, escrowed: false },
			{ headers: { "Cache-Control": "no-store" } },
		);
	} catch (e) {
		return registryErrorResponse(e);
	}
}

/**
 * GET /api/registry/private-key?fingerprint=<40 hex>
 *
 * Returns the ESCROWED encrypted private key for offline restoration. The
 * blob is ciphertext end-to-end: it is only decryptable with the owner's
 * passphrase via OpenPGP's iterated S2K, so possession of the blob alone
 * grants nothing. Responses are never cached and the endpoint is rate
 * limited (30/h/IP) to slow offline passphrase-guessing pipelines.
 */
export async function GET(req: NextRequest) {
	try {
		const url = new URL(req.url);
		const raw = url.searchParams.get("fingerprint");
		if (!raw) throw new RegistryError("Missing 'fingerprint' query parameter", 400);
		const fingerprint = normalizeFingerprint(raw);
		if (!fingerprint) throw new RegistryError("fingerprint must be 40 hex characters", 400);

		const db = await getRegistryDBReady();
		await enforceRateLimit(
			db,
			"private-key-read",
			clientIP(req),
			LIMITS.registryPrivateKeyLimit,
			LIMITS.registryPrivateKeyWindowSec,
			"Too many private-key requests — try again later",
		);

		const row = await db
			.prepare(
				"SELECT encrypted_private, private_updated_at FROM registry_keys WHERE fingerprint = ?1",
			)
			.bind(fingerprint)
			.first<{ encrypted_private: string | null; private_updated_at: number | null }>();
		if (!row) throw new RegistryError("Key not found", 404);

		return NextResponse.json(
			{
				fingerprint,
				encryptedPrivate: row.encrypted_private,
				updatedAt: row.private_updated_at,
			},
			{ headers: { "Cache-Control": "no-store" } },
		);
	} catch (e) {
		return registryErrorResponse(e);
	}
}
