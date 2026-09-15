import { NextRequest, NextResponse } from "next/server";

import { LIMITS } from "@/lib/constants";
import {
	RegistryError,
	auditSafe,
	getRegistryDB,
	nowSeconds,
	randomHex,
	rateLimit,
	sha256Hex,
} from "@/lib/registry/db";
import { parsePublicArmored, verifyChallengeSignature } from "@/lib/registry/keys";
import { clientIP, readJsonBody, registryErrorResponse, stringField } from "@/lib/registry/routes";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/**
 * POST /api/registry/publish — publish an armored PUBLIC key.
 *
 * Body: { "armored": "<ASCII armored public key>" }
 *     or, to REPLACE an existing key's record:
 *       { "armored": "...", "nonce": "...", "signature": "<cleartext signed>" }
 *       where the signature is made with the CURRENTLY stored private key
 *       over the challenge message for that fingerprint.
 *
 * First publish returns a one-time REVOCATION TOKEN (201). The token is
 * shown once; only its SHA-256 hash is stored. Keep it offline — it is the
 * emergency brake if the private key is ever lost or compromised.
 *
 * Revocation is permanent: a revoked fingerprint can never be re-published
 * (attackers must not be able to resurrect a revoked key by re-upload).
 */

export async function POST(req: NextRequest) {
	try {
		const db = getRegistryDB();
		if (
			!(await rateLimit(
				db,
				"publish",
				clientIP(req),
				LIMITS.registryPublishLimit,
				LIMITS.registryPublishWindowSec,
			))
		) {
			throw new RegistryError("Too many publish requests — try again later", 429);
		}

		const body = await readJsonBody(req);
		const armored = stringField(body, "armored", LIMITS.registryMaxArmorBytes);
		if (!armored) throw new RegistryError("The 'armored' field is required", 400);

		const parsed = await parsePublicArmored(armored, LIMITS.registryMaxArmorBytes);

		const existing = await db
			.prepare("SELECT revoked, armored FROM registry_keys WHERE fingerprint = ?1")
			.bind(parsed.fingerprint)
			.first<{ revoked: number; armored: string }>();

		if (existing) {
			// Replacement requires proving possession of the CURRENT key.
			if (existing.revoked === 1) {
				throw new RegistryError("This fingerprint was revoked and cannot be re-published", 409);
			}
			const nonce = stringField(body, "nonce", 128);
			const signature = stringField(body, "signature", 16 * 1024);
			if (!nonce || !signature) {
				throw new RegistryError(
					"Key already exists. To replace it, fetch a challenge from /api/registry/challenge and sign it with the stored key (send nonce + signature).",
					409,
				);
			}
			// Consume the nonce FIRST (atomic delete scoped to THIS fingerprint)
			// so challenges are single-use and a nonce issued for one key can
			// never authorize a mutation of another key.
			const consumed = await db
				.prepare(
					"DELETE FROM registry_challenges WHERE nonce = ?1 AND fingerprint = ?2 AND expires_at > ?3",
				)
				.bind(nonce, parsed.fingerprint, nowSeconds())
				.run();
			if (!consumed.meta || Number(consumed.meta.changes ?? 0) === 0) {
				throw new RegistryError("Challenge is invalid, expired, or already used", 403);
			}
			const ok = await verifyChallengeSignature(
				existing.armored,
				parsed.fingerprint,
				nonce,
				signature,
			);
			if (!ok) {
				throw new RegistryError("Challenge signature is invalid", 403);
			}
			await replaceKeyRecord(db, parsed);
			await auditSafe(db, "replace", parsed.fingerprint, "authorized by stored key signature");
			return NextResponse.json(
				{
					fingerprint: parsed.fingerprint,
					keyId: parsed.keyId,
					subkeyIds: parsed.subkeyIds,
					emails: parsed.emails,
					replaced: true,
				},
				{ headers: { "Cache-Control": "no-store" } },
			);
		}

		// Fresh publish: generate the one-time revocation token.
		const revocationToken = randomHex(32);
		const tokenHash = await sha256Hex(revocationToken);
		const now = nowSeconds();

		// Email-squatting budget: an email may be claimed by at most N keys
		// (emails are self-reported; lookups must stay bounded and useful).
		for (const email of parsed.emails) {
			const claimed = await db
				.prepare("SELECT COUNT(*) AS n FROM registry_emails WHERE email = ?1")
				.bind(email)
				.first<{ n: number }>();
			if ((claimed?.n ?? 0) >= LIMITS.registryMaxKeysPerEmail) {
				throw new RegistryError(
					"This email address is already associated with the maximum number of keys",
					409,
				);
			}
		}

		// Global storage budget guard (sampled): refuse publishes once the
		// registry reaches a hard cap so free-tier storage cannot be filled.
		if (Math.random() < 0.02) {
			const total = await db
				.prepare("SELECT COUNT(*) AS n FROM registry_keys")
				.first<{ n: number }>();
			if ((total?.n ?? 0) >= LIMITS.registryStorageCapKeys) {
				throw new RegistryError("Registry is at capacity — contact the operator", 503);
			}
		}

		try {
			await db.batch([
				db
					.prepare(
						`INSERT INTO registry_keys
				 (fingerprint, key_id, armored, revoked, token_hash, created_at, updated_at)
				 VALUES (?1, ?2, ?3, 0, ?4, ?5, ?5)`,
					)
					.bind(parsed.fingerprint, parsed.keyId, parsed.armored, tokenHash, now),
				...parsed.subkeyIds.map((id) =>
					db
						.prepare(
							"INSERT INTO registry_subkeys (key_id, fingerprint) VALUES (?1, ?2) ON CONFLICT (key_id) DO NOTHING",
						)
						.bind(id, parsed.fingerprint),
				),
				...parsed.emails.map((email) =>
					db
						.prepare(
							"INSERT INTO registry_emails (email, fingerprint) VALUES (?1, ?2) ON CONFLICT (email, fingerprint) DO NOTHING",
						)
						.bind(email, parsed.fingerprint),
				),
			]);
		} catch (e) {
			// Concurrent first-publish of the same fingerprint loses the PK
			// race — map it to the same 409 a pre-check would give (fail-closed).
			const message = (e as Error).message ?? "";
			if (message.includes("UNIQUE")) {
				throw new RegistryError(
					"Key already exists. To replace it, fetch a challenge from /api/registry/challenge and sign it with the stored key (send nonce + signature).",
					409,
				);
			}
			throw e;
		}
		await auditSafe(
			db,
			"publish",
			parsed.fingerprint,
			`emails:${parsed.emails.length} subkeys:${parsed.subkeyIds.length}`,
		);

		return NextResponse.json(
			{
				fingerprint: parsed.fingerprint,
				keyId: parsed.keyId,
				subkeyIds: parsed.subkeyIds,
				emails: parsed.emails,
				replaced: false,
				revocationToken,
				warning:
					"Store this revocation token offline NOW — it is shown only once and is required to retract the key if you lose access to the private key.",
			},
			{ status: 201, headers: { "Cache-Control": "no-store" } },
		);
	} catch (e) {
		return registryErrorResponse(e);
	}
}

/** Overwrite an existing (non-revoked) record atomically. */
async function replaceKeyRecord(
	db: ReturnType<typeof getRegistryDB>,
	parsed: Awaited<ReturnType<typeof parsePublicArmored>>,
) {
	const now = nowSeconds();
	// `AND revoked = 0` closes the TOCTOU window where a concurrent revocation
	// lands between the earlier read and this write — a revoked record must
	// never be mutated. Subkey/email re-inserts mirror the fresh-publish
	// conflict policy (drop colliding IDs instead of failing the batch).
	await db.batch([
		db
			.prepare(
				`UPDATE registry_keys SET armored = ?2, key_id = ?3, updated_at = ?4
			 WHERE fingerprint = ?1 AND revoked = 0`,
			)
			.bind(parsed.fingerprint, parsed.armored, parsed.keyId, now),
		db.prepare("DELETE FROM registry_subkeys WHERE fingerprint = ?1").bind(parsed.fingerprint),
		db.prepare("DELETE FROM registry_emails WHERE fingerprint = ?1").bind(parsed.fingerprint),
		...parsed.subkeyIds.map((id) =>
			db
				.prepare(
					"INSERT INTO registry_subkeys (key_id, fingerprint) VALUES (?1, ?2) ON CONFLICT (key_id) DO NOTHING",
				)
				.bind(id, parsed.fingerprint),
		),
		...parsed.emails.map((email) =>
			db
				.prepare(
					"INSERT INTO registry_emails (email, fingerprint) VALUES (?1, ?2) ON CONFLICT (email, fingerprint) DO NOTHING",
				)
				.bind(email, parsed.fingerprint),
		),
	]);
}
