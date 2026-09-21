import { NextRequest, NextResponse } from "next/server";

import { LIMITS } from "@/lib/constants";
import {
	type D1Result,
	RegistryError,
	auditSafe,
	getRegistryDBReady,
	nowSeconds,
	randomHex,
	enforceRateLimit,
	sha256Hex,
} from "@/lib/registry/db";
import {
	parseEncryptedPrivateArmored,
	parsePqSealPk,
	parsePublicArmored,
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
 * POST /api/registry/publish — publish an armored PUBLIC key.
 *
 * Body: { "armored": "<ASCII armored public key>" }
 *     optional: { "encryptedPrivate": "<ASCII armored PASSPHRASE-ENCRYPTED
 *                private key>" } — opt-in escrow so the owner can restore
 *                their key from any device. The server rejects the upload
 *                unless every secret packet is passphrase-encrypted, so the
 *                database never holds usable private key bytes.
 *     optional: { "dropEncryptedPrivate": true } — remove a previously
 *                escrowed private key during an authorized replacement.
 *     optional: { "pqSealPk": "<base64 ML-KEM-768 public key>" } — store the
 *                owner's quantum-seal PUBLIC half so correspondents can seal
 *                archive copies to this key. The secret half never leaves the
 *                owner's device; the server validates the byte length.
 *     optional: { "turnstileToken": "..." } — Cloudflare Turnstile token;
 *                required when the deployment enforces Turnstile (see
 *                src/lib/registry/turnstile.ts).
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
		// Origin write-lock runs BEFORE any D1 access so a locked preview
		// deployment costs zero database reads/writes (owner's "only main
		// can do stuff to the db" requirement).
		assertWriteOrigin(req);
		const db = await getRegistryDBReady();
		await enforceRateLimit(
			db,
			"publish",
			clientIP(req),
			LIMITS.registryPublishLimit,
			LIMITS.registryPublishWindowSec,
			"Too many publish requests — try again later",
		);

		const body = await readJsonBody(req);

		// Owner request: Turnstile-gate "adding things to the database".
		// Publishing (with or without escrow) is the main INSERT path;
		// verification is enforced only when the deployment configures
		// TURNSTILE_SECRET_KEY (disabled locally + for seed scripts).
		await requireTurnstile(
			typeof body.turnstileToken === "string" ? body.turnstileToken : undefined,
			clientIP(req),
		);

		const armored = stringField(body, "armored", LIMITS.registryMaxArmorBytes);
		if (!armored) throw new RegistryError("The 'armored' field is required", 400);

		const parsed = await parsePublicArmored(armored, LIMITS.registryMaxArmorBytes);

		// Optional escrow: validated BEFORE any write so an invalid
		// encrypted private key cannot publish the public half.
		const dropEscrow = body["dropEncryptedPrivate"] === true;
		const rawPrivate = stringField(body, "encryptedPrivate", LIMITS.registryMaxPrivateArmorBytes);
		if (rawPrivate && dropEscrow) {
			throw new RegistryError(
				"Send either encryptedPrivate or dropEncryptedPrivate, not both",
				400,
			);
		}
		const escrow = rawPrivate
			? await parseEncryptedPrivateArmored(
					rawPrivate,
					LIMITS.registryMaxPrivateArmorBytes,
					parsed.fingerprint,
				)
			: null;

		// Optional quantum-seal public half (ML-KEM-768). Validated BEFORE any
		// write: an invalid value rejects the publish rather than storing junk.
		const rawPqSealPk = stringField(body, "pqSealPk", 2048);
		const pqSealPk = rawPqSealPk ? parsePqSealPk(rawPqSealPk) : null;
		if (rawPqSealPk && !pqSealPk) {
			throw new RegistryError("pqSealPk must be base64 of a 1184-byte ML-KEM-768 public key", 400);
		}

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
			// Email-squatting budget applies to replacements too — but the
			// key being replaced does not count against its own emails.
			for (const email of parsed.emails) {
				const claimed = await db
					.prepare(
						"SELECT COUNT(*) AS n FROM registry_emails WHERE email = ?1 AND fingerprint != ?2",
					)
					.bind(email, parsed.fingerprint)
					.first<{ n: number }>();
				if ((claimed?.n ?? 0) >= LIMITS.registryMaxKeysPerEmail) {
					throw new RegistryError(
						"This email address is already associated with the maximum number of keys",
						409,
					);
				}
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
			await replaceKeyRecord(db, parsed, escrow, dropEscrow, pqSealPk);
			await auditSafe(
				db,
				"replace",
				parsed.fingerprint,
				escrow ? "escrow updated" : dropEscrow ? "escrow dropped" : null,
			);
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
                                 (fingerprint, key_id, armored, encrypted_private, private_updated_at, pq_seal_pk, revoked, token_hash, created_at, updated_at)
                                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0, ?7, ?8, ?8)`,
					)
					.bind(
						parsed.fingerprint,
						parsed.keyId,
						parsed.armored,
						escrow?.armored ?? null,
						escrow ? now : null,
						pqSealPk,
						tokenHash,
						now,
					),
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
				// Names are NOT unique (no collision policy) — plain inserts.
				...parsed.names.map((name) =>
					db
						.prepare(
							"INSERT INTO registry_names (name, fingerprint) VALUES (?1, ?2) ON CONFLICT (name, fingerprint) DO NOTHING",
						)
						.bind(name, parsed.fingerprint),
				),
			]);
		} catch (e) {
			// Concurrent first-publish of the same fingerprint loses the PK
			// race — map it to the same 409 a pre-check would give (fail-closed).
			const message = (e as Error).message ?? "";
			if (message.includes("UNIQUE constraint failed: registry_keys.fingerprint")) {
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
			`emails:${parsed.emails.length} names:${parsed.names.length} subkeys:${parsed.subkeyIds.length}`,
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

/**
 * Overwrite an existing (non-revoked) record atomically. Escrow policy:
 * a provided encryptedPrivate overwrites, dropEscrowPrivate clears, and
 * neither keeps the existing escrow (a same-fingerprint replacement —
 * e.g. adding a subkey — must not silently destroy the owner's backup).
 */
async function replaceKeyRecord(
	db: Awaited<ReturnType<typeof getRegistryDBReady>>,
	parsed: Awaited<ReturnType<typeof parsePublicArmored>>,
	escrow: Awaited<ReturnType<typeof parseEncryptedPrivateArmored>> | null,
	dropEscrow: boolean,
	pqSealPk: string | null,
) {
	const now = nowSeconds();
	// The status UPDATE runs FIRST and alone, gated on `AND revoked = 0` so a
	// concurrent revocation between the earlier read and this write makes the
	// replacement fail with 409 instead of mutating a revoked record. Only
	// after the UPDATE is confirmed do the index rows get rebuilt.
	// Subkey/email re-inserts mirror the fresh-publish conflict policy (drop
	// colliding IDs instead of failing the batch).
	// Each escrow branch gets its own statement so the placeholder count
	// always matches the bound parameters (SQLite fails on out-of-range ?n).
	let updated: D1Result;
	if (escrow) {
		updated = await db
			.prepare(
				`UPDATE registry_keys
                                 SET armored = ?2, key_id = ?3, encrypted_private = ?4, private_updated_at = ?5, updated_at = ?5
                                 WHERE fingerprint = ?1 AND revoked = 0`,
			)
			.bind(parsed.fingerprint, parsed.armored, parsed.keyId, escrow.armored, now)
			.run();
	} else if (dropEscrow) {
		updated = await db
			.prepare(
				`UPDATE registry_keys
                                 SET armored = ?2, key_id = ?3, encrypted_private = NULL, private_updated_at = NULL, updated_at = ?4
                                 WHERE fingerprint = ?1 AND revoked = 0`,
			)
			.bind(parsed.fingerprint, parsed.armored, parsed.keyId, now)
			.run();
	} else {
		updated = await db
			.prepare(
				`UPDATE registry_keys SET armored = ?2, key_id = ?3, updated_at = ?4
                                 WHERE fingerprint = ?1 AND revoked = 0`,
			)
			.bind(parsed.fingerprint, parsed.armored, parsed.keyId, now)
			.run();
	}
	if (!updated.meta || Number(updated.meta.changes ?? 0) === 0) {
		throw new RegistryError("Key was revoked concurrently — replacement refused", 409);
	}
	// Quantum-seal public half is independent of escrow: a provided value
	// replaces, an absent one keeps whatever is stored (same policy as the
	// armored key itself).
	if (pqSealPk) {
		await db
			.prepare("UPDATE registry_keys SET pq_seal_pk = ?2 WHERE fingerprint = ?1 AND revoked = 0")
			.bind(parsed.fingerprint, pqSealPk)
			.run();
	}
	await db.batch([
		db.prepare("DELETE FROM registry_subkeys WHERE fingerprint = ?1").bind(parsed.fingerprint),
		db.prepare("DELETE FROM registry_emails WHERE fingerprint = ?1").bind(parsed.fingerprint),
		db.prepare("DELETE FROM registry_names WHERE fingerprint = ?1").bind(parsed.fingerprint),
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
		...parsed.names.map((name) =>
			db
				.prepare(
					"INSERT INTO registry_names (name, fingerprint) VALUES (?1, ?2) ON CONFLICT (name, fingerprint) DO NOTHING",
				)
				.bind(name, parsed.fingerprint),
		),
	]);
}
