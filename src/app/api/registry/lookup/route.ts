import { NextRequest, NextResponse } from "next/server";

import { LIMITS } from "@/lib/constants";
import { RegistryError, getRegistryDBReady, enforceRateLimit } from "@/lib/registry/db";
import { normalizeEmail, normalizeFingerprint, normalizeKeyID, normalizeName } from "@/lib/registry/keys";
import { fingerprintToPgpWords } from "@/lib/pgp/pgp-words";
import { REGISTRY_CACHE_PUBLIC, clientIP, registryErrorResponse } from "@/lib/registry/routes";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/**
 * GET /api/registry/lookup — PUBLIC read endpoint (no auth, CORS *).
 *
 * Exactly one query parameter is required:
 *   ?fingerprint=<40 hex>   — primary key fingerprint
 *   ?key_id=<16 hex>        — primary OR subkey long key ID
 *   ?email=<address>        — exact-match email (as published)
 *   ?name=<display name>    — exact-match User ID display name (lowercased;
 *                             names are NOT unique — several keys may match)
 *
 * Returns { keys: [...] } so callers can iterate uniformly. Revoked keys
 * are returned WITH their revocation status — hiding them would let an
 * attacker silently suppress revocations.
 *
 * Add ?words=1 to include a `words` array per key: the PGP word list
 * (biometric) rendering of the fingerprint, e.g. "topmost Istanbul Pluto
 * vagabond …". 20 words, canonical capitalization — read aloud over a
 * voice call to verify a fingerprint without trusting the channel.
 */

interface RegistryRow {
	fingerprint: string;
	armored: string;
	revoked: number;
	revoked_at: number | null;
	revoke_reason: string | null;
	created_at: number;
	updated_at: number;
	pq_seal_pk: string | null;
}

const SELECT_COLUMNS =
	"fingerprint, armored, revoked, revoked_at, revoke_reason, created_at, updated_at, pq_seal_pk";

function toPublic(row: RegistryRow) {
	return {
		fingerprint: row.fingerprint,
		armored: row.armored,
		revoked: row.revoked === 1,
		revokedAt: row.revoked_at,
		revokeReason: row.revoke_reason,
		createdAt: row.created_at,
		updatedAt: row.updated_at,
		pqSealPk: row.pq_seal_pk,
	};
}

/** ?words=1 (or =true) opts into PGP word-list fingerprints per key. */
function wantsWords(url: URL): boolean {
	const v = url.searchParams.get("words");
	return v === "1" || v === "true";
}

export async function GET(req: NextRequest) {
	try {
		const url = new URL(req.url);
		const fingerprint = url.searchParams.get("fingerprint");
		const keyID = url.searchParams.get("key_id");
		const email = url.searchParams.get("email");
		const name = url.searchParams.get("name");
		const includeWords = wantsWords(url);

		const db = await getRegistryDBReady();
		// Public read endpoint — still rate limited (read-first limiter:
		// over-limit callers cost ~1 indexed read, zero writes; limiter
		// failures fail OPEN so reads stay available). 120 lookups/hour/IP.
		await enforceRateLimit(
			db,
			"lookup",
			clientIP(req),
			LIMITS.registryLookupLimit,
			LIMITS.registryLookupWindowSec,
			"Too many lookup requests — try again later",
			true,
		);
		let rows: RegistryRow[] = [];

		if (fingerprint) {
			const fpr = normalizeFingerprint(fingerprint);
			if (!fpr) throw new RegistryError("fingerprint must be 40 hex characters", 400);
			const result = await db
				.prepare(`SELECT ${SELECT_COLUMNS} FROM registry_keys WHERE fingerprint = ?1`)
				.bind(fpr)
				.all<RegistryRow>();
			rows = result.results ?? [];
		} else if (keyID) {
			const id = normalizeKeyID(keyID);
			if (!id) throw new RegistryError("key_id must be 16 hex characters", 400);
			// A subkey ID resolves to its primary key via the subkeys table.
			// Bounded by LIMIT: key IDs are only 64 bits, so a determined
			// attacker could publish many fingerprints sharing one key ID.
			const result = await db
				.prepare(
					`SELECT ${SELECT_COLUMNS} FROM registry_keys
                                         WHERE key_id = ?1
                                         UNION
                                         SELECT ${SELECT_COLUMNS} FROM registry_keys
                                         WHERE fingerprint IN (SELECT fingerprint FROM registry_subkeys WHERE key_id = ?1)
                                         LIMIT ?2`,
				)
				.bind(id, LIMITS.registryMaxLookupResults)
				.all<RegistryRow>();
			rows = result.results ?? [];
		} else if (email) {
			const normalized = normalizeEmail(email);
			if (!normalized) throw new RegistryError("email is not a valid address", 400);
			// The inner LIMIT keeps the subquery bounded even if one email
			// was claimed by many keys; ORDER BY keeps results deterministic.
			const result = await db
				.prepare(
					`SELECT ${SELECT_COLUMNS} FROM registry_keys
                                         WHERE fingerprint IN
                                         (SELECT fingerprint FROM registry_emails WHERE email = ?1 LIMIT ?2)
                                         ORDER BY created_at
                                         LIMIT ?2`,
				)
				.bind(normalized, LIMITS.registryMaxLookupResults)
				.all<RegistryRow>();
			rows = result.results ?? [];
		} else if (name) {
			const normalized = normalizeName(name);
			if (!normalized) throw new RegistryError("name is not a valid display name", 400);
			// Names are NOT unique — the same bounded-subquery shape as
			// the email branch keeps one common name from flooding results.
			const result = await db
				.prepare(
					`SELECT ${SELECT_COLUMNS} FROM registry_keys
                                         WHERE fingerprint IN
                                         (SELECT fingerprint FROM registry_names WHERE name = ?1 LIMIT ?2)
                                         ORDER BY created_at
                                         LIMIT ?2`,
				)
				.bind(normalized, LIMITS.registryMaxLookupResults)
				.all<RegistryRow>();
			rows = result.results ?? [];
		} else {
			throw new RegistryError("Provide exactly one of: fingerprint, key_id, email, or name", 400);
		}

		return NextResponse.json(
			{
				keys: rows.map((row) => ({
					...toPublic(row),
					...(includeWords ? { words: fingerprintToPgpWords(row.fingerprint) } : {}),
				})),
			},
			{
				headers: {
					"Cache-Control": REGISTRY_CACHE_PUBLIC,
					"Access-Control-Allow-Origin": "*",
				},
			},
		);
	} catch (e) {
		// The lookup endpoint is a public CORS read API — error responses
		// must be readable by cross-site callers too.
		return registryErrorResponse(e, true);
	}
}

/** CORS preflight for cross-site reads — read-only, GET only. */
export async function OPTIONS() {
	return new NextResponse(null, {
		status: 204,
		headers: {
			"Access-Control-Allow-Origin": "*",
			"Access-Control-Allow-Methods": "GET, OPTIONS",
			"Access-Control-Allow-Headers": "Content-Type",
			"Access-Control-Max-Age": "86400",
		},
	});
}
