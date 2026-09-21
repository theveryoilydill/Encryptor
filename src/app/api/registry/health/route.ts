import { NextRequest, NextResponse } from "next/server";

import { LIMITS } from "@/lib/constants";
import {
	RegistryError,
	getOrCreateSalt,
	getRegistryDBReady,
	lastSaltSource,
	nowSeconds,
	rateLimitSafe,
} from "@/lib/registry/db";
import { appliedSchemaVersions, pendingSchemaVersions } from "@/lib/registry/migrate";
import { clientIP, isLocalDevHost, registryErrorResponse } from "@/lib/registry/routes";
import { turnstileEnforced } from "@/lib/registry/turnstile";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/**
 * Whether THIS deployment (request host) may mutate under the
 * REGISTRY_PROD_ORIGIN write-lock. Mirrors assertWriteOrigin() logic so the
 * health probe is a truthful one-URL answer to "can this deployment write?".
 */
function writesAllowedHereFor(req: NextRequest): boolean {
	const configured = process.env.REGISTRY_PROD_ORIGIN?.trim();
	if (!configured) return true;
	if (process.env.NODE_ENV !== "production") return true;
	const host = (req.headers.get("host") ?? new URL(req.url).hostname).toLowerCase();
	if (isLocalDevHost(host)) return true;
	let allowedHost = configured.toLowerCase();
	try {
		allowedHost = new URL(configured).host.toLowerCase();
	} catch {
		/* configured as a bare host */
	}
	return host === allowedHost;
}

/**
 * GET /api/registry/health — operator-facing schema + capability probe.
 *
 * Runs the self-migration FIRST (so a fresh database heals just by opening
 * this URL) and then reports the applied/pending schema versions, database
 * reachability, whether Turnstile write-gating is enforced, and whether D1
 * WRITES currently succeed (limiterWrite). No secrets, no user data — safe
 * to expose; rate limited generously (fail-open so a limiter outage can
 * never make a healthy database look unhealthy).
 *
 * limiterWrite exists because reads and writes fail differently: the daily
 * D1 write quota (or a full database) leaves every read working while ALL
 * mutations 503 — observed live on a bot-hammered preview. Probing writes
 * from health turns that outage into a one-URL diagnosis. The probe writes
 * and immediately deletes a dedicated bucket row (self-cleaning even if
 * the DELETE fails: the opportunistic registry_rate sweep eventually
 * removes it). # Mr. AI Acting on s183173's Behalf
 */
export async function GET(req: NextRequest) {
	try {
		const db = await getRegistryDBReady();
		// Health checks must not be blocked by rate limiting, but an unbounded
		// endpoint is still a DoS surface — generous cap, fail-open.
		await rateLimitSafe(
			db,
			"health",
			clientIP(req),
			LIMITS.registryLookupLimit,
			LIMITS.registryLookupWindowSec,
			true,
		);
		const applied = await appliedSchemaVersions(db);
		// Resolve (or provision) the rate-limit salt — since 0004 the salt is
		// self-provisioned into registry_meta on first boot, so this can no
		// longer fail the way the old RE_SALT-only check did (mutations used
		// to 503 site-wide when the secret vanished from a recreated worker).
		await getOrCreateSalt(db);
		let limiterWrite = true;
		try {
			// Write probe: reads and writes fail differently — the daily
			// D1 write quota (or a full database) leaves every read healthy
			// while ALL mutations 503. Write + delete a dedicated bucket row
			// so operators get a one-URL diagnosis (self-cleaning even if
			// the DELETE fails: the opportunistic rate sweep removes it).
			const probeBucket = "registry-health-write-probe";
			await db
				.prepare(
					`INSERT INTO registry_rate (bucket, count, reset_at) VALUES (?1, 1, ?2)
                                         ON CONFLICT (bucket) DO UPDATE SET count = count + 1, reset_at = ?2`,
				)
				.bind(probeBucket, nowSeconds() + 300)
				.run();
			await db.prepare("DELETE FROM registry_rate WHERE bucket = ?1").bind(probeBucket).run();
		} catch {
			limiterWrite = false;
		}
		return NextResponse.json(
			{
				ok: true,
				db: true,
				limiterWrite,
				// Kept for dashboard/e2e compatibility: the salt is now ALWAYS
				// configured (self-provisioned). saltSource says how: "env"
				// (RE_SALT adopted on first boot) or "generated" (CSPRNG default).
				saltConfigured: true,
				saltSource: lastSaltSource() ?? "generated",
				schema: {
					applied,
					pending: pendingSchemaVersions(applied),
				},
				turnstile: turnstileEnforced() ? "enforced" : "disabled",
				// Origin write-lock (REGISTRY_PROD_ORIGIN): writesLockedTo is the
				// configured production origin (null = unlocked); writesAllowedHere
				// says whether THIS deployment (request host) may mutate. A branch
				// preview under a locked config reports writesAllowedHere:false.
				writesLockedTo: process.env.REGISTRY_PROD_ORIGIN?.trim() || null,
				writesAllowedHere: writesAllowedHereFor(req),
			},
			{ headers: { "Cache-Control": "no-store" } },
		);
	} catch (e) {
		if (e instanceof RegistryError) {
			// Schema/binding failures: keep the shape stable but ok:false so
			// dashboards can distinguish "database broken" from "route gone".
			return NextResponse.json(
				{ ok: false, db: false, error: e.message },
				{ status: e.status, headers: { "Cache-Control": "no-store" } },
			);
		}
		return registryErrorResponse(e);
	}
}
