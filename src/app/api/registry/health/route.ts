import { NextRequest, NextResponse } from "next/server";

import { LIMITS } from "@/lib/constants";
import {
	RegistryError,
	getRegistryDBReady,
	nowSeconds,
	rateLimitSafe,
	saltConfigured,
} from "@/lib/registry/db";
import { appliedSchemaVersions, pendingSchemaVersions } from "@/lib/registry/migrate";
import { clientIP, registryErrorResponse } from "@/lib/registry/routes";
import { turnstileEnforced } from "@/lib/registry/turnstile";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

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
				saltConfigured: saltConfigured(),
				schema: {
					applied,
					pending: pendingSchemaVersions(applied),
				},
				turnstile: turnstileEnforced() ? "enforced" : "disabled",
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
