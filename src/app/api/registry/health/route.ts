import { NextRequest, NextResponse } from "next/server";

import { LIMITS } from "@/lib/constants";
import { RegistryError, getRegistryDBReady, rateLimitSafe } from "@/lib/registry/db";
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
 * reachability, and whether Turnstile write-gating is enforced. No secrets,
 * no user data — safe to expose; rate limited generously (fail-open so a
 * limiter outage can never make a healthy database look unhealthy).
 *
 * # Mr. AI Acting on s183173's Behalf
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
		return NextResponse.json(
			{
				ok: true,
				db: true,
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
