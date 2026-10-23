import { NextRequest } from "next/server";
import { lookupKeybaseUsersServer } from "@/lib/pgp/keybase";
import { CACHE, proxyCall, requireCsvParam } from "@/lib/api";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/**
 * Server-side Keybase proxy.
 *
 * Browser code cannot call https://keybase.io/_/api/1.0/user/lookup.json
 * directly because Keybase does not set CORS headers. We expose this endpoint
 * on our own origin so the SPA can look up public keys by username.
 *
 * GET /api/keybase?usernames=alice,bob,carol
 */
export async function GET(req: NextRequest) {
	const gate = requireCsvParam(
		new URL(req.url),
		"usernames",
		"Missing or empty 'usernames' query parameter.",
		"A maximum of 50 usernames is allowed per request.",
	);
	if (!gate.ok) return gate.response;

	return proxyCall(() => lookupKeybaseUsersServer(gate.values), CACHE.public);
}
