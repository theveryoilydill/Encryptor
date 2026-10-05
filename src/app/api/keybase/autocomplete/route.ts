import { NextRequest, NextResponse } from "next/server";
import { autocompleteKeybaseUsersServer } from "@/lib/pgp/keybase";
import { CACHE, proxyCall, queryParam } from "@/lib/api";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/**
 * GET /api/keybase/autocomplete?q=<prefix>
 */
export async function GET(req: NextRequest) {
	const q = queryParam(req, "q");
	if (q.trim().length < 1) {
		return NextResponse.json([]);
	}
	return proxyCall(() => autocompleteKeybaseUsersServer(q), CACHE.none);
}
