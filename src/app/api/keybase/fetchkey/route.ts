import { NextRequest } from "next/server";
import { fetchKeyByKeyIDServer } from "@/lib/pgp/keybase";
import { CACHE, proxyKeyCall, requireCsvParam } from "@/lib/api";
import { LIMITS } from "@/lib/constants";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/**
 * GET /api/keybase/fetchkey?key_id=<comma_separated_key_ids>
 */
export async function GET(req: NextRequest) {
	const gate = requireCsvParam(
		new URL(req.url),
		"key_id",
		"Missing 'key_id' query parameter",
		"A maximum of 50 key IDs is allowed per request",
		LIMITS.maxKeyIDsPerRequest,
	);
	if (!gate.ok) return gate.response;

	// Enveloped as { keys } to match the original app's route contract.
	return proxyKeyCall(() => fetchKeyByKeyIDServer(gate.values), CACHE.public);
}
