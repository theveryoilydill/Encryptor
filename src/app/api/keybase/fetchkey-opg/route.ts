import { NextRequest } from "next/server";
import { fetchKeyFromOpenPGP_orgServer } from "@/lib/pgp/keybase";
import { CACHE, proxyKeyCall, requireCsvParam } from "@/lib/api";
import { LIMITS } from "@/lib/constants";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/**
 * GET /api/keybase/fetchkey-opg?key_id=<comma_separated_key_ids>
 *
 * Fetches public keys from keys.openpgp.org (the privacy-respecting Verifying
 * Key Server) by their PGP key IDs. Used as a fallback when Keybase doesn't
 * find the key.
 *
 * Unlike Keybase, keys.openpgp.org doesn't associate keys with usernames.
 * The response includes the armored key + fingerprint + all key IDs, but
 * `username` will be undefined.
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
	return proxyKeyCall(() => fetchKeyFromOpenPGP_orgServer(gate.values), CACHE.public);
}
