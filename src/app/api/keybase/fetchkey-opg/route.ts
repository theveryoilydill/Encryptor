import { NextRequest, NextResponse } from "next/server";
import { fetchKeyFromOpenPGP_orgServer } from "@/lib/pgp/keybase";

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
  const url = new URL(req.url);
  const keyIDParam = url.searchParams.get("key_id") ?? "";
  const keyIDs = keyIDParam
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);

  if (keyIDs.length === 0) {
    return NextResponse.json(
      { error: "Missing 'key_id' query parameter" },
      { status: 400 },
    );
  }
  if (keyIDs.length > 50) {
    return NextResponse.json(
      { error: "A maximum of 50 key IDs is allowed per request" },
      { status: 400 },
    );
  }

  try {
    const keys = await fetchKeyFromOpenPGP_orgServer(keyIDs);
    return NextResponse.json(
      { keys },
      { headers: { "Cache-Control": "public, max-age=300, s-maxage=600" } },
    );
  } catch (e) {
    return NextResponse.json(
      { error: (e as Error).message },
      { status: 502 },
    );
  }
}
