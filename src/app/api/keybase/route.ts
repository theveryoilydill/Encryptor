import { NextRequest, NextResponse } from "next/server";
import { lookupKeybaseUsersServer } from "@/lib/pgp/keybase";

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
  const url = new URL(req.url);
  const usernames = (url.searchParams.get("usernames") ?? "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);

  if (usernames.length === 0) {
    return NextResponse.json(
      { error: "Missing or empty 'usernames' query parameter." },
      { status: 400 },
    );
  }

  if (usernames.length > 50) {
    return NextResponse.json(
      { error: "A maximum of 50 usernames is allowed per request." },
      { status: 400 },
    );
  }

  try {
    const result = await lookupKeybaseUsersServer(usernames);
    return NextResponse.json(result, {
      headers: {
        "Cache-Control": "public, max-age=300, s-maxage=600",
      },
    });
  } catch (e) {
    const msg = (e as Error).message;
    return NextResponse.json({ error: msg }, { status: 502 });
  }
}
