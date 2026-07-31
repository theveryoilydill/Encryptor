import { NextRequest, NextResponse } from "next/server";
import { autocompleteKeybaseUsersServer } from "@/lib/pgp/keybase";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/**
 * GET /api/keybase/autocomplete?q=<prefix>
 */
export async function GET(req: NextRequest) {
  const url = new URL(req.url);
  const q = url.searchParams.get("q") ?? "";
  if (q.trim().length < 1) {
    return NextResponse.json([]);
  }
  try {
    const results = await autocompleteKeybaseUsersServer(q);
    return NextResponse.json(results, {
      headers: { "Cache-Control": "no-store" },
    });
  } catch (e) {
    return NextResponse.json(
      { error: (e as Error).message },
      { status: 502 },
    );
  }
}
