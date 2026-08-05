import { NextRequest, NextResponse } from "next/server";
import { searchAllKeyserversServer } from "@/lib/pgp/keybase";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/**
 * GET /api/keybase/search-all?q=<query>
 *
 * Searches across multiple PGP keyserver sources:
 *  - Keybase (username + full name fuzzy search)
 *  - Ubuntu keyserver (HKP — name/email/keyID search)
 *  - keys.openpgp.org (VKS — exact email lookup)
 *
 * Returns a merged, deduplicated list of results.
 */
export async function GET(req: NextRequest) {
  const url = new URL(req.url);
  const q = url.searchParams.get("q") ?? "";
  const keybaseOnly = url.searchParams.get("keybase_only") === "1";
  if (q.trim().length < 1) {
    return NextResponse.json([]);
  }
  try {
    const results = await searchAllKeyserversServer(q, fetch, keybaseOnly);
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
