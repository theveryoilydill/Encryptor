import { NextRequest, NextResponse } from "next/server";
import { searchAllKeyserversServer } from "@/lib/pgp/keybase";
import { CACHE, proxyCall, queryParam } from "@/lib/api";

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
  const q = queryParam(req, "q");
  const keybaseOnly = queryParam(req, "keybase_only") === "1";
  if (q.trim().length < 1) {
    return NextResponse.json([]);
  }
  return proxyCall(() => searchAllKeyserversServer(q, fetch, keybaseOnly), CACHE.none);
}
