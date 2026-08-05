import type { Route } from "./+types/api.keybase.search-all";
import { searchAllKeyserversServer } from "~/lib/keybase";

/**
 * GET /api/keybase/search-all?q=<query>
 *
 * Searches across multiple PGP keyserver sources:
 *  - Keybase (username + full name fuzzy search)
 *  - Ubuntu keyserver (HKP — name/email/keyID search)
 *  - keys.openpgp.org (VKS — exact email lookup)
 */
export async function loader({ request }: Route.LoaderArgs) {
  const url = new URL(request.url);
  const q = url.searchParams.get("q") ?? "";
  const keybaseOnly = url.searchParams.get("keybase_only") === "1";
  if (q.trim().length < 1) {
    return Response.json([]);
  }
  try {
    const results = await searchAllKeyserversServer(q, fetch, keybaseOnly);
    return Response.json(results, {
      headers: { "Cache-Control": "no-store" },
    });
  } catch (e) {
    return Response.json({ error: (e as Error).message }, { status: 502 });
  }
}
