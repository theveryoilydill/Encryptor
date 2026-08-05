import type { Route } from "./+types/api.keybase.autocomplete";
import { autocompleteKeybaseUsersServer } from "~/lib/keybase";

/**
 * GET /api/keybase/autocomplete?q=<prefix>
 *
 * Returns up to 10 Keybase usernames matching the prefix.
 */
export async function loader({ request }: Route.LoaderArgs) {
  const url = new URL(request.url);
  const q = url.searchParams.get("q") ?? "";
  if (q.trim().length < 1) {
    return Response.json([]);
  }
  try {
    const results = await autocompleteKeybaseUsersServer(q);
    return Response.json(results, {
      headers: { "Cache-Control": "no-store" },
    });
  } catch (e) {
    return Response.json({ error: (e as Error).message }, { status: 502 });
  }
}
