import type { Route } from "./+types/api.keybase.fetchkey";
import { fetchKeyByKeyIDServer } from "~/lib/keybase";

/**
 * GET /api/keybase/fetchkey?key_id=<comma_separated_key_ids>
 *
 * Fetches public keys from Keybase by their PGP key IDs (short 16-hex or
 * long 40-hex). The response includes the owning Keybase username when known,
 * which makes this endpoint useful for "who signed it?" lookups.
 */
export async function loader({ request }: Route.LoaderArgs) {
  const url = new URL(request.url);
  const keyIDParam = url.searchParams.get("key_id") ?? "";
  const keyIDs = keyIDParam
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);

  if (keyIDs.length === 0) {
    return Response.json(
      { error: "Missing 'key_id' query parameter" },
      { status: 400 },
    );
  }
  if (keyIDs.length > 50) {
    return Response.json(
      { error: "A maximum of 50 key IDs is allowed per request" },
      { status: 400 },
    );
  }

  try {
    const keys = await fetchKeyByKeyIDServer(keyIDs);
    return Response.json(
      { keys },
      { headers: { "Cache-Control": "public, max-age=300, s-maxage=600" } },
    );
  } catch (e) {
    return Response.json(
      { error: (e as Error).message },
      { status: 502 },
    );
  }
}
