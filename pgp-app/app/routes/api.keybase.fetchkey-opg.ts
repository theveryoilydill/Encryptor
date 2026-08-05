import type { Route } from "./+types/api.keybase.fetchkey-opg";
import { fetchKeyFromOpenPGP_orgServer } from "~/lib/keybase";

/**
 * GET /api/keybase/fetchkey-opg?key_id=<comma_separated_key_ids>
 *
 * Fetches public keys from keys.openpgp.org (the privacy-respecting Verifying
 * Key Server) by their PGP key IDs. Used as a fallback when Keybase doesn't
 * find the key.
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
    const keys = await fetchKeyFromOpenPGP_orgServer(keyIDs);
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
