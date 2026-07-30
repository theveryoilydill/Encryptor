import type { Route } from "./+types/api.keybase.getsalt";

/**
 * POST /api/keybase/getsalt
 * Body: { username: string }
 *
 * Proxies https://keybase.io/_/api/1.0/getsalt.json?email_or_username=<username>
 * because Keybase does not set CORS headers.
 */
export async function action({ request }: Route.ActionArgs) {
  if (request.method !== "POST") {
    return Response.json({ error: "Method not allowed" }, { status: 405 });
  }

  let body: { username?: string };
  try {
    body = (await request.json()) as { username?: string };
  } catch {
    return Response.json({ error: "Invalid JSON body" }, { status: 400 });
  }

  const username = (body.username ?? "").trim().toLowerCase();
  if (!username || !/^[a-z0-9_]{2,15}$/.test(username)) {
    return Response.json(
      { error: "Invalid Keybase username (2–15 chars: a–z, 0–9, _)" },
      { status: 400 },
    );
  }

  const url = `https://keybase.io/_/api/1.0/getsalt.json?email_or_username=${encodeURIComponent(
    username,
  )}`;
  try {
    const res = await fetch(url, {
      headers: { Accept: "application/json", "User-Agent": "pgp-keybase-cloudflare/1.0" },
    });
    if (!res.ok) {
      return Response.json(
        { error: `Keybase returned HTTP ${res.status}` },
        { status: 502 },
      );
    }
    const data = (await res.json()) as {
      status: { code: number; name: string; desc?: string };
      salt?: string;
      csrf_token?: string;
      login_session?: string;
      pwh_version?: number;
      uid?: string;
    };
    if (!data.status || data.status.code !== 0) {
      return Response.json(
        {
          error: data.status?.desc || data.status?.name || "Keybase API error",
        },
        { status: 400 },
      );
    }
    return Response.json({
      salt: data.salt,
      csrf_token: data.csrf_token,
      login_session: data.login_session,
      pwh_version: data.pwh_version ?? 3,
      uid: data.uid,
    });
  } catch (e) {
    return Response.json(
      { error: `Failed to reach Keybase: ${(e as Error).message}` },
      { status: 502 },
    );
  }
}
