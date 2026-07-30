import { NextRequest, NextResponse } from "next/server";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/**
 * POST /api/keybase/login
 * Body: { username, pwhash, csrf_token, login_session }
 *
 * Performs the Keybase login flow:
 *  1. POST to https://keybase.io/_/api/1.0/login.json with the credentials.
 *  2. If successful, call https://keybase.io/_/api/1.0/me.json with the
 *     session cookie to fetch the user's profile + encrypted private key bundle.
 *  3. Return the bundle to the client, which decrypts it locally with the pwhash.
 */
export async function POST(req: NextRequest) {
  let body: {
    username?: string;
    pwhash?: string;
    csrf_token?: string;
    login_session?: string;
  };
  try {
    body = (await req.json()) as typeof body;
  } catch {
    return NextResponse.json({ error: "Invalid JSON body" }, { status: 400 });
  }

  const username = (body.username ?? "").trim().toLowerCase();
  const pwhash = body.pwhash ?? "";
  const csrfToken = body.csrf_token ?? "";
  const loginSession = body.login_session ?? "";

  if (!username || !pwhash || !csrfToken || !loginSession) {
    return NextResponse.json(
      { error: "Missing required fields (username, pwhash, csrf_token, login_session)" },
      { status: 400 },
    );
  }

  // Step 1: Log in to Keybase.
  const loginParams = new URLSearchParams();
  loginParams.set("email_or_username", username);
  loginParams.set("password", pwhash);
  loginParams.set("csrf_token", csrfToken);
  loginParams.set("login_session", loginSession);

  let sessionCookie: string | null = null;
  try {
    const loginRes = await fetch("https://keybase.io/_/api/1.0/login.json", {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": "encryptor/1.0",
        Cookie: `csrf_token=${csrfToken}`,
      },
      body: loginParams.toString(),
    });
    const loginData = (await loginRes.json()) as {
      status: { code: number; name: string; desc?: string };
      session?: string;
      uid?: string;
    };
    if (!loginData.status || loginData.status.code !== 0) {
      return NextResponse.json(
        {
          error:
            loginData.status?.desc ||
            loginData.status?.name ||
            "Keybase login failed (wrong username or password?)",
        },
        { status: 401 },
      );
    }
    sessionCookie = loginData.session ?? null;
    if (!sessionCookie) {
      const setCookie = loginRes.headers.get("set-cookie") || "";
      const m = setCookie.match(/session=([^;]+)/);
      sessionCookie = m ? m[1] : null;
    }
    if (!sessionCookie) {
      return NextResponse.json(
        { error: "Keybase login succeeded but no session was returned." },
        { status: 502 },
      );
    }
  } catch (e) {
    return NextResponse.json(
      { error: `Failed to reach Keybase: ${(e as Error).message}` },
      { status: 502 },
    );
  }

  // Step 2: Fetch me.json with the session cookie.
  try {
    const meRes = await fetch(
      "https://keybase.io/_/api/1.0/me.json?fields=basics,public_keys,private_keys",
      {
        headers: {
          Accept: "application/json",
          "User-Agent": "encryptor/1.0",
          Cookie: `session=${sessionCookie}`,
        },
      },
    );
    const meData = (await meRes.json()) as {
      status: { code: number; name: string; desc?: string };
      me?: {
        basics?: { username?: string };
        pictures?: { primary?: { url?: string } };
        profile?: { full_name?: string };
        public_keys?: {
          primary?: { bundle?: string; kid?: string; fingerprint?: string };
        };
        private_keys?: { primary?: { bundle?: string; kid?: string } };
      };
    };
    if (!meData.status || meData.status.code !== 0 || !meData.me) {
      return NextResponse.json(
        {
          error:
            meData.status?.desc ||
            meData.status?.name ||
            "Keybase me.json call failed",
        },
        { status: 502 },
      );
    }
    const me = meData.me;
    return NextResponse.json({
      username: me.basics?.username ?? username,
      uid: "",
      picture_url: me.pictures?.primary?.url,
      full_name: me.profile?.full_name,
      private_key_bundle: me.private_keys?.primary?.bundle ?? null,
      primary_key_fingerprint: me.public_keys?.primary?.fingerprint,
      primary_key_kid: me.public_keys?.primary?.kid,
    });
  } catch (e) {
    return NextResponse.json(
      { error: `Failed to fetch me.json: ${(e as Error).message}` },
      { status: 502 },
    );
  }
}
