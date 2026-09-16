import { NextRequest, NextResponse } from "next/server";
import { UpstreamError, proxyCall } from "@/lib/api";
import { KEYBASE_USERNAME_RE } from "@/lib/constants";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/**
 * POST /api/keybase/getsalt
 * Body: { username: string }
 *
 * Proxies https://keybase.io/_/api/1.0/getsalt.json?email_or_username=<username>&pdpka_login=true
 * because Keybase does not set CORS headers.
 */
export async function POST(req: NextRequest) {
	let body: { username?: string };
	try {
		body = (await req.json()) as { username?: string };
	} catch {
		return NextResponse.json({ error: "Invalid JSON body" }, { status: 400 });
	}

	const username = (body.username ?? "").trim().toLowerCase();
	if (!username || !KEYBASE_USERNAME_RE.test(username)) {
		return NextResponse.json(
			{ error: "Invalid Keybase username (2–15 chars: a–z, 0-9, _)" },
			{ status: 400 },
		);
	}

	return proxyCall(async () => {
		const url = `https://keybase.io/_/api/1.0/getsalt.json?email_or_username=${encodeURIComponent(
			username,
		)}&pdpka_login=true`;
		const res = await fetch(url, {
			headers: { Accept: "application/json", "User-Agent": "encryptor/1.0" },
		});
		if (!res.ok) {
			throw new UpstreamError(`Keybase returned HTTP ${res.status}`, 502);
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
			throw new UpstreamError(data.status?.desc || data.status?.name || "Keybase API error", 400);
		}
		return {
			salt: data.salt,
			csrf_token: data.csrf_token,
			login_session: data.login_session,
			pwh_version: data.pwh_version ?? 3,
			uid: data.uid,
		};
	});
}
