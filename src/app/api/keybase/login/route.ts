import { NextRequest } from "next/server";
import { UpstreamError, proxyCall } from "@/lib/api";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/**
 * POST /api/keybase/login
 * Body: { username, pdpka4, pdpka5, csrf_token, login_session }
 *
 * Performs the Keybase PDPKA login flow:
 *  1. POST to https://keybase.io/_/api/1.0/login.json with
 *     { email_or_username, pdpka4, pdpka5 } and the CSRF cookie.
 *  2. If successful, call https://keybase.io/_/api/1.0/me.json with the
 *     session cookie to fetch the user's profile + encrypted private key bundle.
 *  3. Return the bundle to the client, which decrypts it locally with the pwh.
 */

interface LoginBody {
	username?: string;
	pdpka4?: string;
	pdpka5?: string;
	csrf_token?: string;
	login_session?: string;
}

export async function POST(req: NextRequest) {
	let body: LoginBody;
	try {
		body = (await req.json()) as LoginBody;
	} catch {
		return Response.json({ error: "Invalid JSON body" }, { status: 400 });
	}

	const username = (body.username ?? "").trim().toLowerCase();
	const pdpka4 = body.pdpka4 ?? "";
	const pdpka5 = body.pdpka5 ?? "";
	const csrfToken = body.csrf_token ?? "";
	const loginSession = body.login_session ?? "";

	if (!username || !pdpka4 || !pdpka5 || !csrfToken || !loginSession) {
		return Response.json(
			{
				error: "Missing required fields (username, pdpka4, pdpka5, csrf_token, login_session)",
			},
			{ status: 400 },
		);
	}

	return proxyCall(async () => {
		// Step 1: Log in to Keybase with the PDPKA signatures.
		const loginParams = new URLSearchParams();
		loginParams.set("email_or_username", username);
		loginParams.set("pdpka4", pdpka4);
		loginParams.set("pdpka5", pdpka5);

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
			throw new UpstreamError(
				loginData.status?.desc ||
					loginData.status?.name ||
					"Keybase login failed (wrong username or password?)",
				401,
			);
		}
		let sessionCookie: string | null = loginData.session ?? null;
		if (!sessionCookie) {
			const setCookie = loginRes.headers.get("set-cookie") || "";
			const m = setCookie.match(/session=([^;]+)/);
			sessionCookie = m ? m[1] : null;
		}
		if (!sessionCookie) {
			throw new UpstreamError("Keybase login succeeded but no session was returned.", 502);
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
				throw new UpstreamError(
					meData.status?.desc || meData.status?.name || "Keybase me.json call failed",
					502,
				);
			}
			const me = meData.me;
			return {
				username: me.basics?.username ?? username,
				uid: "",
				picture_url: me.pictures?.primary?.url,
				full_name: me.profile?.full_name,
				private_key_bundle: me.private_keys?.primary?.bundle ?? null,
				primary_key_fingerprint: me.public_keys?.primary?.fingerprint,
				primary_key_kid: me.public_keys?.primary?.kid,
			};
		} catch (e) {
			if (e instanceof UpstreamError) throw e;
			throw new UpstreamError(`Failed to fetch me.json: ${(e as Error).message}`, 502);
		}
	});
}
