/**
 * Cloudflare Turnstile server-side verification for registry WRITES.
 *
 * Owner request (PR #25 review): "Make a Cloudflare Turnstile to add things
 * to the database" — publishing a key and storing an escrowed private key
 * are the two INSERT paths, and both now require a valid Turnstile token
 * whenever the deployment has TURNSTILE_SECRET_KEY configured.
 *
 * Policy:
 *  - Secret NOT configured  → verification is DISABLED. Local development,
 *    the seed script, and the e2e suite keep working unchanged; production
 *    opts in by provisioning the secret (`wrangler secret put`).
 *  - Secret configured + missing/invalid token → 403 (caller's fault).
 *  - Secret configured + siteverify unreachable/misconfigured → 503,
 *    FAIL-CLOSED (never wave writes through on infrastructure errors).
 *  - Tokens are single-use server-side at Cloudflare; the client must
 *    reset the widget after every attempt (see TurnstileWidget).
 *
 * # Mr. AI Acting on s183173's Behalf
 */
import { RegistryError, getCloudflareEnv } from "./db";

const SITEVERIFY_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify";
const TOKEN_MAX_CHARS = 2048; // Turnstile tokens are ~hundreds of chars; cap for hygiene.
const VERIFY_TIMEOUT_MS = 5000;

/** Whether this deployment enforces Turnstile on registry writes. */
export function turnstileEnforced(): boolean {
	return Boolean(getCloudflareEnv()?.TURNSTILE_SECRET_KEY);
}

/**
 * Verify a Turnstile token (or skip entirely when the secret is absent).
 * `ip` is forwarded to siteverify for extra tamper resistance when it
 * looks like a real address; "unknown" (dev) is omitted.
 */
export async function requireTurnstile(token: string | undefined, ip: string): Promise<void> {
	const secret = getCloudflareEnv()?.TURNSTILE_SECRET_KEY;
	if (!secret) return; // Disabled: no secret configured on this deployment.
	if (!token || token.length === 0 || token.length > TOKEN_MAX_CHARS) {
		throw new RegistryError(
			"Bot verification failed — complete the Turnstile challenge and try again",
			403,
		);
	}

	const form = new URLSearchParams({ secret, response: token });
	if (ip && ip !== "unknown" && /^[0-9a-fA-F:.]+$/.test(ip)) {
		form.set("remoteip", ip);
	}

	let response: Response;
	try {
		response = await fetch(SITEVERIFY_URL, {
			method: "POST",
			headers: { "Content-Type": "application/x-www-form-urlencoded" },
			body: form,
			signal: AbortSignal.timeout(VERIFY_TIMEOUT_MS),
			cache: "no-store",
		});
	} catch {
		// Network failure — fail closed.
		throw new RegistryError("Bot verification is temporarily unavailable — try again shortly", 503);
	}
	if (!response.ok) {
		throw new RegistryError("Bot verification is temporarily unavailable — try again shortly", 503);
	}

	let payload: { success?: boolean; "error-codes"?: string[] };
	try {
		payload = (await response.json()) as { success?: boolean; "error-codes"?: string[] };
	} catch {
		throw new RegistryError("Bot verification returned an unreadable response", 503);
	}
	if (payload.success === true) return;

	const codes = payload["error-codes"] ?? [];
	if (codes.includes("invalid-input-secret") || codes.includes("missing-input-secret")) {
		// Operator misconfiguration — a user cannot fix this by retrying.
		throw new RegistryError(
			"Bot verification is misconfigured on this deployment (invalid Turnstile secret)",
			503,
		);
	}
	throw new RegistryError(
		"Bot verification failed — the challenge expired or was already used. Please retry.",
		403,
	);
}
