/**
 * DRY helpers shared by the /api/registry/* routes: JSON body parsing with
 * size + content-type enforcement, client-IP extraction, and consistent
 * error mapping. Security-relevant checks live here so no route can
 * forget them.
 *
 * # Mr. AI Acting on s183173's Behalf
 */
import { NextRequest, NextResponse } from "next/server";

import { LIMITS } from "@/lib/constants";
import { RegistryError } from "./db";

/**
 * Lock registry MUTATIONS to the production origin (owner's PR #25 ask:
 * "make sure that only main can actually do stuff to the db").
 *
 * Cloudflare Workers Builds gives every pushed branch a preview Worker that
 * shares the PRODUCTION D1 binding — so any branch (owner's or a trusted
 * collaborator's) can write to production data. Setting REGISTRY_PROD_ORIGIN
 * (e.g. "https://encryptor.example.workers.dev") flips every preview
 * deployment to read-only: mutation routes reject non-matching hosts 403
 * BEFORE touching D1 (no migrations check, no limiter write burn), while
 * the matching production host and local dev stay writable. Unset = writes
 * allowed everywhere (previous behavior, and what previews need while the
 * owner tests publish flows on them).
 */
export function isLocalDevHost(host: string): boolean {
	const bare = host.toLowerCase();
	// Strip a trailing :port, but never inside an IPv6 literal: "::1" ends
	// in ":1" which would otherwise be mistaken for a port. Bracketed
	// IPv6 ("[::1]:3000") strips the "]:port" tail; unbracketed literals
	// (more than one colon) are left untouched.
	const h = bare.startsWith("[")
		? bare.replace(/\]:\d+$/, "]")
		: (bare.match(/:/g)?.length ?? 0) === 1
			? bare.replace(/:\d+$/, "")
			: bare;
	return h === "localhost" || h === "127.0.0.1" || h === "::1" || h === "[::1]" || h === "0.0.0.0";
}

export function assertWriteOrigin(req: NextRequest): void {
	const allowed = process.env.REGISTRY_PROD_ORIGIN?.trim();
	if (!allowed) return;
	const host = (req.headers.get("host") ?? new URL(req.url).hostname).toLowerCase();
	if (process.env.NODE_ENV !== "production" || isLocalDevHost(host)) return;
	let allowedHost = allowed.toLowerCase();
	try {
		allowedHost = new URL(allowed).host.toLowerCase();
	} catch {
		/* configured as a bare host — use as-is */
	}
	if (host !== allowedHost) {
		throw new RegistryError(
			"Registry writes are locked to the production origin on this deployment (REGISTRY_PROD_ORIGIN)",
			403,
		);
	}
}

/** Cache header for public read endpoints (safe to cache short bursts). */
export const REGISTRY_CACHE_PUBLIC = "public, max-age=60, s-maxage=300";

/**
 * Extract the client IP. On Cloudflare, CF-Connecting-IP is set at the
 * edge and cannot be spoofed by the client; fall back to x-forwarded-for
 * for local development.
 */
export function clientIP(req: NextRequest): string {
	const cfIP = req.headers.get("cf-connecting-ip");
	if (cfIP) return cfIP;
	// Off the Cloudflare edge, x-forwarded-for is client-controlled and
	// must never back the rate limiter in production. Dev keeps the
	// fallback so local testing can exercise per-IP buckets.
	if (process.env.NODE_ENV === "production") return "unknown";
	return req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ?? "unknown";
}

/** Uniform JSON error response; RegistryError carries its own status. */
export function registryErrorResponse(e: unknown, cors = false): NextResponse {
	const headers: Record<string, string> = { "Cache-Control": "no-store" };
	if (cors) headers["Access-Control-Allow-Origin"] = "*";
	if (e instanceof RegistryError) {
		// 429s carry an accurate Retry-After so well-behaved clients can
		// back off until the window actually rolls over (RFC 9110 §10.2.3).
		if (e.status === 429 && e.retryAfterSeconds && e.retryAfterSeconds > 0) {
			headers["Retry-After"] = String(Math.ceil(e.retryAfterSeconds));
			return NextResponse.json(
				{ error: e.message, retryAfter: Math.ceil(e.retryAfterSeconds) },
				{ status: e.status, headers },
			);
		}
		return NextResponse.json({ error: e.message }, { status: e.status, headers });
	}
	// Unexpected errors must be observable — log before the generic 500.
	console.error("[registry] unhandled error:", e);
	return NextResponse.json({ error: "Internal registry error" }, { status: 500, headers });
}

/**
 * Parse a JSON POST body with strict guards: content type must be
 * application/json (blocks form-based CSRF simple requests) and the raw
 * body must be under the configured cap.
 */
export async function readJsonBody(req: NextRequest): Promise<Record<string, unknown>> {
	const contentType = req.headers.get("content-type") ?? "";
	if (!contentType.toLowerCase().includes("application/json")) {
		throw new RegistryError("Content-Type must be application/json", 415);
	}
	// Reject oversized bodies BEFORE buffering them (memory-exhaustion guard).
	const declaredLength = Number(req.headers.get("content-length") ?? "0");
	if (declaredLength > LIMITS.registryMaxBodyBytes) {
		throw new RegistryError("Request body too large", 413);
	}
	const raw = await req.text();
	// Belt-and-braces: chunked bodies can omit Content-Length.
	if (raw.length > LIMITS.registryMaxBodyBytes) {
		throw new RegistryError("Request body too large", 413);
	}
	try {
		const body: unknown = JSON.parse(raw);
		if (typeof body !== "object" || body === null || Array.isArray(body)) {
			throw new RegistryError("Body must be a JSON object", 400);
		}
		return body as Record<string, unknown>;
	} catch (e) {
		if (e instanceof RegistryError) throw e;
		throw new RegistryError("Body is not valid JSON", 400);
	}
}

/**
 * String field getter. Absent/wrong-type fields return null (the caller
 * decides the error); over-length fields are REJECTED outright — silent
 * truncation would turn a clear 4xx into a confusing downstream failure.
 */
export function stringField(
	body: Record<string, unknown>,
	name: string,
	maxLength: number,
): string | null {
	const value = body[name];
	if (typeof value !== "string" || value.length === 0) return null;
	if (value.length > maxLength) {
		throw new RegistryError(`The '${name}' field exceeds its maximum length`, 400);
	}
	return value;
}

/** Strip control characters from a user-supplied reason before storing. */
export function sanitizeReason(reason: string | null): string | null {
	if (!reason) return null;
	// eslint-disable-next-line no-control-regex
	const cleaned = reason.replace(/[\u0000-\u001f\u007f]+/g, " ").trim();
	if (cleaned.length === 0) return null;
	return cleaned.slice(0, LIMITS.registryMaxReasonChars);
}
