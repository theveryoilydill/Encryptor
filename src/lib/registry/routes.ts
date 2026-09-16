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
