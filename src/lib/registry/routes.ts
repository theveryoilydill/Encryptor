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
	return (
		req.headers.get("cf-connecting-ip") ??
		req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ??
		"unknown"
	);
}

/** Uniform JSON error response; RegistryError carries its own status. */
export function registryErrorResponse(e: unknown, cors = false): NextResponse {
	if (e instanceof RegistryError) {
		return NextResponse.json(
			{ error: e.message },
			{
				status: e.status,
				headers: cors ? { "Access-Control-Allow-Origin": "*" } : undefined,
			},
		);
	}
	// Unexpected errors must be observable — log before the generic 500.
	console.error("[registry] unhandled error:", e);
	return NextResponse.json(
		{ error: "Internal registry error" },
		{
			status: 500,
			headers: cors ? { "Access-Control-Allow-Origin": "*" } : undefined,
		},
	);
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
	const raw = await req.text();
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

/** String field getter with an upper bound; null when absent or wrong type. */
export function stringField(
	body: Record<string, unknown>,
	name: string,
	maxLength: number,
): string | null {
	const value = body[name];
	if (typeof value !== "string" || value.length === 0) return null;
	return value.length > maxLength ? value.slice(0, maxLength) : value;
}

/** Strip control characters from a user-supplied reason before storing. */
export function sanitizeReason(reason: string | null): string | null {
	if (!reason) return null;
	// eslint-disable-next-line no-control-regex
	const cleaned = reason.replace(/[\u0000-\u001f\u007f]+/g, " ").trim();
	if (cleaned.length === 0) return null;
	return cleaned.slice(0, LIMITS.registryMaxReasonChars);
}
