import { NextRequest, NextResponse } from "next/server";
import { LIMITS } from "@/lib/constants";

/**
 * DRY helpers shared by all Keybase proxy API routes.
 *
 * Every route: parses params, validates, calls an upstream server fn, and
 * maps errors to consistent JSON responses with the same cache semantics.
 */

export const ROUTE_CONFIG = {
  runtime: "nodejs",
  dynamic: "force-dynamic",
} as const;

/** Browser-visible cache header sets used by the proxy routes. */
export const CACHE = {
  /** Upstream results are stable for a while — allow short caching. */
  public: "public, max-age=300, s-maxage=600",
  /** Live search results — never cache. */
  none: "no-store",
} as const;

/** Split a comma-separated query parameter into trimmed, non-empty items. */
export function csvParam(url: URL, name: string): string[] {
  return (url.searchParams.get(name) ?? "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
}

export function jsonError(message: string, status: number) {
  return NextResponse.json({ error: message }, { status });
}

/**
 * Validate a csv list param against a required check and a max count.
 * Returns either an error response or the parsed list.
 */
export function requireCsvParam(
  url: URL,
  name: string,
  missingMessage: string,
  maxMessage: string,
  max: number = LIMITS.maxUsernamesPerRequest,
): { ok: true; values: string[] } | { ok: false; response: NextResponse } {
  const values = csvParam(url, name);
  if (values.length === 0) {
    return { ok: false, response: jsonError(missingMessage, 400) };
  }
  if (values.length > max) {
    return { ok: false, response: jsonError(maxMessage, 400) };
  }
  return { ok: true, values };
}

/**
 * Error carrying the HTTP status the proxy should return to the client.
 * Throw this from proxied handlers when the upstream error maps to a
 * specific status (e.g. 400 invalid username, 401 bad login).
 */
export class UpstreamError extends Error {
  status: number;
  constructor(message: string, status: number) {
    super(message);
    this.name = "UpstreamError";
    this.status = status;
  }
}

/**
 * Wrap a proxied upstream call: 502 with the error message on failure
 * (or the status carried by an UpstreamError). Keeps the try/catch
 * boilerplate out of every route (DRY).
 */
export async function proxyCall<T>(
  fn: () => Promise<T>,
  cacheControl?: string,
): Promise<NextResponse> {
  try {
    const data = await fn();
    return NextResponse.json(data, {
      headers: cacheControl ? { "Cache-Control": cacheControl } : undefined,
    });
  } catch (e) {
    if (e instanceof UpstreamError) {
      return jsonError(e.message, e.status);
    }
    return jsonError((e as Error).message, 502);
  }
}

/**
 * proxyCall variant for the key-fetch proxy routes (fetchkey, fetchkey-opg).
 *
 * The server helpers return a bare KeybaseKeyByIDResult[], but the client
 * helpers (fetchKeyByKeyIDClient / fetchKeyFromOpenPGP_orgClient) read
 * `body.keys` — matching the original app's route shape
 * `NextResponse.json({ keys })`. Wrapping here keeps that contract in ONE
 * place (DRY) instead of per-route. NOTE: an unwrapped bare array would be
 * misread by the clients — `body.keys` on a JSON array resolves to
 * Array.prototype.keys (a function), so `body.keys ?? []` never falls back.
 */
export async function proxyKeyCall(
  fn: () => Promise<unknown[]>,
  cacheControl?: string,
): Promise<NextResponse> {
  return proxyCall(async () => ({ keys: await fn() }), cacheControl);
}

/** Extract a query string param with a default. */
export function queryParam(req: NextRequest, name: string, fallback = ""): string {
  return new URL(req.url).searchParams.get(name) ?? fallback;
}
