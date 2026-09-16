/**
 * Registry D1 access layer — the ONLY module that talks to the registry
 * database. Every statement in this file (and its callers) uses prepared
 * statements with bound parameters; string interpolation into SQL is
 * forbidden by design.
 *
 * # Mr. AI Acting on s183173's Behalf
 */
import { getCloudflareContext } from "@opennextjs/cloudflare/cloudflare-context";

import { ensureRegistrySchema } from "./migrate";

/** Minimal structural typing for the D1 binding (no runtime dependency). */
export interface D1Result<T = unknown> {
	results?: T[];
	success: boolean;
	meta?: Record<string, unknown>;
}

export interface D1PreparedStatement {
	bind(...values: unknown[]): D1PreparedStatement;
	run(): Promise<D1Result>;
	all<T = unknown>(): Promise<D1Result<T>>;
	first<T = unknown>(): Promise<T | null>;
}

export interface D1DatabaseLike {
	prepare(sql: string): D1PreparedStatement;
	batch<T = unknown>(statements: D1PreparedStatement[]): Promise<D1Result<T>[]>;
	/** Native D1 multi-statement execution (used by the self-migrator). */
	exec?(sql: string): Promise<unknown>;
}

/** Env bindings + secrets the registry needs (set via wrangler/CF). */
export interface RegistryEnv {
	REGISTRY_DB?: D1DatabaseLike;
	RE_SALT?: string;
	ADMIN_REVOKE_TOKEN?: string;
	/** Cloudflare Turnstile server secret. Writes are captcha-gated ONLY
	 *  when this is set, so local dev + seed scripts keep working and
	 *  production opts in by provisioning the secret. */
	TURNSTILE_SECRET_KEY?: string;
}

/** Fail with a stable HTTP status the routes can pass through. */
export class RegistryError extends Error {
	status: number;
	/** For 429s: seconds until the rate-limit window rolls over. Emitted as
	 *  the Retry-After response header so clients can back off precisely. */
	retryAfterSeconds?: number;
	constructor(message: string, status: number) {
		super(message);
		this.name = "RegistryError";
		this.status = status;
	}
}

/**
 * Build a 429 RegistryError carrying the retry horizon. The server turns
 * this into a Retry-After header; the browser client surfaces it so users
 * see "resets in 42s" instead of an opaque "try again later".
 */
export function tooManyRequests(message: string, retryAfterSeconds: number): RegistryError {
	const err = new RegistryError(message, 429);
	err.retryAfterSeconds = Math.max(1, Math.ceil(retryAfterSeconds));
	return err;
}

/** Outcome of a rate-limit check, with the retry horizon when denied. */
export interface RateLimitOutcome {
	allowed: boolean;
	/** Seconds until the current window rolls over (>=1 when denied). */
	retryAfterSeconds: number;
	/** True when the limiter itself could not reach D1 and the call was
	 *  fail-closed. A denial in this state is an AVAILABILITY problem
	 *  (503), not a client problem (429): "you sent too many requests"
	 *  would be a lie, and a Retry-After horizon is unknowable. */
	limiterDown?: boolean;
}

/** Development-only fallback salt — NEVER used in production builds. */
const DEV_SALT = "encryptor-registry-dev-salt";

/** Resolve the full Cloudflare env (bindings + secrets), or undefined. */
export function getCloudflareEnv(): RegistryEnv | undefined {
	return getCloudflareContext().env as RegistryEnv | undefined;
}

/** Resolve the D1 binding from the Cloudflare context. */
export function getRegistryDB(): D1DatabaseLike {
	const db = getCloudflareEnv()?.REGISTRY_DB;
	if (!db) {
		throw new RegistryError(
			"Registry database is not available (missing REGISTRY_DB binding)",
			503,
		);
	}
	return db;
}

/**
 * Resolve the D1 binding AND guarantee the schema exists. Every registry
 * route uses this instead of getRegistryDB so a freshly created (never
 * migrated) remote D1 database self-heals on first request — Workers Builds
 * CI deploys the worker without ever running `wrangler d1 migrations apply`,
 * which is why production publishes previously failed with opaque 500s.
 */
export async function getRegistryDBReady(): Promise<D1DatabaseLike> {
	const db = getRegistryDB();
	try {
		await ensureRegistrySchema(db);
	} catch (e) {
		console.error("[registry] schema initialization failed:", e);
		throw new RegistryError(
			"Registry schema is initializing or failed to migrate — retry shortly",
			503,
		);
	}
	return db;
}

/**
 * Resolve the rate-limit/privacy salt. In production a missing RE_SALT
 * fails CLOSED (503): a known constant salt would make rate buckets
 * brute-forceable from a DB dump, turning it into an IP-disclosure leak.
 * Local development supplies it via .dev.vars.
 */
function getSalt(): string {
	const salt = getCloudflareEnv()?.RE_SALT;
	if (salt) return salt;
	if (process.env.NODE_ENV === "production") {
		throw new RegistryError("RE_SALT secret is not configured on this deployment", 503);
	}
	return DEV_SALT;
}

/** SHA-256 of a UTF-8 string, as lowercase hex. */
export async function sha256Hex(input: string): Promise<string> {
	const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(input));
	return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/**
 * Constant-time equality for two same-length hex digests. Inputs are
 * always SHA-256 outputs produced by sha256Hex, so length is fixed; the
 * loop still walks every byte to keep timing flat.
 */
export function timingSafeHexEqual(a: string, b: string): boolean {
	if (a.length !== b.length) return false;
	let diff = 0;
	for (let i = 0; i < a.length; i++) {
		diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
	}
	return diff === 0;
}

/** Cryptographically strong random hex string of 2*bytes chars. */
export function randomHex(bytes: number): string {
	const buf = new Uint8Array(bytes);
	crypto.getRandomValues(buf);
	return [...buf].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/** Current time in epoch seconds. */
export function nowSeconds(): number {
	return Math.floor(Date.now() / 1000);
}

/**
 * Fixed-window rate limiter backed by D1. Returns the outcome plus the
 * retry horizon (seconds until the window rolls over) so 429 responses
 * can carry an accurate Retry-After. The bucket key is a salted hash of
 * action+IP+window so raw IPs never reach the database and buckets are
 * unlinkable across windows.
 */
export async function rateLimit(
	db: D1DatabaseLike,
	action: string,
	ip: string,
	limit: number,
	windowSeconds: number,
): Promise<RateLimitOutcome> {
	const window = Math.floor(Date.now() / 1000 / windowSeconds);
	const bucket = await sha256Hex(`${getSalt()}|${action}|${ip}|${window}`);
	const resetAt = (window + 1) * windowSeconds;
	const retryAfter = Math.max(1, resetAt - nowSeconds());
	// Read-first: over-limit requests cost one indexed read and ZERO
	// writes, so abuse cannot exhaust the daily D1 write quota via the
	// limiter itself.
	const existing = await db
		.prepare("SELECT count FROM registry_rate WHERE bucket = ?1")
		.bind(bucket)
		.first<{ count: number }>();
	if (existing && existing.count >= limit) return { allowed: false, retryAfterSeconds: retryAfter };
	const stmt = db
		.prepare(
			`INSERT INTO registry_rate (bucket, count, reset_at) VALUES (?1, 1, ?2)
                         ON CONFLICT (bucket) DO UPDATE SET count = count + 1
                         RETURNING count`,
		)
		.bind(bucket, resetAt);
	const row = await stmt.first<{ count: number }>();
	if ((row?.count ?? 0) > limit) return { allowed: false, retryAfterSeconds: retryAfter };
	// Opportunistic cleanup: ~2% of calls purge expired windows (indexed).
	if (Math.random() < 0.02) {
		await db.prepare("DELETE FROM registry_rate WHERE reset_at < ?1").bind(nowSeconds()).run();
	}
	return { allowed: true, retryAfterSeconds: 0 };
}

/**
 * rateLimit with explicit failure policy: if the limiter itself cannot
 * reach D1 (quota exhaustion, transient errors), PUBLIC READS fail OPEN
 * (availability first) while MUTATIONS fail CLOSED (never lose the gate).
 * Without this, a write-quota outage would turn every route into a 500.
 */
export async function rateLimitSafe(
	db: D1DatabaseLike,
	action: string,
	ip: string,
	limit: number,
	windowSeconds: number,
	failOpen: boolean,
): Promise<RateLimitOutcome> {
	try {
		return await rateLimit(db, action, ip, limit, windowSeconds);
	} catch (e) {
		console.error(`[registry] rate limiter unavailable (${action}):`, e);
		return { allowed: failOpen, retryAfterSeconds: 0, limiterDown: true };
	}
}

/**
 * Enforce a mutation/read rate limit and throw the RIGHT error on denial:
 *
 * - over-limit with a healthy limiter → 429 + Retry-After so clients can
 *   back off precisely ("resets in 42s");
 * - limiter outage on a fail-closed call (D1 unreachable, write quota
 *   exhausted) → 503 with NO Retry-After, because the outage horizon is
 *   unknowable and "too many requests" would blame the client for a
 *   server-side condition (observed live: preview D1 hiccup returned a
 *   misleading 429 with Retry-After: 1, causing immediate retry storms).
 *
 * Shared by every route so the distinction cannot drift site-by-site.
 */
export async function enforceRateLimit(
	db: D1DatabaseLike,
	action: string,
	ip: string,
	limit: number,
	windowSeconds: number,
	tooManyMessage: string,
	failOpen = false,
): Promise<void> {
	const gate = await rateLimitSafe(db, action, ip, limit, windowSeconds, failOpen);
	if (gate.limiterDown) {
		if (failOpen) return; // availability first: public reads proceed unthrottled
		throw new RegistryError("Registry is temporarily unavailable — please try again shortly", 503);
	}
	if (!gate.allowed) {
		throw tooManyRequests(tooManyMessage, gate.retryAfterSeconds);
	}
}

/** Append an audit row (fingerprints and action names only). */
export async function audit(
	db: D1DatabaseLike,
	action: string,
	fingerprint: string | null,
	detail: string | null,
): Promise<void> {
	await db
		.prepare("INSERT INTO registry_audit (at, action, fingerprint, detail) VALUES (?1, ?2, ?3, ?4)")
		.bind(nowSeconds(), action, fingerprint, detail)
		.run();
}

/** Best-effort audit that never throws into the request path. */
export async function auditSafe(
	db: D1DatabaseLike,
	action: string,
	fingerprint: string | null,
	detail: string | null,
): Promise<void> {
	try {
		await audit(db, action, fingerprint, detail);
	} catch {
		// Audit failures must not break the caller; the action already happened.
	}
}
