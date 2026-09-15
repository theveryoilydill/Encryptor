/**
 * Registry D1 access layer — the ONLY module that talks to the registry
 * database. Every statement in this file (and its callers) uses prepared
 * statements with bound parameters; string interpolation into SQL is
 * forbidden by design.
 *
 * # Mr. AI Acting on s183173's Behalf
 */
import { getCloudflareContext } from "@opennextjs/cloudflare/cloudflare-context";

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
}

/** Env bindings + secrets the registry needs (set via wrangler/CF). */
export interface RegistryEnv {
	REGISTRY_DB?: D1DatabaseLike;
	RE_SALT?: string;
	ADMIN_REVOKE_TOKEN?: string;
}

/** Fail with a stable HTTP status the routes can pass through. */
export class RegistryError extends Error {
	status: number;
	constructor(message: string, status: number) {
		super(message);
		this.name = "RegistryError";
		this.status = status;
	}
}

/** Development-only fallback salt (production MUST set RE_SALT). */
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

/** Resolve the rate-limit/privacy salt. */
function getSalt(): string {
	return getCloudflareEnv()?.RE_SALT ?? DEV_SALT;
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
 * Fixed-window rate limiter backed by D1. Returns true when the action is
 * allowed. The bucket key is a salted hash of action+IP+window so raw IPs
 * never reach the database and buckets are unlinkable across windows.
 */
export async function rateLimit(
	db: D1DatabaseLike,
	action: string,
	ip: string,
	limit: number,
	windowSeconds: number,
): Promise<boolean> {
	const window = Math.floor(Date.now() / 1000 / windowSeconds);
	const bucket = await sha256Hex(`${getSalt()}|${action}|${ip}|${window}`);
	const resetAt = (window + 1) * windowSeconds;
	const stmt = db
		.prepare(
			`INSERT INTO registry_rate (bucket, count, reset_at) VALUES (?1, 1, ?2)
                         ON CONFLICT (bucket) DO UPDATE SET count = count + 1
                         RETURNING count`,
		)
		.bind(bucket, resetAt);
	const row = await stmt.first<{ count: number }>();
	if ((row?.count ?? 0) > limit) return false;
	// Opportunistic cleanup: ~10% of calls purge expired windows.
	if (Math.random() < 0.1) {
		await db.prepare("DELETE FROM registry_rate WHERE reset_at < ?1").bind(nowSeconds()).run();
	}
	return true;
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
