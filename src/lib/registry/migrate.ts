/**
 * Self-migrating registry schema.
 *
 * WHY THIS EXISTS: Workers Builds CI only deploys the worker —
 * `wrangler d1 migrations apply` never runs in CI, so a freshly created
 * remote D1 database has NO tables and every registry read/write fails with
 * an opaque 500 (reported on PR #25 as "there are no writes to my
 * database"). Instead of asking the operator to remember a manual step,
 * the worker applies the bundled migrations on first DB access, exactly
 * like an embedded database would.
 *
 * Safety properties:
 *  - Memoized per isolate: one cheap SELECT per isolate after the first
 *    request; migrations only run when a version is actually missing.
 *  - Idempotent: CREATE TABLE/INDEX IF NOT EXISTS everywhere; the two
 *    ALTER TABLE statements (0003) tolerate "duplicate column" so a
 *    database previously migrated via wrangler is left untouched.
 *  - Concurrent-isolate safe: two isolates racing the same migration both
 *    produce identical idempotent DDL; SQLite serializes the writes.
 *  - Fail loud: a failed migration clears the memoized promise (the next
 *    request retries) and surfaces as a 503 with a clear message instead
 *    of a generic 500.
 *
 * # Mr. AI Acting on s183173's Behalf
 */
import type { D1DatabaseLike } from "./db";
import { REGISTRY_MIGRATIONS } from "./migrations.generated";

/** Version ledger — separate from wrangler's own d1_migrations table so the
 *  two mechanisms never fight (wrangler remains usable for local setup). */
const LEDGER_TABLE = "registry_schema_migrations";

/** Errors that mean "this object already exists" — treated as applied. */
const ALREADY_APPLIED_RE = /already exists|duplicate column/i;

/** Statement splitter for the fallback path (D1 exec missing). Pure DDL
 *  today: no ";" inside literals or comments (see generated header). */
function splitStatements(sql: string): string[] {
	return sql
		.replace(/^\s*--.*$/gm, "") // strip line comments
		.split(";")
		.map((s) => s.trim())
		.filter(Boolean);
}

/** Execute a multi-statement migration script. D1's native exec() rejects
 *  scripts whose leading content is a comment ("SQL code did not contain a
 *  statement"), so the deterministic path is: strip comments, split on ";",
 *  run each statement as a prepared statement. Pure DDL today — no ";"
 *  inside literals (see the generated file's header constraint). */
async function runMigrationScript(db: D1DatabaseLike, sql: string): Promise<void> {
	for (const statement of splitStatements(sql)) {
		await db.prepare(statement).run();
	}
}

/** All versions present in the ledger (ordered by version string). */
export async function appliedSchemaVersions(db: D1DatabaseLike): Promise<string[]> {
	const rows = await db.prepare(`SELECT version FROM ${LEDGER_TABLE}`).all<{ version: string }>();
	return (rows.results ?? []).map((r) => r.version).sort();
}

/** Apply every bundled migration that the ledger says is missing. */
async function applyMissingMigrations(db: D1DatabaseLike): Promise<void> {
	await db
		.prepare(
			`CREATE TABLE IF NOT EXISTS ${LEDGER_TABLE} (
                                version TEXT PRIMARY KEY,
                                applied_at INTEGER NOT NULL
                        )`,
		)
		.run();
	const applied = new Set(await appliedSchemaVersions(db));
	for (const migration of REGISTRY_MIGRATIONS) {
		if (applied.has(migration.id)) continue;
		try {
			await runMigrationScript(db, migration.sql);
		} catch (e) {
			const message = (e as Error).message ?? "";
			// Tolerate partial application (e.g. the operator already ran
			// `wrangler d1 migrations apply`): the DDL is idempotent by design,
			// so "already exists" is success — anything else is fatal.
			if (!ALREADY_APPLIED_RE.test(message)) throw e;
		}
		await db
			.prepare(
				`INSERT INTO ${LEDGER_TABLE} (version, applied_at) VALUES (?1, ?2)
                                 ON CONFLICT (version) DO NOTHING`,
			)
			.bind(migration.id, Math.floor(Date.now() / 1000))
			.run();
	}
}

/** Memoized per-isolate run. Cleared on failure so the next request retries. */
let schemaPromise: Promise<void> | null = null;

export function ensureRegistrySchema(db: D1DatabaseLike): Promise<void> {
	if (!schemaPromise) {
		schemaPromise = applyMissingMigrations(db).catch((e) => {
			schemaPromise = null;
			throw e;
		});
	}
	return schemaPromise;
}

/** Versions still missing after ensure — normally always empty; the health
 *  endpoint surfaces it so an operator can see drift at a glance. */
export function pendingSchemaVersions(applied: string[]): string[] {
	return REGISTRY_MIGRATIONS.map((m) => m.id).filter((id) => !applied.includes(id));
}

/** Test hook: forget the memoized state between test runs. */
export function resetRegistrySchemaCache(): void {
	schemaPromise = null;
}
