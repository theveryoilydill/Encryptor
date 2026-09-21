#!/usr/bin/env node
/**
 * Generate src/lib/registry/migrations.generated.ts from migrations/*.sql.
 *
 * WHY: Workers Builds CI runs only `opennextjs-cloudflare build && wrangler
 * deploy` — `wrangler d1 migrations apply` NEVER runs in CI, so a freshly
 * created remote D1 database has no tables and every registry write fails
 * (this was reported on PR #25 as "there are no writes to my database").
 * The worker therefore self-migrates on first DB access; to do that the SQL
 * must be bundled with the worker (Workers have no fs), which is what this
 * generated module provides.
 *
 * Run after adding a migration file:
 *   node scripts/gen-migrations.mjs
 * ...then commit the regenerated file together with the new .sql.
 *
 * # Mr. AI Acting on s183173's Behalf
 */
import { readdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const migrationsDir = fileURLToPath(new URL("../migrations", import.meta.url));
const outFile = fileURLToPath(
	new URL("../src/lib/registry/migrations.generated.ts", import.meta.url),
);

const files = readdirSync(migrationsDir)
	.filter((f) => f.endsWith(".sql"))
	.sort();

if (files.length === 0) {
	console.error("No .sql migration files found in migrations/ — nothing to generate.");
	process.exit(1);
}

const entries = files.map((name) => ({
	id: name.replace(/\.sql$/, ""),
	sql: readFileSync(join(migrationsDir, name), "utf8").trimEnd(),
}));

const header = `/**
 * GENERATED FILE — do not edit by hand.
 * Source of truth: migrations/*.sql via scripts/gen-migrations.mjs
 * Re-run \`node scripts/gen-migrations.mjs\` after adding a migration.
 *
 * Bundled so the worker can self-migrate a fresh D1 database on first
 * access (Workers Builds CI never runs wrangler d1 migrations apply).
 *
 * STATEMENT SPLIT CONSTRAINT (fallback path only): the SQL must not contain
 * a ";" inside string literals or comments — every current migration is
 * pure DDL and satisfies this. The primary path uses D1's native exec().
 *
 * # Mr. AI Acting on s183173's Behalf
 */
`;

const body = `export const REGISTRY_MIGRATIONS: readonly { readonly id: string; readonly sql: string }[] = ${JSON.stringify(entries, null, 2)};
`;

writeFileSync(outFile, header + body);
console.log(
	`Generated ${outFile} with ${entries.length} migration(s): ${entries.map((e) => e.id).join(", ")}`,
);
