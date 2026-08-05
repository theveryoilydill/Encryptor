import { defineConfig } from "vitest/config";
import path from "node:path";

/**
 * Vitest configuration for unit tests.
 *
 * Unit tests live in `tests/unit/**` and exercise the PGP / Keybase logic
 * with mocked fetch (no real network calls in the default `bun run test`
 * run). Tests that need real Keybase credentials are gated behind the
 * `INTEGRATION=true` env var and skipped otherwise.
 *
 * E2E tests (Playwright) live in `tests/e2e/**` and are run separately
 * via `bun run test:e2e`.
 */
export default defineConfig({
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
  css: {
    // Skip PostCSS processing — we're testing pure TS logic, not styles.
    postcss: { plugins: [] },
  },
  test: {
    environment: "node",
    include: ["tests/unit/**/*.test.ts"],
    // integration tests are skipped unless INTEGRATION=true is set
    env: {
      INTEGRATION: process.env.INTEGRATION ?? "false",
    },
    // triplesec + kbpgp are heavy CommonJS libs; give them room to load
    testTimeout: 30_000,
    hookTimeout: 30_000,
  },
});
