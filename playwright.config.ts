import { defineConfig, devices } from "@playwright/test";

/**
 * Playwright E2E configuration.
 *
 * E2E tests live in `tests/e2e/**` and exercise the full Next.js app via
 * a real browser. They start the Next.js dev server on port 3000, then
 * drive the UI with Playwright.
 *
 * Run locally:   bun run test:e2e
 * Run in CI:     triggered by .github/workflows/e2e.yml
 */
export default defineConfig({
  testDir: "./tests/e2e",
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  workers: process.env.CI ? 1 : undefined,
  reporter: process.env.CI ? [["github"], ["html", { open: "never" }]] : "list",
  timeout: 60_000,
  expect: { timeout: 10_000 },
  use: {
    baseURL: "http://localhost:3000",
    trace: "on-first-retry",
    screenshot: "only-on-failure",
    video: "retain-on-failure",
  },
  projects: [
    {
      name: "chromium",
      use: { ...devices["Desktop Chrome"] },
    },
  ],
  webServer: {
    command: "bun run dev",
    url: "http://localhost:3000",
    reuseExistingServer: !process.env.CI,
    timeout: 120_000,
    stdout: "pipe",
    stderr: "pipe",
  },
});
