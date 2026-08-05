/**
 * E2E smoke test: verifies the app loads and the four tabs render.
 *
 * Run: bun run test:e2e
 */
import { expect, test } from "@playwright/test";

test.describe("app smoke", () => {
  test("loads the home page and shows the Encrypt tab by default", async ({ page }) => {
    await page.goto("/");
    // Header
    await expect(page.getByText("Encryptor").first()).toBeVisible();
    // Default tab
    await expect(page.getByRole("tab", { name: "Encrypt" })).toHaveAttribute(
      "aria-selected",
      "true",
    );
    // Message textarea placeholder
    await expect(page.getByPlaceholder(/Type the message you want to encrypt/i)).toBeVisible();
  });

  test("switches between all four tabs", async ({ page }) => {
    await page.goto("/");
    for (const tabName of ["Decrypt", "Sign", "Verify", "Encrypt"]) {
      await page.getByRole("tab", { name: tabName }).click();
      await expect(page.getByRole("tab", { name: tabName })).toHaveAttribute(
        "aria-selected",
        "true",
      );
    }
  });

  test("opens the configure-private-key modal", async ({ page }) => {
    await page.goto("/");
    await page.getByRole("button", { name: /Configure private key/i }).click();
    await expect(page.getByText("Configure your private key")).toBeVisible();
    await expect(page.getByText("Log in with Keybase")).toBeVisible();
    await expect(page.getByText("Paste a private key")).toBeVisible();
  });
});
