/**
 * E2E test: sign → verify round-trip using a locally generated key.
 *
 * Verifies the detached-signature flow end-to-end:
 *   1. Generate a local key pair (with passphrase).
 *   2. Switch to the Sign tab, type text, sign it (detached).
 *   3. Switch to the Verify tab, paste the signature + plaintext, verify it.
 *   4. Confirm the verification result says "Signature is valid".
 *
 * Also verifies requirement #4 (no "Nuke plaintext" button on the Sign tab):
 *   the OutputBlock on the Sign tab should NOT show the amber nuke banner.
 */
import { expect, test } from "@playwright/test";

test.describe("sign-verify round-trip", () => {
  test("signs a message and verifies the signature", async ({ page }) => {
    await page.goto("/");

    // ---- 1. Generate a local key ----
    await page.getByRole("button", { name: /Configure private key/i }).click();
    await page.getByText("Generate a new local key").click();
    await page.getByPlaceholder("Full name").fill("Sign Test");
    await page.getByPlaceholder("email@example.com").fill("sign@test.com");
    await page.getByPlaceholder("Passphrase (optional)").fill("pass");
    await page.getByRole("button", { name: "Generate key pair" }).click();
    await expect(page.getByText("Sign Test").first()).toBeVisible({
      timeout: 30_000,
    });

    // ---- 2. Sign a message (detached) ----
    await page.getByRole("tab", { name: "Sign" }).click();

    const plaintext = "This is the text I want to sign.";
    const signTextarea = page.getByPlaceholder("Paste the text you want to sign.");
    await signTextarea.fill(plaintext);

    // Select "Detached signature" radio.
    await page.getByLabel("Detached signature").check();

    await page.getByRole("button", { name: "Sign message" }).click();

    // Passphrase prompt.
    const passInput = page.getByPlaceholder("Passphrase for the private key");
    await expect(passInput).toBeVisible({ timeout: 15_000 });
    await passInput.fill("pass");
    await page.getByRole("button", { name: "Decrypt & continue" }).click();

    // The signature output should appear.
    const sigTextarea = page.locator("textarea").filter({
      hasText: "BEGIN PGP SIGNATURE",
    });
    await expect(sigTextarea).toBeVisible({ timeout: 30_000 });

    const signature = await sigTextarea.inputValue();
    expect(signature).toContain("BEGIN PGP SIGNATURE");

    // Verify the Sign tab does NOT show the "Nuke plaintext" button
    // (requirement #4 from the user).
    await expect(page.getByRole("button", { name: /Nuke plaintext/i })).toHaveCount(0);
    await expect(page.getByText(/Your input is still in memory/i)).toHaveCount(0);

    // ---- 3. Verify the signature ----
    await page.getByRole("tab", { name: "Verify" }).click();

    // Paste the signature into the Verify tab.
    const verifySigTextarea = page.getByPlaceholder(/Paste a cleartext-signed message/i);
    await verifySigTextarea.fill(signature);

    // The Verify tab should auto-detect "detached-signature" format and
    // show the "Original plaintext" field.
    const plaintextInput = page.getByPlaceholder("Paste the plaintext that was signed.");
    await expect(plaintextInput).toBeVisible({ timeout: 5_000 });
    await plaintextInput.fill(plaintext);

    await page.getByRole("button", { name: "Verify" }).click();

    // The result should say "Signature is valid".
    await expect(page.getByText("Signature is valid")).toBeVisible({
      timeout: 30_000,
    });
  });

  test("Sign tab does not show a 'Nuke plaintext' button (requirement #4)", async ({ page }) => {
    await page.goto("/");

    // Generate a key.
    await page.getByRole("button", { name: /Configure private key/i }).click();
    await page.getByText("Generate a new local key").click();
    await page.getByPlaceholder("Full name").fill("Nuke Check");
    await page.getByPlaceholder("email@example.com").fill("n@test.com");
    await page.getByPlaceholder("Passphrase (optional)").fill("p");
    await page.getByRole("button", { name: "Generate key pair" }).click();
    await expect(page.getByText("Nuke Check").first()).toBeVisible({
      timeout: 30_000,
    });

    // Switch to Sign and sign something.
    await page.getByRole("tab", { name: "Sign" }).click();
    await page.getByPlaceholder("Paste the text you want to sign.").fill("nuke check text");
    await page.getByRole("button", { name: "Sign message" }).click();

    const passInput = page.getByPlaceholder("Passphrase for the private key");
    await expect(passInput).toBeVisible({ timeout: 15_000 });
    await passInput.fill("p");
    await page.getByRole("button", { name: "Decrypt & continue" }).click();

    // Wait for the output to render.
    await expect(page.locator("textarea").filter({ hasText: "BEGIN PGP" })).toBeVisible({
      timeout: 30_000,
    });

    // The Sign tab must not render the nuke-plaintext button OR the amber
    // "input is still in memory" banner.
    await expect(page.getByText(/Nuke plaintext/i)).toHaveCount(0);
    await expect(page.getByText(/Your input is still in memory/i)).toHaveCount(0);
  });
});
