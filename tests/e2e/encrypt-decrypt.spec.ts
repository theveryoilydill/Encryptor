/**
 * E2E test: full encrypt → decrypt round-trip using a locally generated key.
 *
 * Verifies the core PGP flow end-to-end through the browser UI:
 *   1. Generate a local key pair in the Configure modal.
 *   2. Switch to the Encrypt tab, type a message, encrypt it.
 *   3. Switch to the Decrypt tab, paste the encrypted output, decrypt it.
 *   4. Verify the decrypted message matches the original plaintext.
 *
 * This test does NOT exercise the Keybase login flow — that requires real
 * credentials and is covered by the unit-test integration suite.
 */
import { expect, test } from "@playwright/test";

test.describe("encrypt-decrypt round-trip", () => {
  test("generates a local key, encrypts, then decrypts the same message", async ({ page }) => {
    await page.goto("/");

    // ---- 1. Generate a local key ----
    await page.getByRole("button", { name: /Configure private key/i }).click();
    await expect(page.getByText("Configure your private key")).toBeVisible();

    // Expand the "Generate a new local key" details element.
    await page.getByText("Generate a new local key").click();

    // Fill in name + email + passphrase.
    await page.getByPlaceholder("Full name").fill("Test User");
    await page.getByPlaceholder("email@example.com").fill("test@example.com");
    await page.getByPlaceholder("Passphrase (optional)").fill("test-pass-123");

    // Generate the key (button text: "Generate key pair").
    await page.getByRole("button", { name: "Generate key pair" }).click();

    // Wait for the modal to close and the header to show the configured key.
    await expect(page.getByText("@Test User").or(page.getByText("Test User"))).toBeVisible({
      timeout: 30_000,
    });

    // ---- 2. Encrypt a message ----
    const plaintext = "Hello, encryptor! This is a test message.";
    const textarea = page.getByPlaceholder(/Type the message you want to encrypt/i);
    await textarea.fill(plaintext);

    await page.getByRole("button", { name: "Encrypt & sign" }).click();

    // The passphrase prompt should appear. Enter the passphrase we set.
    const passInput = page.getByPlaceholder("Passphrase for the private key");
    await expect(passInput).toBeVisible({ timeout: 15_000 });
    await passInput.fill("test-pass-123");
    await page.getByRole("button", { name: "Decrypt & continue" }).click();

    // The encrypted output should appear.
    const outputTextarea = page.locator("textarea").filter({
      hasText: "BEGIN PGP MESSAGE",
    });
    await expect(outputTextarea).toBeVisible({ timeout: 30_000 });

    // Read the encrypted output.
    const encrypted = await outputTextarea.inputValue();
    expect(encrypted).toContain("BEGIN PGP MESSAGE");
    expect(encrypted).toContain("END PGP MESSAGE");

    // ---- 3. Decrypt the message ----
    await page.getByRole("tab", { name: "Decrypt" }).click();

    const decryptInput = page.getByPlaceholder(/BEGIN PGP MESSAGE/i);
    await decryptInput.fill(encrypted);

    await page.getByRole("button", { name: "Decrypt" }).click();

    // Passphrase prompt again.
    const passInput2 = page.getByPlaceholder("Passphrase for the private key");
    await expect(passInput2).toBeVisible({ timeout: 15_000 });
    await passInput2.fill("test-pass-123");
    await page.getByRole("button", { name: "Decrypt & continue" }).click();

    // The decrypted output should match the original plaintext.
    const decryptedTextarea = page.locator("textarea").filter({
      hasText: plaintext,
    });
    await expect(decryptedTextarea).toBeVisible({ timeout: 30_000 });
  });

  test("allows editing the plaintext after encryption completes", async ({ page }) => {
    await page.goto("/");

    // Generate a local key first.
    await page.getByRole("button", { name: /Configure private key/i }).click();
    await page.getByText("Generate a new local key").click();
    await page.getByPlaceholder("Full name").fill("Edit Test");
    await page.getByPlaceholder("email@example.com").fill("edit@test.com");
    await page.getByPlaceholder("Passphrase (optional)").fill("pass");
    await page.getByRole("button", { name: "Generate key pair" }).click();

    await expect(page.getByText("Edit Test").first()).toBeVisible({
      timeout: 30_000,
    });

    // Type and encrypt.
    const textarea = page.getByPlaceholder(/Type the message you want to encrypt/i);
    await textarea.fill("First message");
    await page.getByRole("button", { name: "Encrypt & sign" }).click();

    const passInput = page.getByPlaceholder("Passphrase for the private key");
    await expect(passInput).toBeVisible({ timeout: 15_000 });
    await passInput.fill("pass");
    await page.getByRole("button", { name: "Decrypt & continue" }).click();

    // Wait for encrypted output to appear.
    await expect(page.locator("textarea").filter({ hasText: "BEGIN PGP MESSAGE" })).toBeVisible({
      timeout: 30_000,
    });

    // The textarea should still be editable (not disabled) — verify by
    // changing the value.
    await textarea.fill("Edited message");
    await expect(textarea).toHaveValue("Edited message");

    // The button label should now say "Re-encrypt & sign".
    await expect(page.getByRole("button", { name: "Re-encrypt & sign" })).toBeVisible();
  });
});
