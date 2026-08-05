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
    // Use .first() because after a key is configured the user's name appears
    // in BOTH the header "Configure private key" button AND the "Include me"
    // recipient chip ("Test User (you)"). Both come from the same key config,
    // so matching the first one is sufficient and avoids the strict-mode
    // violation from matching both.
    await expect(page.getByText("Test User").first()).toBeVisible({
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

  test("pasted images appear inline in the message with a custom scale slider", async ({ page }) => {
    await page.goto("/");

    // Generate a local key first so we can encrypt + decrypt.
    await page.getByRole("button", { name: /Configure private key/i }).click();
    await page.getByText("Generate a new local key").click();
    await page.getByPlaceholder("Full name").fill("Image Paste Test");
    await page.getByPlaceholder("email@example.com").fill("img@test.com");
    await page.getByPlaceholder("Passphrase (optional)").fill("pass");
    await page.getByRole("button", { name: "Generate key pair" }).click();
    await expect(page.getByText("Image Paste Test").first()).toBeVisible({
      timeout: 30_000,
    });

    // Focus the message textarea.
    const textarea = page.getByPlaceholder(/Type the message you want to encrypt/i);
    await textarea.click();

    // Simulate pasting an image by dispatching a synthetic paste event with
    // a tiny PNG (a 1×1 red pixel). Playwright doesn't have a high-level
    // "paste image" helper, so we construct a ClipboardEvent manually.
    const pngBase64 =
      "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==";
    await page.evaluate(async (b64) => {
      const bytes = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
      const blob = new Blob([bytes], { type: "image/png" });
      const file = new File([blob], "red-pixel.png", { type: "image/png" });
      const dt = new DataTransfer();
      dt.items.add(file);
      const textarea = document.querySelector(
        'textarea[placeholder*="Type the message you want to encrypt"]',
      ) as HTMLTextAreaElement;
      const ev = new ClipboardEvent("paste", {
        clipboardData: dt as unknown as DataTransfer,
        bubbles: true,
        cancelable: true,
      });
      textarea.dispatchEvent(ev);
    }, pngBase64);

    // The inline image marker should appear in the textarea.
    await expect(textarea).toHaveValue(/!\[red-pixel\.png\|50%\]\(envelope:\/\/red-pixel\.png\)/, {
      timeout: 5_000,
    });

    // The InlineImageControls panel should appear with a thumbnail + scale slider.
    await expect(page.getByText(/Inline images \(1\)/)).toBeVisible();
    await expect(page.getByRole("slider", { name: /Scale for red-pixel\.png/i })).toBeVisible();
    // The scale readout span sits next to the slider — use exact match to
    // disambiguate from the textarea content (which also contains "50%"
    // as part of the `|50%|` marker).
    await expect(page.getByText("50%", { exact: true })).toBeVisible();

    // Type a message after the image.
    await textarea.press("End");
    await textarea.type("\n\nThis message has an inline image.");

    // Encrypt + sign.
    await page.getByRole("button", { name: "Encrypt & sign" }).click();
    const passInput = page.getByPlaceholder("Passphrase for the private key");
    await expect(passInput).toBeVisible({ timeout: 15_000 });
    await passInput.fill("pass");
    await page.getByRole("button", { name: "Decrypt & continue" }).click();

    // Wait for the encrypted output.
    await expect(page.locator("textarea").filter({ hasText: "BEGIN PGP MESSAGE" })).toBeVisible({
      timeout: 30_000,
    });
    const encrypted = await page
      .locator("textarea")
      .filter({ hasText: "BEGIN PGP MESSAGE" })
      .inputValue();

    // Switch to the Decrypt tab and paste the encrypted output.
    await page.getByRole("tab", { name: "Decrypt" }).click();
    const decryptInput = page.getByPlaceholder(/BEGIN PGP MESSAGE/i);
    await decryptInput.fill(encrypted);
    await page.getByRole("button", { name: "Decrypt" }).click();

    // Passphrase prompt.
    const passInput2 = page.getByPlaceholder("Passphrase for the private key");
    await expect(passInput2).toBeVisible({ timeout: 15_000 });
    await passInput2.fill("pass");
    await page.getByRole("button", { name: "Decrypt & continue" }).click();

    // The rendered decrypted-message preview should contain the inline image
    // (rendered as an <img> with width: 50%).
    const renderedImage = page.locator(
      'img[alt="red-pixel.png"][style*="width: 50%"]',
    );
    await expect(renderedImage).toBeVisible({ timeout: 30_000 });

    // The "Decrypted message (raw text)" textarea should contain the marker.
    const rawTextarea = page
      .locator("textarea")
      .filter({ hasText: "envelope://red-pixel.png" });
    await expect(rawTextarea).toBeVisible({ timeout: 30_000 });

    // And the typed text should be present too.
    await expect(
      page.locator("textarea").filter({ hasText: "This message has an inline image." }),
    ).toBeVisible();
  });
});
