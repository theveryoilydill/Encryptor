/**
 * E2E test: full encrypt → decrypt round-trip using a locally generated key.
 *
 * Verifies the core PGP flow end-to-end through the browser UI:
 *   1. Generate a local key pair in the Configure modal.
 *   2. Switch to the Encrypt tab, type a message, encrypt it.
 *   3. Switch to the Decrypt tab, paste the encrypted output, decrypt it.
 *   4. Verify the decrypted message matches the original plaintext.
 *
 * The plaintext composer is a contentEditable rendered surface
 * (`[data-content-shell]` wrapping `[data-content-root]`) — there is no longer
 * a <textarea>, so we drive it with click + keyboard.type and read the typed
 * text back from the rendered content root.
 *
 * This test does NOT exercise the Keybase login flow — that requires real
 * credentials and is covered by the unit-test integration suite.
 */
import { expect, test } from "@playwright/test";

// The image-paste test below writes a real PNG to the OS clipboard via the
// async clipboard API, then triggers a genuine Ctrl+V paste. Both clipboard
// permissions are required for that round-trip.
test.use({ permissions: ["clipboard-read", "clipboard-write"] });

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
    // The message composer is a contentEditable rendered surface (no textarea):
    // focus it, type the message, and read it back from the content root.
    const plaintext = "Hello, encryptor! This is a test message.";
    const surface = page.locator("[data-content-shell]").first();
    await expect(surface).toBeVisible({ timeout: 10_000 });
    await surface.click();
    await page.keyboard.type(plaintext);
    await expect(page.locator("[data-content-root]")).toContainText(plaintext, {
      timeout: 5_000,
    });

    await page.getByRole("button", { name: "Encrypt & sign" }).click();

    // The passphrase prompt should appear. Enter the passphrase we set.
    const passInput = page.getByPlaceholder("Passphrase for the private key");
    await expect(passInput).toBeVisible({ timeout: 15_000 });
    await passInput.fill("test-pass-123");
    await page.getByRole("button", { name: "Decrypt & continue" }).click();

    // The encrypted output area should appear. The default view is the
    // rendered preview, so toggle to "Show raw text" to access the
    // encrypted PGP text in a textarea.
    await page.getByText("Show raw text").first().click();
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
    // The Decrypt tab defaults to the rendered preview, so toggle to
    // "Show raw text" to access the raw decrypted text in a textarea.
    await page.getByText("Show raw text").click();
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

    // Type and encrypt. The composer is a contentEditable surface.
    const surface = page.locator("[data-content-shell]").first();
    await expect(surface).toBeVisible({ timeout: 10_000 });
    await surface.click();
    await page.keyboard.type("First message");
    await expect(page.locator("[data-content-root]")).toContainText("First message", {
      timeout: 5_000,
    });
    await page.getByRole("button", { name: "Encrypt & sign" }).click();

    const passInput = page.getByPlaceholder("Passphrase for the private key");
    await expect(passInput).toBeVisible({ timeout: 15_000 });
    await passInput.fill("pass");
    await page.getByRole("button", { name: "Decrypt & continue" }).click();

    // Wait for encrypted output to appear. The default view is the rendered
    // preview, so toggle to "Show raw text" to see the PGP text.
    await page.getByText("Show raw text").first().click();
    await expect(page.locator("textarea").filter({ hasText: "BEGIN PGP MESSAGE" })).toBeVisible({
      timeout: 30_000,
    });
    // Toggle back to preview so the UI is in its default state.
    await page.getByText("Show preview").first().click();

    // The composer should still be editable — select all + replace the text.
    await surface.click();
    await page.keyboard.press("Control+a");
    await page.keyboard.press("Delete");
    await page.keyboard.type("Edited message");
    await expect(page.locator("[data-content-root]")).toContainText("Edited message", {
      timeout: 5_000,
    });

    // The button label should now say "Re-encrypt & sign".
    await expect(page.getByRole("button", { name: "Re-encrypt & sign" })).toBeVisible();
  });

  test("pasted images appear inline in the message and can be scaled with keyboard shortcuts", async ({
    page,
  }) => {
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

    // Focus the contentEditable message surface.
    const surface = page.locator("[data-content-shell]").first();
    await expect(surface).toBeVisible({ timeout: 10_000 });
    await surface.click();

    // Paste an inline image. Browsers ignore synthetic ClipboardEvent paste,
    // so we write a real PNG to the OS clipboard (async clipboard API; the
    // clipboard-read/write permissions are granted above) then dispatch a
    // genuine Ctrl+V — the textarea-free, contentEditable surface honors it.
    const pngBase64 =
      "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==";
    await page.evaluate(async (b64) => {
      const bin = atob(b64);
      const bytes = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
      const blob = new Blob([bytes], { type: "image/png" });
      // ClipboardItem requires the blob's type be a known MIME; image/png is.
      await navigator.clipboard.write([new ClipboardItem({ "image/png": blob })]);
    }, pngBase64);
    // Place the caret in the surface, then trigger a real paste.
    await surface.focus();
    await page.keyboard.press("Control+v");

    // A chip should render inline (an <img> wrapped in a span stamped with the
    // stable reconstruction attributes). Default scale is 50% at origin (0,0).
    const chip = page.locator("[data-content-root] [data-img-filename]").first();
    await expect(chip).toBeAttached({ timeout: 5_000 });
    await expect(chip).toHaveAttribute("data-img-filename", "image.png");
    await expect(chip).toHaveAttribute("data-img-scale", "50");
    await expect(chip).toHaveAttribute("data-img-dx", "0");
    await expect(chip).toHaveAttribute("data-img-dy", "0");
    const img = chip.locator("img");
    await expect(img).toHaveAttribute("alt", "image.png");
    await expect(img).toBeVisible();
    // The attachment list should now list the file too.
    await expect(page.getByRole("button", { name: "Remove image.png" })).toBeVisible();

    // Click the image to select it (the keydown handler only acts on the
    // selected chip).
    await img.click();

    // Alt+ArrowUp increases scale by 5% (50% → 55%).
    await page.keyboard.press("Alt+ArrowUp");
    await expect(chip).toHaveAttribute("data-img-scale", "55", { timeout: 5_000 });

    // Shift+Alt+ArrowUp micro-scales by 1% (55% → 56%).
    await page.keyboard.press("Shift+Alt+ArrowUp");
    await expect(chip).toHaveAttribute("data-img-scale", "56", { timeout: 5_000 });

    // ArrowRight moves by 10px → dx=10.
    await page.keyboard.press("ArrowRight");
    await expect(chip).toHaveAttribute("data-img-dx", "10", { timeout: 5_000 });

    // Shift+ArrowRight micro-moves by 1px → dx=11.
    await page.keyboard.press("Shift+ArrowRight");
    await expect(chip).toHaveAttribute("data-img-dx", "11", { timeout: 5_000 });

    // Deselect with Escape.
    await page.keyboard.press("Escape");

    // Type a message after the image. Move the caret to the end of the
    // content root first, then type.
    await surface.click();
    await page.keyboard.press("End");
    await page.keyboard.type("\n\nThis message has an inline image.");

    // Encrypt + sign.
    await page.getByRole("button", { name: "Encrypt & sign" }).click();
    const passInput = page.getByPlaceholder("Passphrase for the private key");
    await expect(passInput).toBeVisible({ timeout: 15_000 });
    await passInput.fill("pass");
    await page.getByRole("button", { name: "Decrypt & continue" }).click();

    // Wait for the encrypted output — toggle to "Show raw text" since the
    // default view is now the rendered preview.
    await page.getByText("Show raw text").first().click();
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
    // (an <img> rendered at the scale we set via keyboard).
    const renderedImage = page.locator('img[alt="image.png"][style*="width: 56%"]');
    await expect(renderedImage).toBeVisible({ timeout: 30_000 });

    // Toggle to "Show raw text" to verify the raw marker text is present.
    await page.getByText("Show raw text").first().click();
    await expect(
      page.locator("textarea").filter({ hasText: "envelope://image.png" }),
    ).toBeVisible({ timeout: 30_000 });

    // And the typed text should be present too.
    await expect(
      page.locator("textarea").filter({ hasText: "This message has an inline image." }),
    ).toBeVisible({ timeout: 30_000 });
  });

  test("rich text mode round-trips through encrypt + decrypt", async ({ page }) => {
    await page.goto("/");

    // Generate a local key.
    await page.getByRole("button", { name: /Configure private key/i }).click();
    await page.getByText("Generate a new local key").click();
    await page.getByPlaceholder("Full name").fill("Rich Test");
    await page.getByPlaceholder("email@example.com").fill("rich@test.com");
    await page.getByPlaceholder("Passphrase (optional)").fill("pass");
    await page.getByRole("button", { name: "Generate key pair" }).click();
    await expect(page.getByText("Rich Test").first()).toBeVisible({ timeout: 30_000 });

    // Switch to Rich text mode (the "Content mode" selector, distinct from the
    // top-level Encrypt/Decrypt tabs).
    await page.getByRole("tab", { name: "Rich text" }).click();

    // The RichTextEditor (MDXEditor) is lazy-loaded; wait for its contentEditable.
    const editor = page.locator('[contenteditable="true"]').first();
    await expect(editor).toBeVisible({ timeout: 15_000 });
    await editor.click();
    // Type heading + bold. The markdown-shortcut plugin renders these live and
    // the editor serializes back to Markdown on change.
    await page.keyboard.type("# Heading\n");
    await page.keyboard.type("**bold text**");

    // Attach a file so the rich payload wraps in a V2 envelope with kind:"rich"
    // (rich + no files is portable raw Markdown — indistinguishable from
    // plaintext on the wire, so it would decrypt as kind:"text"). The file
    // forces the V2 wire format, exercising the RichTextViewer decrypt path.
    const pngBase64 =
      "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==";
    const fileInput = page.locator('input[type="file"]').first();
    await fileInput.setInputFiles({
      name: "rich-pixel.png",
      mimeType: "image/png",
      buffer: Buffer.from(pngBase64, "base64"),
    });

    await page.getByRole("button", { name: "Encrypt & sign" }).click();
    const passInput = page.getByPlaceholder("Passphrase for the private key");
    await expect(passInput).toBeVisible({ timeout: 15_000 });
    await passInput.fill("pass");
    await page.getByRole("button", { name: "Decrypt & continue" }).click();

    // Grab the encrypted output (raw view).
    await page.getByText("Show raw text").first().click();
    await expect(page.locator("textarea").filter({ hasText: "BEGIN PGP MESSAGE" })).toBeVisible({
      timeout: 30_000,
    });
    const encrypted = await page
      .locator("textarea")
      .filter({ hasText: "BEGIN PGP MESSAGE" })
      .inputValue();
    // The attachment forced a V2 envelope (kind:"rich"). The envelope marker
    // is plaintext INSIDE the PGP armor, so it can't appear in the armored
    // output — only its presence post-decrypt proves the wrap. Sanity-check
    // the armor shape, then verify the V2 kind:"rich" wrap on the Decrypt side
    // (the "Decrypted rich text" label) below.
    expect(encrypted).toContain("BEGIN PGP MESSAGE");
    expect(encrypted).toContain("END PGP MESSAGE");

    // Decrypt.
    await page.getByRole("tab", { name: "Decrypt" }).click();
    await page.getByPlaceholder(/BEGIN PGP MESSAGE/i).fill(encrypted);
    await page.getByRole("button", { name: "Decrypt" }).click();
    const passInput2 = page.getByPlaceholder("Passphrase for the private key");
    await expect(passInput2).toBeVisible({ timeout: 15_000 });
    await passInput2.fill("pass");
    await page.getByRole("button", { name: "Decrypt & continue" }).click();

    // The Decrypt tab renders the rich content in a RichTextViewer (read-only
    // MDXEditor) — the rendered heading + bold, NOT raw Markdown. The label
    // "Decrypted rich text" comes from the kind-branching fix.
    await expect(page.getByText("Decrypted rich text")).toBeVisible({ timeout: 30_000 });
    await expect(page.getByRole("heading", { name: "Heading" })).toBeVisible({ timeout: 30_000 });
    await expect(page.getByText("bold text").first()).toBeVisible({ timeout: 30_000 });

    // Toggling "Show raw text" reveals the stored Markdown (the `text` field).
    await page.getByText("Show raw text").click();
    await expect(
      page.locator("textarea").filter({ hasText: "**bold text**" }),
    ).toBeVisible({ timeout: 10_000 });
  });

  test("graph mode round-trips a whiteboard through encrypt + decrypt", async ({ page }) => {
    await page.goto("/");

    // Generate a local key.
    await page.getByRole("button", { name: /Configure private key/i }).click();
    await page.getByText("Generate a new local key").click();
    await page.getByPlaceholder("Full name").fill("Graph Test");
    await page.getByPlaceholder("email@example.com").fill("graph@test.com");
    await page.getByPlaceholder("Passphrase (optional)").fill("pass");
    await page.getByRole("button", { name: "Generate key pair" }).click();
    await expect(page.getByText("Graph Test").first()).toBeVisible({ timeout: 30_000 });

    // Switch to Graph mode.
    await page.getByRole("tab", { name: "Graph" }).click();

    // Select the sticky tool and click near the top-left of the canvas to place
    // a node (top-left avoids the bottom-right zoom widget intercepting the
    // click). The canvas is lazy-loaded, so wait for it first.
    await page.getByRole("button", { name: "🟪 Sticky" }).click();
    const canvas = page.locator('[data-graph-canvas]').first();
    await expect(canvas).toBeVisible({ timeout: 15_000 });
    await canvas.click({ position: { x: 250, y: 100 } });

    // The newly placed node auto-enters edit mode (a textarea with
    // data-node-editor). Type a label, then commit with Escape.
    const nodeEditor = page.locator('[data-node-editor]').first();
    await expect(nodeEditor).toBeVisible({ timeout: 10_000 });
    await nodeEditor.fill("Graph node label");
    await page.keyboard.press("Escape");

    // The committed node carries its text on data-node-text.
    await expect(page.locator('[data-node-text="Graph node label"]')).toBeVisible({
      timeout: 10_000,
    });

    await page.getByRole("button", { name: "Encrypt & sign" }).click();
    const passInput = page.getByPlaceholder("Passphrase for the private key");
    await expect(passInput).toBeVisible({ timeout: 15_000 });
    await passInput.fill("pass");
    await page.getByRole("button", { name: "Decrypt & continue" }).click();

    // Grab the encrypted output.
    await page.getByText("Show raw text").first().click();
    await expect(page.locator("textarea").filter({ hasText: "BEGIN PGP MESSAGE" })).toBeVisible({
      timeout: 30_000,
    });
    const encrypted = await page
      .locator("textarea")
      .filter({ hasText: "BEGIN PGP MESSAGE" })
      .inputValue();
    // Graph mode always wraps in a V2 kind:"graph" envelope. The marker is
    // plaintext INSIDE the PGP armor so it can't appear in the armored output
    // — the read-only GraphBoard rendered post-decrypt (below) is the proof.
    // Sanity-check the armor shape here.
    expect(encrypted).toContain("BEGIN PGP MESSAGE");
    expect(encrypted).toContain("END PGP MESSAGE");

    // Decrypt.
    await page.getByRole("tab", { name: "Decrypt" }).click();
    await page.getByPlaceholder(/BEGIN PGP MESSAGE/i).fill(encrypted);
    await page.getByRole("button", { name: "Decrypt" }).click();
    const passInput2 = page.getByPlaceholder("Passphrase for the private key");
    await expect(passInput2).toBeVisible({ timeout: 15_000 });
    await passInput2.fill("pass");
    await page.getByRole("button", { name: "Decrypt & continue" }).click();

    // The Decrypt tab renders a read-only GraphBoard with the node's text. The
    // kind-branching fix drives this (previously graph decrypted to blanks).
    await expect(page.getByText("Decrypted whiteboard")).toBeVisible({ timeout: 30_000 });
    await expect(page.locator('[data-graph-canvas]').first()).toBeVisible({ timeout: 30_000 });
    await expect(page.getByText("Graph node label")).toBeVisible({ timeout: 30_000 });
  });
});
