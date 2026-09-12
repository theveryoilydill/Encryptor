"use client";

import { useCallback, useMemo, useState } from "react";

import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { RecipientPicker } from "@/components/pgp/RecipientPicker";
import { AttachmentList, ErrorBanner, OutputBlock } from "@/components/pgp/shared";
import { InteractiveMessagePreview } from "@/components/pgp/InteractiveMessagePreview";
import type { PrivateKeyConfig, Recipient } from "@/components/pgp/contracts";
import { encryptAndSign } from "@/lib/pgp/pgp";
import {
  buildPlaintextForEncryption,
  formatFileSize,
  readFileAsBase64,
  type EnvelopeFile,
} from "@/lib/pgp/envelope";
import { buildInlineImageMarker, DEFAULT_INLINE_IMAGE_SCALE } from "@/lib/pgp/inline-image";
import { LIMITS } from "@/lib/constants";
import { InputHint, detectPgpBlock } from "@/components/pgp/InputHint";
import { parseLooseDate } from "@/lib/pgp/key-details";

export function EncryptTab({
  privateKey,
  recipients,
  setRecipients,
  includeSelf,
  onIncludeSelfChange,
  requestDecryptedKey,
}: {
  privateKey: PrivateKeyConfig | null;
  recipients: Recipient[];
  setRecipients: (updater: (prev: Recipient[]) => Recipient[]) => void;
  includeSelf: boolean;
  onIncludeSelfChange: (v: boolean) => void;
  requestDecryptedKey: () => Promise<OpenPGP.PrivateKey>;
}) {
  const [plaintext, setPlaintext] = useState("");
  const [attachments, setAttachments] = useState<EnvelopeFile[]>([]);
  const [output, setOutput] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  // Drag & drop depth counter (avoids flicker when crossing child elements).
  const [dragDepth, setDragDepth] = useState(0);
  // Smart-input hint dismissal, keyed to the exact message content: clearing
  // the textarea (or typing different content) re-arms the hint without
  // needing a state-reset effect.
  const [hintDismissedFor, setHintDismissedFor] = useState<string | null>(null);

  // Derive the user's own public key from the configured private key.
  // Shown as a recipient chip when "Include me" is checked.
  const selfRecipient = useMemo<Recipient | null>(() => {
    if (!privateKey) return null;
    const info = privateKey.info;
    return {
      source: "local",
      label:
        privateKey.source === "keybase"
          ? `@${privateKey.username} (you)`
          : `${privateKey.label} (you)`,
      armored: "", // not needed — we'll inject it directly in handleEncrypt
      fingerprint: info.fingerprint,
      keyID: info.keyID,
      algorithm: info.algorithm,
      expiresAt:
        // parseLooseDate (key-details.ts): the persisted config's
        // expirationTime is a Date right after configure but an ISO STRING
        // after a localStorage reload round-trip — calling .getTime()
        // directly on the string crashed the whole tab on load (R11 fix).
        // It also rejects non-Date/number garbage; a fresh Infinity (never
        // expiring) isn't a string/Date → null, matching the never-expires
        // posture of every other expiresAt consumer.
        parseLooseDate(info.expirationTime)?.getTime() ?? null,
    };
  }, [privateKey]);

  const addFiles = useCallback(async (fileList: FileList | File[]) => {
    setError(null);
    const files = Array.from(fileList);
    if (files.length === 0) return;
    const newOnes: EnvelopeFile[] = [];
    for (const f of files) {
      if (f.size > LIMITS.maxFileBytes) {
        setError(`"${f.name}" is ${formatFileSize(f.size)} — max ${LIMITS.maxFileLabel} per file.`);
        continue;
      }
      try {
        const data = await readFileAsBase64(f);
        newOnes.push({
          name: f.name || "unnamed",
          type: f.type || "application/octet-stream",
          data,
          size: f.size,
        });
      } catch (e) {
        setError(`Failed to read "${f.name}": ${(e as Error).message}`);
      }
    }
    if (newOnes.length > 0) {
      setAttachments((prev) => [...prev, ...newOnes]);
    }
  }, []);

  const handleAddFiles = useCallback(
    (files: FileList | null) => {
      if (files) void addFiles(files);
    },
    [addFiles],
  );

  // Image paste handler — intercepts pasted images and:
  //   1. Adds the image bytes to `attachments` (so they're encrypted into the
  //      envelope and downloadable by the recipient).
  //   2. Inserts an inline image marker at the cursor position in the textarea
  //      so the image renders inline in the message body (not just as a
  //      separate attachment chip). The marker uses the syntax:
  //        ![filename.png|50%](envelope://filename.png)
  //      where `50%` is the rendered-width scale (default 50%, since pasted
  //      screenshots are usually much larger than the message column).
  const handlePaste = useCallback((e: React.ClipboardEvent<HTMLTextAreaElement>) => {
    const items = e.clipboardData?.items;
    if (!items) return;
    const imageItems: DataTransferItem[] = [];
    for (let i = 0; i < items.length; i++) {
      const it = items[i];
      if (it.kind === "file" && it.type.startsWith("image/")) {
        imageItems.push(it);
      }
    }
    if (imageItems.length === 0) return;
    e.preventDefault();

    // Capture the cursor position BEFORE the (async) addFiles call —
    // otherwise the textarea will have lost focus/selection by the time
    // we want to insert the marker.
    const textarea = e.currentTarget;
    const cursorStart = textarea.selectionStart;
    const cursorEnd = textarea.selectionEnd;

    const files = imageItems.map((it) => it.getAsFile()).filter((f): f is File => f !== null);
    if (files.length === 0) return;

    // Resolve a unique filename for each pasted image so the inline marker
    // always references the correct attachment (no duplicate-name ambiguity).
    // We can't read `attachments` here (it's stale in this closure), so we
    // generate the unique name inside the setAttachments updater.
    const defaultNames = files.map((f) => f.name || `pasted-image.png`);
    const defaultTypes = files.map((f) => f.type || "image/png");

    void (async () => {
      // Read all files first so we can do one setAttachments call.
      const readResults: Array<
        { name: string; type: string; data: string; size: number } | { error: string }
      > = [];
      for (let i = 0; i < files.length; i++) {
        const f = files[i];
        if (f.size > LIMITS.maxFileBytes) {
          readResults.push({
            error: `"${f.name}" is ${formatFileSize(f.size)} — max ${LIMITS.maxFileLabel} per file.`,
          });
          continue;
        }
        try {
          const data = await readFileAsBase64(f);
          readResults.push({
            name: defaultNames[i],
            type: defaultTypes[i],
            data,
            size: f.size,
          });
        } catch (err) {
          readResults.push({
            error: `Failed to read "${f.name}": ${(err as Error).message}`,
          });
        }
      }

      // Generate unique filenames + insert inline markers.
      // We do both inside the setAttachments updater so we can deduplicate
      // against the existing attachment list atomically.
      let insertedMarkers: string[] = [];
      setAttachments((prev) => {
        const existing = prev;
        const usedNames = new Set(existing.map((a) => a.name));
        const added: EnvelopeFile[] = [];
        const newMarkers: string[] = [];
        for (const r of readResults) {
          if ("error" in r) {
            setError(r.error);
            continue;
          }
          // Deduplicate: if "cat.png" already exists, try "cat-1.png", "cat-2.png", etc.
          let uniqueName = r.name;
          let counter = 1;
          const dot = r.name.lastIndexOf(".");
          while (usedNames.has(uniqueName)) {
            if (dot > 0) {
              uniqueName = `${r.name.slice(0, dot)}-${counter}${r.name.slice(dot)}`;
            } else {
              uniqueName = `${r.name}-${counter}`;
            }
            counter++;
          }
          usedNames.add(uniqueName);
          added.push({
            name: uniqueName,
            type: r.type,
            data: r.data,
            size: r.size,
          });
          // Default scale 50% — pasted screenshots are typically 2x–4x the
          // message column width, so 50% is a sensible starting size that
          // the user can fine-tune by dragging or using arrow keys.
          newMarkers.push(
            buildInlineImageMarker(uniqueName, DEFAULT_INLINE_IMAGE_SCALE, 0, 0, r.name),
          );
        }
        insertedMarkers = newMarkers;
        return [...existing, ...added];
      });

      // Insert the markers at the captured cursor position.
      if (insertedMarkers.length > 0) {
        const insert = insertedMarkers.join("\n\n");
        setPlaintext((prev) => {
          const before = prev.slice(0, cursorStart);
          const after = prev.slice(cursorEnd);
          // Ensure the marker is on its own line — pad with newlines if
          // the cursor was in the middle of a paragraph.
          const needsLeadingNL = before.length > 0 && !before.endsWith("\n");
          const needsTrailingNL = after.length > 0 && !after.startsWith("\n");
          const paddedInsert =
            (needsLeadingNL ? "\n\n" : "") + insert + (needsTrailingNL ? "\n\n" : "");
          return before + paddedInsert + after;
        });
        // Restore focus + move cursor to just after the inserted markers.
        queueMicrotask(() => {
          textarea.focus();
          const insertLen = insertedMarkers.join("\n\n").length;
          // Account for any padding newlines we added.
          const before = textarea.value.slice(0, cursorStart);
          const after = textarea.value.slice(cursorEnd);
          const needsLeadingNL = before.length > 0 && !before.endsWith("\n");
          const needsTrailingNL = after.length > 0 && !after.startsWith("\n");
          const paddedLen = (needsLeadingNL ? 2 : 0) + insertLen + (needsTrailingNL ? 2 : 0);
          const newPos = cursorStart + paddedLen;
          textarea.setSelectionRange(newPos, newPos);
        });
      }
    })();
  }, []);

  const handleEncrypt = useCallback(async () => {
    setError(null);
    setOutput("");
    if (!plaintext.trim() && attachments.length === 0) {
      setError("Enter a message to encrypt, or attach a file.");
      return;
    }
    if (!privateKey) {
      setError(
        "Configure your private key first (top-right button) to sign the encrypted message.",
      );
      return;
    }

    setBusy(true);
    try {
      // Request the decrypted key — this shows the passphrase prompt.
      // The decrypted key exists only in this local variable and is
      // cleared when the function returns.
      const decryptedKey = await requestDecryptedKey();

      // Build the recipient key list. If "include me" is checked, derive
      // the public key from the decrypted private key.
      const recipientKeys: string[] = recipients.map((r) => r.armored);
      if (includeSelf) {
        try {
          const pubArmored = decryptedKey.toPublic().armor();
          recipientKeys.push(pubArmored);
        } catch {
          // skip self-inclusion on error
        }
      }

      // Wrap plaintext + attachments in the envelope wire format.
      const plaintextForEncryption = buildPlaintextForEncryption(plaintext, attachments);

      // Pass the PrivateKey object directly to avoid re-armoring +
      // re-parsing, which can lose key material for Keybase P3SKB keys.
      const armored = await encryptAndSign({
        plaintext: plaintextForEncryption,
        recipientPublicKeys: recipientKeys,
        signerPrivateKey: decryptedKey,
      });
      setOutput(armored);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }, [plaintext, attachments, recipients, privateKey, includeSelf, requestDecryptedKey]);

  // Cheap substring detection on the MESSAGE textarea, computed during render
  // (no effect needed). Hints never appear for empty input; signed input is
  // not flagged here (signing already-encrypted input is a legitimate flow).
  // Dismissal is keyed to the message text, so clearing the field re-arms
  // the hint.
  const detectedBlock = detectPgpBlock(plaintext);
  const showEncryptHint =
    plaintext.trim() !== "" &&
    (detectedBlock === "encrypted" ||
      detectedBlock === "publickey" ||
      detectedBlock === "privatekey") &&
    hintDismissedFor !== plaintext;

  return (
    <section
      className="relative space-y-6"
      onDragEnter={(e) => {
        if (!e.dataTransfer.types.includes("Files")) return;
        e.preventDefault();
        setDragDepth((d) => d + 1);
      }}
      onDragOver={(e) => {
        if (!e.dataTransfer.types.includes("Files")) return;
        e.preventDefault();
      }}
      onDragLeave={(e) => {
        if (!e.dataTransfer.types.includes("Files")) return;
        setDragDepth((d) => Math.max(0, d - 1));
      }}
      onDrop={(e) => {
        if (!e.dataTransfer.types.includes("Files")) return;
        e.preventDefault();
        setDragDepth(0);
        if (e.dataTransfer.files.length > 0) {
          void addFiles(e.dataTransfer.files);
        }
      }}
    >
      {dragDepth > 0 && (
        <div
          aria-hidden
          className="pointer-events-none absolute inset-0 z-10 flex items-center justify-center rounded-xl border-2 border-dashed border-[#0055dc] bg-[#0055dc]/5 dark:border-[#5e94ff] dark:bg-[#5e94ff]/10 animate-fade-up"
        >
          <span className="rounded-lg bg-background/95 px-4 py-2 text-sm font-medium text-[#0055dc] shadow-sm dark:text-[#5e94ff]">
            Drop files to attach
          </span>
        </div>
      )}
      <RecipientPicker
        recipients={recipients}
        setRecipients={setRecipients}
        selfRecipient={selfRecipient}
        includeSelf={includeSelf}
        onIncludeSelfChange={onIncludeSelfChange}
      />

      <div className="rounded-xl border border-border bg-card p-4 shadow-sm sm:p-6">
        <div className="mb-1.5 flex items-center gap-2">
          <span
            aria-hidden="true"
            className="h-3.5 w-[3px] shrink-0 rounded-full bg-[#0055dc] dark:bg-[#5e94ff]"
          />
          <Label className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
            Message
          </Label>
        </div>
        <Textarea
          value={plaintext}
          onChange={(e) => setPlaintext(e.target.value)}
          onPaste={handlePaste}
          placeholder="Type the message you want to encrypt + sign. You can paste images directly (Ctrl/Cmd+V) — they'll appear inline and you can resize/move them below."
          rows={8}
          spellCheck={false}
          className="text-xs leading-relaxed field-sizing-fixed bg-background dark:bg-input/20"
        />
        {/* Additive char/size counter (visual feedback only; aria-live off —
            announcing every keystroke would be noisy for screen readers). */}
        <div aria-live="off" className="mt-1 text-right text-[10px] text-muted-foreground">
          {plaintext.length.toLocaleString()} chars
          {plaintext.length > 0 && ` · ~${(plaintext.length / 1024).toFixed(1)} KB`}
        </div>
        <p className="mt-1.5 text-[11px] text-muted-foreground">
          Paste images directly into the box, or use “Add files” below to attach any file. Pasted
          images appear in the preview below — drag them with the mouse or use arrow keys (Shift =
          micro-move, Alt = scale) to position and resize.
        </p>
        {showEncryptHint && detectedBlock && (
          <InputHint
            tone={detectedBlock === "encrypted" ? "amber" : "info"}
            onDismiss={() => setHintDismissedFor(plaintext)}
          >
            {detectedBlock === "encrypted"
              ? "This looks like an already-encrypted message. Encrypting it again is rarely what you want."
              : "This looks like a PGP key. Keys are imported in the key configuration dialog, not encrypted as messages."}
          </InputHint>
        )}
      </div>

      {/* Interactive message preview: renders the message with inline images
          and lets the user drag/scale/move each image with the mouse and
          keyboard. This is the primary "what your message looks like" view. */}
      <div className="rounded-xl border border-border bg-card p-4 shadow-sm sm:p-6">
        <div className="mb-1.5 flex items-center gap-2">
          <span
            aria-hidden="true"
            className="h-3.5 w-[3px] shrink-0 rounded-full bg-[#0055dc] dark:bg-[#5e94ff]"
          />
          <Label className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
            Preview
          </Label>
        </div>
        <InteractiveMessagePreview
          plaintext={plaintext}
          files={attachments}
          onChange={setPlaintext}
          emptyPlaceholder="Type a message or paste an image (Ctrl/Cmd+V) to see the preview."
        />
      </div>

      <AttachmentList
        attachments={attachments}
        onAddFiles={handleAddFiles}
        onRemove={(idx) => setAttachments((prev) => prev.filter((_, i) => i !== idx))}
      />

      {error && <ErrorBanner message={error} />}

      <div className="flex gap-2">
        <Button
          onClick={handleEncrypt}
          disabled={busy}
          className="bg-[#0055dc] text-white hover:bg-[#0046b8] transition-colors duration-150"
        >
          {busy ? "Encrypting…" : output ? "Re-encrypt & sign" : "Encrypt & sign"}
        </Button>
      </div>

      {output && (
        <OutputBlock
          title="Encrypted + signed message"
          output={output}
          files={attachments}
          preview={buildPlaintextForEncryption(plaintext, attachments)}
          operation="encrypt"
          nukeLabel="Nuke plaintext"
          onNuke={() => {
            setPlaintext("");
            setAttachments([]);
          }}
          onReset={() => {
            setOutput("");
            setPlaintext("");
            setAttachments([]);
            setError(null);
          }}
        />
      )}
    </section>
  );
}
