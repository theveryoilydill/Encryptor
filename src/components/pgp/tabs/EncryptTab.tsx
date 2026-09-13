"use client";

import { useCallback, useMemo, useState } from "react";

import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { RecipientPicker } from "@/components/pgp/RecipientPicker";
import { AttachmentList, ErrorBanner, OutputBlock } from "@/components/pgp/shared";
import { MessageEditor } from "@/components/pgp/MessageEditor";
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
import type { AppSettings } from "@/lib/pgp/settings";
import { InputHint, detectPgpBlock } from "@/components/pgp/InputHint";
import { parseLooseDate } from "@/lib/pgp/key-details";

export function EncryptTab({
  privateKey,
  recipients,
  setRecipients,
  includeSelf,
  onIncludeSelfChange,
  requestDecryptedKey,
  settings,
}: {
  privateKey: PrivateKeyConfig | null;
  recipients: Recipient[];
  setRecipients: (updater: (prev: Recipient[]) => Recipient[]) => void;
  includeSelf: boolean;
  onIncludeSelfChange: (v: boolean) => void;
  requestDecryptedKey: () => Promise<OpenPGP.PrivateKey>;
  /** App preferences (compression + editor style) — owned by PgpApp so a
   *  settings change re-renders the open tab immediately. */
  settings: AppSettings;
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

  /** Read + store files, returning the stored entries (with unique names).
   *  Shared by the add-files button/drop and the editor's image paste. */
  const addFilesReturning = useCallback(
    async (fileList: FileList | File[]): Promise<EnvelopeFile[]> => {
      const files = Array.from(fileList);
      const newOnes: EnvelopeFile[] = [];
      let sizeError: string | null = null;
      for (const f of files) {
        if (f.size > LIMITS.maxFileBytes) {
          sizeError = `"${f.name}" is ${formatFileSize(f.size)} — max ${LIMITS.maxFileLabel} per file.`;
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
          sizeError = `Failed to read "${f.name}": ${(e as Error).message}`;
        }
      }
      if (newOnes.length > 0) {
        setAttachments((prev) => {
          // Deduplicate names so inline image markers always reference the
          // right attachment (same rule the old paste path used).
          const usedNames = new Set(prev.map((a) => a.name));
          for (const n of newOnes) {
            if (!usedNames.has(n.name)) {
              usedNames.add(n.name);
              continue;
            }
            const dot = n.name.lastIndexOf(".");
            let counter = 1;
            let unique = n.name;
            while (usedNames.has(unique)) {
              unique =
                dot > 0
                  ? `${n.name.slice(0, dot)}-${counter}${n.name.slice(dot)}`
                  : `${n.name}-${counter}`;
              counter++;
            }
            usedNames.add(unique);
            n.name = unique;
          }
          return [...prev, ...newOnes];
        });
      }
      if (sizeError) setError(sizeError);
      return newOnes;
    },
    [],
  );

  const addFiles = useCallback(
    async (fileList: FileList | File[]) => {
      setError(null);
      if (Array.from(fileList).length === 0) return;
      await addFilesReturning(fileList);
    },
    [addFilesReturning],
  );

  /** Editor paste bridge: store a pasted image (as a data URL) as an
   *  attachment and return the stored entry so the editor can reference it
   *  with an envelope:// marker. Sync by contract — throws on read errors. */
  const handleNewImageDataUrl = useCallback((dataUrl: string): EnvelopeFile => {
    // Parse "data:<mime>;base64,<data>".
    const match = /^data:([^;,]+);base64,([\s\S]*)$/.exec(dataUrl);
    if (!match) throw new Error("Unsupported image data URL.");
    const type = match[1];
    const data = match[2];
    const size = Math.floor(data.length * 0.75);
    if (size > LIMITS.maxFileBytes) {
      throw new Error(`Image is ${formatFileSize(size)} — max ${LIMITS.maxFileLabel}.`);
    }
    const ext = type.split("/")[1]?.replace("jpeg", "jpg") || "png";
    const stored: EnvelopeFile = {
      name: `pasted-image.${ext}`,
      type,
      data,
      size,
    };
    setAttachments((prev) => {
      const usedNames = new Set(prev.map((a) => a.name));
      if (!usedNames.has(stored.name)) return [...prev, stored];
      const dot = stored.name.lastIndexOf(".");
      let counter = 1;
      let unique = stored.name;
      while (usedNames.has(unique)) {
        unique =
          dot > 0
            ? `${stored.name.slice(0, dot)}-${counter}${stored.name.slice(dot)}`
            : `${stored.name}-${counter}`;
        counter++;
      }
      usedNames.add(unique);
      return [...prev, { ...stored, name: unique }];
    });
    return stored;
  }, []);

  const handleAddFiles = useCallback(
    (files: FileList | null) => {
      if (files) void addFiles(files);
    },
    [addFiles],
  );

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
        // User preference: compress by default, at maximum supported
        // compression; "off" maps to the explicit uncompressed preference.
        compression: settings.compression === "off" ? "uncompressed" : settings.compression,
      });
      setOutput(armored);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }, [
    plaintext,
    attachments,
    recipients,
    privateKey,
    includeSelf,
    requestDecryptedKey,
    settings.compression,
  ]);

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
      onKeyDown={(e) => {
        // Ctrl/Cmd+Enter runs the primary action from anywhere in the tab
        // (editor, attachment list, button). Skips while a run is in flight
        // — same guard as the button's disabled state.
        if ((e.ctrlKey || e.metaKey) && !e.altKey && !e.shiftKey && e.key === "Enter") {
          e.preventDefault();
          if (!busy) void handleEncrypt();
        }
      }}
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
        <MessageEditor
          value={plaintext}
          onChange={setPlaintext}
          files={attachments}
          onNewImageDataUrl={handleNewImageDataUrl}
          editorKind={settings.markdownEditor}
          placeholder="Type the message you want to encrypt + sign…"
        />
        {/* Additive char/size counter (visual feedback only; aria-live off —
            announcing every keystroke would be noisy for screen readers). */}
        <div aria-live="off" className="mt-1 text-right text-[10px] text-muted-foreground">
          {plaintext.length.toLocaleString()} chars
          {plaintext.length > 0 && ` · ~${(plaintext.length / 1024).toFixed(1)} KB`}
        </div>
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
          className="bg-[#0055dc] text-white hover:bg-[#0046b8] transition-colors duration-150 press-effect"
        >
          {busy ? "Encrypting…" : output ? "Re-encrypt & sign" : "Encrypt & sign"}
        </Button>
      </div>

      {output && (
        <OutputBlock
          title="Encrypted + signed message"
          output={output}
          files={attachments}
          // Preview the MESSAGE (with inline images resolved against the
          // attachments) — the envelope wire format is an implementation
          // detail the user should never have to look at.
          preview={plaintext}
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
