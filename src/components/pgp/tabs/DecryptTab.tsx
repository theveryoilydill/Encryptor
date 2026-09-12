"use client";

import { useCallback, useState } from "react";

import { Lock, LockKeyholeOpen } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import {
  DecryptedMessageView,
  ErrorBanner,
  FileDownloadList,
  OutputBlock,
  SignerBadges,
} from "@/components/pgp/shared";
import type { PrivateKeyConfig, SignatureInfo } from "@/components/pgp/contracts";
import { PROXIES } from "@/components/pgp/contracts";
import {
  decryptAndAutoVerify,
  describeEncryptedMessage,
  type EncryptedMessageMeta,
} from "@/lib/pgp/pgp";
import { parseDecryptedPlaintext, type EnvelopeFile } from "@/lib/pgp/envelope";
import { fetchKeysFromAllSourcesWithLocal } from "@/lib/pgp/key-lookup";
import { InputHint, detectPgpBlock } from "@/components/pgp/InputHint";
import { AsciiDropOverlay, useAsciiTextDrop } from "@/components/pgp/ascii-drop";

export function DecryptTab({
  privateKey,
  requestDecryptedKey,
}: {
  privateKey: PrivateKeyConfig | null;
  requestDecryptedKey: () => Promise<OpenPGP.PrivateKey>;
}) {
  const [armored, setArmored] = useState("");
  const [output, setOutput] = useState<{
    plaintext: string;
    files: EnvelopeFile[];
    signatures: SignatureInfo[];
  } | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  // Hidden toggle: when true, shows the raw decrypted text (with markers)
  // instead of the rendered preview. Defaults to false — the rendered preview
  // is always shown. This is an advanced feature, so the toggle is visually
  // de-emphasized (small, muted text).
  const [showRaw, setShowRaw] = useState(false);
  // Smart-input hint dismissal, keyed to the exact input content: clearing
  // the textarea (or pasting different content) re-arms the hint without
  // needing a state-reset effect.
  const [hintDismissedFor, setHintDismissedFor] = useState<string | null>(null);

  // Drag & drop: load a .asc armor file onto the input card (R10). Shared
  // hook (ascii-drop.tsx) sniffs for a PGP armor header; errors reuse this
  // tab's existing error banner. R11: a successful load ALSO clears any
  // stale error banner — a good drop should never leave an old error up.
  const { dragDepth, dropProps } = useAsciiTextDrop({
    onText: (text) => {
      setArmored(text);
      setError(null);
    },
    onError: (message) => setError(message),
  });

  // Message metadata strip (R9): how many recipient keys the pasted block
  // is encrypted to, and with which public-key algorithms — parsed WITHOUT
  // any secret material (PKESK packet headers only). Parsing is async
  // (openpgp readMessage), so the result is cached per input using the
  // repo's render-time state-adjustment pattern (same as OutputBlock's
  // nuke re-arm, no effect): on input change we synchronously reset to
  // "unknown" and kick off a fresh parse; the promise result only applies
  // if the input is still current, so stale parses are dropped. Gated by
  // detectPgpBlock first so openpgp parsing only runs for plausible PGP
  // MESSAGE blocks; huge inputs are skipped inside the helper itself
  // (MAX_ENCRYPTED_MESSAGE_META_CHARS) to keep typing snappy.
  const [metaState, setMetaState] = useState<{ for: string; meta: EncryptedMessageMeta | null }>(
    () => ({ for: "", meta: null }),
  );
  if (metaState.for !== armored) {
    setMetaState({ for: armored, meta: null });
    const metaInput = armored;
    if (detectPgpBlock(metaInput) === "encrypted") {
      void describeEncryptedMessage(metaInput)
        .then((meta) => {
          setMetaState((prev) => (prev.for === metaInput ? { ...prev, meta } : prev));
        })
        .catch(() => {
          // describeEncryptedMessage is null-on-error by contract; this is
          // belt-and-suspenders against unhandled rejections.
        });
    }
  }
  const messageMeta = metaState.for === armored ? metaState.meta : null;

  const handleDecrypt = useCallback(async () => {
    setError(null);
    setOutput(null);
    if (!armored.trim()) {
      setError("Paste the encrypted PGP message.");
      return;
    }
    if (!privateKey) {
      setError("Configure your private key first (top-right button).");
      return;
    }
    setBusy(true);
    try {
      // Request the decrypted key — shows passphrase prompt.
      // The key exists only in this local variable and is cleared after.
      const decryptedKey = await requestDecryptedKey();

      // Pass the PrivateKey object directly to avoid re-armoring +
      // re-parsing, which can lose key material for Keybase P3SKB keys.
      const result = await decryptAndAutoVerify(
        {
          armoredMessage: armored,
          decryptionPrivateKey: decryptedKey,
          verificationPublicKeys: [],
        },
        async (keyIDs) =>
          // Verification keys: remote keyserver lookup + local self-signer
          // recognition (a locally-configured key resolves its own
          // signatures — shared one-liner with the Verify tab).
          fetchKeysFromAllSourcesWithLocal(
            keyIDs,
            PROXIES.fetchkeyProxy,
            PROXIES.fetchkeyOpgProxy,
            privateKey
              ? {
                  encryptedArmored: privateKey.encryptedArmored,
                  label: privateKey.label,
                }
              : null,
          ),
      );

      // Detect whether the decrypted plaintext is an envelope (text + files)
      // or a plain-text message from an older client.
      const parsed = parseDecryptedPlaintext(result.plaintext);
      setOutput({
        plaintext: parsed.kind === "envelope" ? parsed.envelope.text : parsed.text,
        files: parsed.kind === "envelope" ? parsed.envelope.files : [],
        signatures: result.signatures,
      });
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }, [armored, privateKey, requestDecryptedKey]);

  // Cheap substring detection computed during render (no effect needed).
  // Hints never appear for empty input, nor when the text already looks like
  // a normal encrypted message. Dismissal is keyed to the input text, so
  // clearing the field re-arms the hint.
  const detectedBlock = detectPgpBlock(armored);
  const showDecryptHint =
    armored.trim() !== "" &&
    detectedBlock !== null &&
    detectedBlock !== "encrypted" &&
    hintDismissedFor !== armored;

  return (
    <section className="space-y-6">
      {/* Input card doubles as a .asc drop target (R10): relative + drop
          props + overlay (aria-hidden, pointer-events-none) — the textarea
          and paste path are untouched. */}
      <div
        className="relative rounded-xl border border-border bg-card p-4 shadow-sm sm:p-6"
        {...dropProps}
      >
        <AsciiDropOverlay active={dragDepth > 0} label="Drop to load message" />
        <div className="mb-1.5 flex items-center gap-2">
          <span
            aria-hidden="true"
            className="h-3.5 w-[3px] shrink-0 rounded-full bg-[#0055dc] dark:bg-[#5e94ff]"
          />
          <Label className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
            Encrypted message
          </Label>
          {/* Metadata strip (R9): shown only while the input parses as an
              encrypted message; renders nothing otherwise (no layout
              reservation). Right-aligned like the output-block toggles. */}
          {messageMeta && (
            <span className="ml-auto inline-flex items-center gap-1 text-[11px] text-muted-foreground">
              <Lock aria-hidden="true" className="size-3.5" />
              Encrypted to {messageMeta.recipientKeyCount}{" "}
              {messageMeta.recipientKeyCount === 1 ? "key" : "keys"}
              {messageMeta.publicKeyAlgorithms.length > 0 && (
                <span> · {messageMeta.publicKeyAlgorithms.join(", ")}</span>
              )}
            </span>
          )}
        </div>
        {!armored.trim() && !output && (
          <div className="animate-fade-up mb-3 flex flex-col items-center justify-center rounded-xl border-2 border-dashed border-border bg-muted/30 p-6 text-center sm:p-8">
            <div className="grid size-12 place-items-center rounded-full bg-[#0055dc]/10 dark:bg-[#5e94ff]/10">
              <LockKeyholeOpen
                aria-hidden="true"
                className="size-7 text-[#0055dc] dark:text-[#5e94ff]"
              />
            </div>
            <p className="mt-3 text-sm font-medium">
              Paste an encrypted message, or drop a .asc file
            </p>
            <p className="mt-1 text-xs text-muted-foreground">
              The message is decrypted locally in your browser — nothing leaves this device.
            </p>
          </div>
        )}
        <Textarea
          value={armored}
          onChange={(e) => setArmored(e.target.value)}
          placeholder={"-----BEGIN PGP MESSAGE-----\n...\n-----END PGP MESSAGE-----"}
          rows={10}
          spellCheck={false}
          className="text-xs leading-relaxed field-sizing-fixed bg-background dark:bg-input/20"
        />
        <p className="mt-1.5 text-[11px] text-muted-foreground">
          Or drop a .asc file on this card to load it.
        </p>
        {showDecryptHint && detectedBlock && (
          <InputHint
            tone={detectedBlock === "signed" ? "info" : "amber"}
            onDismiss={() => setHintDismissedFor(armored)}
          >
            {detectedBlock === "signed"
              ? "This looks like a signed (not encrypted) message. The Verify tab is designed for that."
              : "This looks like a PGP key rather than an encrypted message. Keys are managed in the key configuration dialog."}
          </InputHint>
        )}
      </div>

      {error && <ErrorBanner message={error} />}

      <div className="flex gap-2">
        <Button
          onClick={handleDecrypt}
          disabled={busy}
          className="bg-[#0055dc] text-white hover:bg-[#0046b8] transition-colors duration-150"
        >
          {busy ? "Decrypting…" : output ? "Re-decrypt" : "Decrypt"}
        </Button>
      </div>

      {output && (
        <div className="space-y-6">
          {output.signatures.length > 0 && <SignerBadges signatures={output.signatures} />}
          {output.files.length > 0 && <FileDownloadList files={output.files} />}

          {/* Always show the rendered preview as the primary view.
              The raw-text textarea is hidden behind a subtle toggle
              ("Show raw text") — it's an advanced feature. */}
          {/* result-enter: one-time success ring when the decrypted message
              panel first appears (output resets to null before each decrypt,
              so re-runs replay it; showRaw toggles don't remount this
              wrapper). Reduced-motion gated in globals.css. */}
          <div className="result-enter">
            <div className="flex items-center justify-between mb-1">
              <div className="flex items-center gap-2">
                <span
                  aria-hidden="true"
                  className="h-3.5 w-[3px] shrink-0 rounded-full bg-[#0055dc] dark:bg-[#5e94ff]"
                />
                <Label className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
                  Decrypted message
                </Label>
              </div>
              <button
                type="button"
                onClick={() => setShowRaw((v) => !v)}
                className="text-[10px] text-muted-foreground hover:text-foreground underline-offset-2 hover:underline transition-colors duration-150"
                title="Toggle between rendered preview and raw text (advanced)"
              >
                {showRaw ? "Show rendered" : "Show raw text"}
              </button>
            </div>
            {showRaw ? (
              <Textarea
                value={output.plaintext}
                readOnly
                rows={10}
                spellCheck={false}
                className="text-xs leading-relaxed field-sizing-fixed bg-muted/40"
              />
            ) : (
              <div className="rounded-xl border border-border bg-card p-4 shadow-sm min-h-[100px]">
                <DecryptedMessageView text={output.plaintext} files={output.files} />
              </div>
            )}
          </div>

          <OutputBlock
            title="Encrypted message (source)"
            output={armored}
            nukeLabel="Nuke encrypted input"
            onNuke={() => {
              setArmored("");
            }}
            onReset={() => {
              setOutput(null);
              setArmored("");
              setError(null);
              setShowRaw(false);
            }}
            signers={output.signatures}
            files={output.files}
            operation="decrypt"
          />
        </div>
      )}
    </section>
  );
}
