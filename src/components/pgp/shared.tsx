"use client";

/**
 * Shared PGP UI building blocks.
 *
 * Logic, strings, and defaults are ported verbatim from the original app
 * (src/components/pgp/PgpApp.tsx in the audit tree) — only the styling is
 * modernized (shadcn/ui + #0055dc accent, 150–200ms transitions, a11y).
 */
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { BadgeCheck, Check, Copy, FileSignature, FileText, Lock } from "lucide-react";
import { toast } from "@/hooks/use-toast";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { envelopeFileToDataUrl, formatFileSize, type EnvelopeFile } from "@/lib/pgp/envelope";
import { findInlineImageMarkers } from "@/lib/pgp/inline-image";
import { formatTimestamp } from "@/lib/pgp/signer-info";
import { getKeyExpiryStatus } from "@/lib/pgp/key-details";
import {
  base64ToUint8Array,
  buildZipBundle,
  downloadBlob,
  zipFilename,
} from "@/lib/pgp/zip-bundle";
import type { SignatureInfo, VerificationResult } from "@/components/pgp/contracts";

/* Accent helpers (design brief: #0055dc, hover #0046b8, dark text #5e94ff). */
const ACCENT_TEXT = "text-[#0055dc] dark:text-[#5e94ff]";

/* -------------------------------- ErrorBanner ------------------------------- */

/** Destructive-tinted error panel. Renders nothing when there is no message. */
export function ErrorBanner({ message }: { message: string | null | undefined }) {
  if (!message) return null;
  return (
    <div
      role="alert"
      className="rounded-lg border border-destructive/30 bg-destructive/10 px-3 py-2 text-xs text-destructive"
    >
      {message}
    </div>
  );
}

/* -------------------------------- CopyButton -------------------------------- */

/** Clipboard write with "Copy" → "Copied!" feedback for 1500ms. The leading
 *  icon swaps Copy → Check (emerald tint) for ~1.6s after a successful copy
 *  (timer cleared on unmount / re-copy). Success and failure are additionally
 *  surfaced as toasts (additive; the button label and timing behavior are
 *  unchanged from the original). */
export function CopyButton({
  text,
  label = "Copy",
  ariaLabel = "Copy output to clipboard",
}: {
  /** The string to copy. */
  text: string;
  /** Visible button label (defaults to "Copy", as in the original). */
  label?: string;
  /** Accessible name (defaults to the original "Copy output to clipboard"). */
  ariaLabel?: string;
}) {
  const [copied, setCopied] = useState(false);
  const [showCheck, setShowCheck] = useState(false);
  const checkTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  // Clear the pending icon-swap timer on unmount.
  useEffect(() => {
    return () => {
      if (checkTimerRef.current) clearTimeout(checkTimerRef.current);
    };
  }, []);

  return (
    <Button
      type="button"
      variant="outline"
      size="sm"
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(text);
          setCopied(true);
          setTimeout(() => setCopied(false), 1500);
          setShowCheck(true);
          if (checkTimerRef.current) clearTimeout(checkTimerRef.current);
          checkTimerRef.current = setTimeout(() => setShowCheck(false), 1600);
          toast({ title: "Copied to clipboard" });
        } catch (e) {
          toast({
            title: "Copy failed",
            description: (e as Error)?.message || "Clipboard unavailable",
            variant: "destructive",
          });
        }
      }}
      className="h-11 gap-1.5 px-3 text-xs transition-colors sm:h-8"
      title="Copy to clipboard"
      aria-label={ariaLabel}
    >
      {showCheck ? (
        <Check aria-hidden="true" className="size-3.5 text-emerald-600 dark:text-emerald-400" />
      ) : (
        <Copy aria-hidden="true" className="size-3.5" />
      )}
      {copied ? "Copied!" : label}
    </Button>
  );
}

/* ----------------------------- ZipDownloadButton ---------------------------- */

/** Button that bundles the output + files + metadata into a ZIP download.
 *  jszip is loaded dynamically by buildZipBundle so it doesn't bloat the
 *  initial client bundle. */
export function ZipDownloadButton({
  files,
  operation,
  output,
  signers,
  verificationResult,
  fileCount,
}: {
  files: EnvelopeFile[];
  operation: string;
  output?: string;
  signers?: SignatureInfo[];
  /** Accepts the structured VerificationResult or a plain status string;
   *  metadata.json always stores the string form (same shape as the original). */
  verificationResult?: VerificationResult | string;
  fileCount?: number;
}) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleDownload = useCallback(async () => {
    setError(null);
    setBusy(true);
    try {
      // Convert EnvelopeFile[] (base64 data) to ZipFileEntry[] (Uint8Array).
      const entries = files.map((f) => ({
        name: f.name,
        data: base64ToUint8Array(f.data),
      }));
      const blob = await buildZipBundle(entries, {
        operation,
        generatedAt: new Date().toISOString(),
        output,
        signers,
        verificationResult:
          typeof verificationResult === "string"
            ? verificationResult
            : verificationResult?.verified,
        fileCount: fileCount ?? entries.length,
      });
      const filename = zipFilename(operation);
      downloadBlob(blob, filename);
      toast({
        title: "ZIP downloaded",
        description: `${filename}${entries.length > 0 ? ` · ${entries.length} file${entries.length === 1 ? "" : "s"}` : ""}`,
      });
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }, [files, operation, output, signers, verificationResult, fileCount]);

  return (
    <div className="flex items-center gap-2">
      {error && <span className="text-[10px] text-red-600 dark:text-red-400">{error}</span>}
      <Button
        type="button"
        variant="outline"
        size="sm"
        onClick={handleDownload}
        disabled={busy}
        className="h-11 gap-1 px-3 text-xs transition-colors sm:h-8"
        title="Download the output + attachments + metadata as a ZIP file"
        aria-label="Download output as a ZIP file"
      >
        {busy ? "Zipping…" : "⬇ ZIP"}
      </Button>
    </div>
  );
}

/* --------------------------- Output title status icon ----------------------- */

/** Small status icon for an output block, derived purely from the title
 *  string (pure function, no props API): Lock for encrypted outputs,
 *  FileSignature for signature/signed outputs, FileText for decrypted text,
 *  BadgeCheck as fallback. "decrypted" is checked first so a decrypted-
 *  message title always maps to FileText. Returns a ready-to-render
 *  aria-hidden element (NOT a component) so callers can inline it without
 *  creating a component during render (react-hooks/static-components). */
function outputStatusIcon(title: string) {
  const cls = "size-3.5 shrink-0 text-[#0055dc] dark:text-[#5e94ff]";
  const t = title.toLowerCase();
  if (t.includes("decrypted")) return <FileText className={cls} aria-hidden="true" />;
  if (t.includes("encrypted")) return <Lock className={cls} aria-hidden="true" />;
  if (t.includes("signature") || t.includes("signed"))
    return <FileSignature className={cls} aria-hidden="true" />;
  return <BadgeCheck className={cls} aria-hidden="true" />;
}

/* ------------------------------ DownloadButton ------------------------------ */

/** Derive a text-file filename from an output title: lowercase,
 *  non-alphanumeric runs → "-", trimmed, + ".txt"
 *  (e.g. "Encrypted + signed message" → "encrypted-signed-message.txt"). */
function outputTitleToFilename(title: string): string {
  const slug = title
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
  return `${slug || "output"}.txt`;
}

/** Small ghost button that downloads the output text as a .txt file.
 *  Additive next to Copy/ZIP in the output actions row; builds a
 *  text/plain Blob client-side and reuses downloadBlob from zip-bundle. */
function DownloadButton({ text, title }: { text: string; title: string }) {
  const handleDownload = useCallback(() => {
    try {
      const blob = new Blob([text], { type: "text/plain;charset=utf-8" });
      downloadBlob(blob, outputTitleToFilename(title));
      toast({ title: "Text file downloaded" });
    } catch (e) {
      toast({
        title: "Download failed",
        description: (e as Error)?.message || "Download unavailable",
        variant: "destructive",
      });
    }
  }, [text, title]);

  return (
    <Button
      type="button"
      variant="outline"
      size="sm"
      onClick={handleDownload}
      className="h-11 gap-1 px-3 text-xs transition-colors sm:h-8"
      title="Download output as a text file"
      aria-label="Download output as a text file"
    >
      ⬇ .txt
    </Button>
  );
}

/* -------------------------------- OutputBlock ------------------------------- */

/** Output section: rendered preview / raw text toggle, ZIP + copy actions,
 *  nuke-input panel, and a "Start over" reset. */
export function OutputBlock({
  title,
  output,
  files,
  preview,
  onNuke,
  nukeLabel,
  onReset,
  signers,
  verificationResult,
  operation,
}: {
  title: string;
  output: string;
  /** When provided, renders a ZIP download button bundling output + files +
   *  metadata (pass [] for a metadata-only bundle). */
  files?: EnvelopeFile[];
  /** When provided, shows a rendered preview of the message (with inline
   *  images) as the primary view. A small toggle switches to the raw
   *  `output` text. Copy/ZIP always act on `output`.
   *  Accepts either a plain string (the envelope plaintext — inline images
   *  are resolved against the top-level `files`) or an object of the shape
   *  `{ text?/plaintext?, files? }`. */
  preview?: string | { text?: string; plaintext?: string; files?: EnvelopeFile[] };
  onNuke?: () => void;
  nukeLabel?: string;
  onReset: () => void;
  signers?: SignatureInfo[];
  verificationResult?: VerificationResult | string;
  /** Operation tag used for the ZIP filename + metadata (e.g. "encrypt",
   *  "decrypt", "sign-cleartext"). Defaults to "output". */
  operation?: string;
}) {
  const [showRaw, setShowRaw] = useState(false);
  const [nuked, setNuked] = useState(false);

  // Re-arm the nuke panel whenever a new output is produced — done via the
  // render-time state adjustment pattern (no effect needed).
  const [prevOutput, setPrevOutput] = useState(output);
  if (prevOutput !== output) {
    setPrevOutput(output);
    setNuked(false);
  }

  const previewText =
    typeof preview === "string" ? preview : (preview?.text ?? preview?.plaintext ?? "");
  const previewFiles =
    typeof preview === "string" ? (files ?? []) : (preview?.files ?? files ?? []);

  // Small status icon in the title row, derived from the title string only.
  const statusIcon = outputStatusIcon(title);

  return (
    <div className={output ? "animate-scale-in glow-accent space-y-3" : "space-y-3"}>
      {/* result-enter: one-time success ring when the output block first
            appears (mounts once per operation — the tabs clear output before
            each run, so re-runs replay it; showRaw toggles do not remount
            this wrapper). Reduced-motion gated in globals.css. */}
      <div className="result-enter">
        <div className="mb-1 flex items-center justify-between gap-2">
          <span className="flex items-center gap-2">
            {statusIcon}
            <span
              aria-hidden
              className="h-3.5 w-[3px] shrink-0 rounded-full bg-[#0055dc] dark:bg-[#5e94ff]"
            />
            {/* Section-label family (R11-b): the tab input cards and the
                Decrypt-tab result rows both render their Label as
                text-xs uppercase tracking-wide muted — the OutputBlock title
                is the same kind of section label, so it joins the family. */}
            <Label className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
              {title}
            </Label>
          </span>
          {preview && (
            <button
              type="button"
              onClick={() => setShowRaw((v) => !v)}
              className="inline-flex min-h-11 items-center text-[10px] text-muted-foreground underline-offset-2 transition-colors hover:text-foreground hover:underline sm:min-h-0"
              title="Toggle between rendered preview and raw text (advanced)"
            >
              {showRaw ? "Show preview" : "Show raw text"}
            </button>
          )}
        </div>
        {preview && !showRaw ? (
          // bg-card (R11-b): this pane floats directly on the page background
          // (tabs render OutputBlock outside any card), so in dark mode it must
          // use the elevated card token like every sibling preview pane
          // (Decrypt-tab preview, SignerBadges) — light mode is unchanged
          // (#ffffff == #ffffff).
          <div className="min-h-[100px] rounded-xl border bg-card px-3.5 py-3 shadow-sm">
            <DecryptedMessageView text={previewText} files={previewFiles} />
          </div>
        ) : (
          <Textarea
            value={output}
            readOnly
            rows={12}
            className="field-sizing-fixed resize-y bg-muted/40 font-mono"
            aria-label={title}
          />
        )}
        <div className="mt-2 flex justify-end gap-2">
          {operation && (
            <ZipDownloadButton
              files={files ?? []}
              operation={operation}
              output={output}
              signers={signers}
              verificationResult={verificationResult}
            />
          )}
          <DownloadButton text={output} title={title} />
          <CopyButton text={output} />
        </div>
      </div>

      {onNuke && (
        <div className="rounded-xl border border-amber-200 bg-amber-50 px-3 py-2.5 shadow-sm dark:border-amber-900/60 dark:bg-amber-950/30">
          {!nuked ? (
            <div className="flex flex-col justify-between gap-2.5 sm:flex-row sm:items-center">
              <p className="text-xs text-amber-800 dark:text-amber-300">
                Your input is still in memory. Nuke it now to make sure only the output remains.
              </p>
              <Button
                type="button"
                onClick={() => {
                  onNuke();
                  setNuked(true);
                }}
                className="h-11 shrink-0 bg-amber-700 px-3 text-xs font-medium text-white transition-colors hover:bg-amber-800 sm:h-8 dark:bg-amber-500 dark:text-amber-950 dark:hover:bg-amber-400"
              >
                {nukeLabel ?? "Nuke input"}
              </Button>
            </div>
          ) : (
            <p className="text-xs text-emerald-700 dark:text-emerald-400">
              ✓ Input nuked. Only the output remains in memory.
            </p>
          )}
        </div>
      )}

      <div className="flex gap-2">
        <Button type="button" variant="ghost" onClick={onReset} className="h-11 text-sm sm:h-9">
          Start over
        </Button>
      </div>
    </div>
  );
}

/* ------------------------------ AttachmentList ------------------------------ */

/** Render the list of files attached to an outgoing encrypted message.
 *  Owns the hidden multi-file input; its value is reset after each change so
 *  selecting the same file again still fires onChange. */
export function AttachmentList({
  attachments,
  onAddFiles,
  onRemove,
}: {
  attachments: EnvelopeFile[];
  onAddFiles: (files: FileList | null) => void;
  onRemove: (index: number) => void;
}) {
  const fileInputRef = useRef<HTMLInputElement>(null);

  return (
    <div className="space-y-2">
      <div className="flex flex-wrap items-center gap-2">
        <Button
          type="button"
          variant="outline"
          onClick={() => fileInputRef.current?.click()}
          className="h-11 text-sm sm:h-9"
        >
          + Add files
        </Button>
        {attachments.length > 0 && (
          <span className="text-[11px] text-muted-foreground">
            {attachments.length} file{attachments.length === 1 ? "" : "s"} ·{" "}
            {formatFileSize(attachments.reduce((sum, f) => sum + f.size, 0))}
          </span>
        )}
      </div>
      {attachments.length > 0 && (
        <ul className="flex flex-wrap gap-2">
          {attachments.map((f, idx) => {
            const isImage = f.type.startsWith("image/");
            const previewUrl = isImage ? envelopeFileToDataUrl(f) : null;
            return (
              <li
                key={`${f.name}-${idx}`}
                className="relative flex items-center gap-2 rounded-lg border bg-background py-1.5 pl-2 pr-7 text-xs shadow-xs transition-shadow hover:shadow-sm"
                title={f.name}
              >
                {previewUrl ? (
                  <img src={previewUrl} alt="" className="size-6 rounded-md object-cover" />
                ) : (
                  <div className="grid size-6 place-items-center rounded-md bg-muted text-[10px] font-medium text-muted-foreground">
                    {f.name.split(".").pop()?.toUpperCase().slice(0, 4) || "FILE"}
                  </div>
                )}
                <div className="min-w-0 max-w-[180px]">
                  <div className="truncate font-medium">{f.name}</div>
                  <div className="text-[10px] text-muted-foreground">{formatFileSize(f.size)}</div>
                </div>
                <button
                  type="button"
                  onClick={() => onRemove(idx)}
                  className="absolute right-1 top-1/2 grid size-6 -translate-y-1/2 place-items-center rounded-full text-base leading-none text-muted-foreground transition-colors hover:bg-destructive/10 hover:text-destructive"
                  aria-label={`Remove ${f.name}`}
                >
                  ×
                </button>
              </li>
            );
          })}
        </ul>
      )}
      <input
        ref={fileInputRef}
        type="file"
        multiple
        className="hidden"
        aria-hidden="true"
        tabIndex={-1}
        onChange={(e) => {
          onAddFiles(e.target.files);
          // reset so selecting the same file again still fires onChange
          e.target.value = "";
        }}
      />
    </div>
  );
}

/* --------------------------- DecryptedMessageView --------------------------- */

/** Render the decrypted message text with inline images.
 *
 *  Splits `text` into a sequence of plain-text and image segments by
 *  scanning for `![alt|NN%[@dx,dy]](envelope://filename)` markers. Each image
 *  segment is resolved to a `data:` URL by looking up `filename` in `files`,
 *  then rendered as an `<img>` with `width: NN%` and `translate(dx, dy)`.
 *
 *  Plain-text segments preserve newlines via `whitespace-pre-wrap` so the
 *  rendered output matches what the sender typed.
 *
 *  If a marker references a filename not present in `files`, a small
 *  "[missing image: NAME]" placeholder is rendered instead of a broken img.
 */
export function DecryptedMessageView({ text, files }: { text: string; files: EnvelopeFile[] }) {
  // Build a filename → data URL map. First match wins (matching the
  // Encrypt-side behavior where deduplicated names are unique).
  const fileMap = useMemo(() => {
    const m = new Map<string, string>();
    for (const f of files) {
      if (!m.has(f.name)) {
        m.set(f.name, envelopeFileToDataUrl(f));
      }
    }
    return m;
  }, [files]);

  // Split plaintext into ordered text/image segments.
  const segments = useMemo(() => {
    const out: Array<
      | { type: "text"; content: string }
      | {
          type: "image";
          filename: string;
          displayName: string;
          scale: number;
          dx: number;
          dy: number;
        }
    > = [];
    const markers = findInlineImageMarkers(text);
    let lastIndex = 0;
    for (const m of markers) {
      if (m.startIndex > lastIndex) {
        out.push({ type: "text", content: text.slice(lastIndex, m.startIndex) });
      }
      out.push({
        type: "image",
        filename: m.filename,
        displayName: m.displayName,
        scale: m.scale,
        dx: m.dx,
        dy: m.dy,
      });
      lastIndex = m.endIndex;
    }
    if (lastIndex < text.length) {
      out.push({ type: "text", content: text.slice(lastIndex) });
    }
    return out;
  }, [text]);

  // Fast path: no inline images at all → just render the text. This is the
  // common case (most messages are text-only) and avoids the extra spans.
  if (segments.length === 1 && segments[0].type === "text") {
    return (
      <div className="whitespace-pre-wrap break-words text-sm leading-relaxed text-foreground">
        {segments[0].content}
      </div>
    );
  }

  return (
    <div className="whitespace-pre-wrap break-words text-sm leading-relaxed text-foreground">
      {segments.map((seg, i) => {
        if (seg.type === "text") {
          return <span key={i}>{seg.content}</span>;
        }
        const src = fileMap.get(seg.filename);
        if (!src) {
          return (
            <span
              key={i}
              className="mx-1 inline-block rounded border border-red-200 bg-red-50 px-2 py-0.5 text-[11px] italic text-red-700 dark:border-red-900 dark:bg-red-950/40 dark:text-red-400"
            >
              [missing image: {seg.displayName}]
            </span>
          );
        }
        return (
          <span
            key={i}
            className="my-1 inline-block align-middle"
            style={{ transform: `translate(${seg.dx}px, ${seg.dy}px)` }}
          >
            <img
              src={src}
              alt={seg.displayName}
              style={{ width: `${seg.scale}%`, maxWidth: "100%", minHeight: "20px" }}
              className="my-1 rounded border border-border"
            />
          </span>
        );
      })}
    </div>
  );
}

/* ------------------------------- SignerBadges ------------------------------- */

/** "Signed by" panel describing each signature found on a message. */
export function SignerBadges({ signatures }: { signatures: SignatureInfo[] }) {
  return (
    <div className="rounded-xl border bg-muted/40 p-4 shadow-sm">
      <div className="mb-1.5 text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
        Signed by
      </div>
      <ul className="space-y-2">
        {signatures.map((s, i) => {
          const color =
            s.verified === "valid"
              ? "border-emerald-200 bg-emerald-100 text-emerald-800 dark:border-emerald-900 dark:bg-emerald-950/40 dark:text-emerald-300"
              : s.verified === "invalid"
                ? "border-red-200 bg-red-100 text-red-800 dark:border-red-900 dark:bg-red-950/40 dark:text-red-300"
                : "border-border bg-muted text-muted-foreground";
          const label =
            s.verified === "valid"
              ? "verified"
              : s.verified === "invalid"
                ? "invalid signature"
                : "unknown signer";
          // Build the display name: prefer Keybase username, then full name,
          // then email, then raw userID, then fall back to "Unknown key".
          const displayName = s.username
            ? `@${s.username}`
            : s.name
              ? s.name
              : s.email
                ? s.email
                : s.userID
                  ? s.userID
                  : "Unknown key";
          // Signer-key expiry (R9): only when the verification record carried
          // real expiration data (currently the local-match path). Same DRY
          // helper + pill classes as the RecipientPicker chips.
          const expiry =
            typeof s.expiresAt === "number" ? getKeyExpiryStatus(new Date(s.expiresAt)) : null;
          return (
            <li key={i} className="text-sm">
              <div className="flex flex-wrap items-center gap-2">
                <span className={`font-medium ${ACCENT_TEXT}`}>{displayName}</span>
                <span
                  className={`inline-flex items-center rounded-full border px-2 py-0.5 text-[10px] font-medium tracking-wide ${color}`}
                >
                  {label}
                </span>
                {/* Self-signer marker: the signature verified against the
                    user's own locally-configured key (never published to
                    keyservers, hence resolved locally — R7). */}
                {s.self && (
                  <span className="inline-flex items-center rounded-full border border-[#0055dc]/30 bg-[#0055dc]/5 px-2 py-0.5 text-[10px] font-medium tracking-wide text-[#0055dc] dark:border-[#5e94ff]/40 dark:bg-[#5e94ff]/10 dark:text-[#5e94ff]">
                    you
                  </span>
                )}
                {/* Signer-key expiry (R9): rendered only when the verification
                    record carried real expiration data (currently the local-
                    match path). Same red/amber pills as the RecipientPicker
                    chips. "none"/unknown → no pill. */}
                {expiry?.status === "expired" && (
                  <span className="shrink-0 rounded-full bg-red-100 px-1.5 py-0.5 text-[10px] font-medium text-red-800 dark:bg-red-950/50 dark:text-red-300">
                    Expired
                  </span>
                )}
                {expiry?.status === "expiring" && (
                  <span className="shrink-0 rounded-full bg-amber-100 px-1.5 py-0.5 text-[10px] font-medium text-amber-800 dark:bg-amber-950/50 dark:text-amber-300">
                    {expiry.label}
                  </span>
                )}
                <span className="ml-auto font-mono text-[11px] text-muted-foreground">
                  {s.keyID}
                </span>
              </div>
              {/* Secondary info line: name + email + comment (if available and
                  not already used as the display name). */}
              {(s.name || s.email || s.comment) &&
                !s.username && (
                  // Wrap rhythm (R9-b): horizontal separation unchanged (8px);
                  // wrapped rows tighten to the 2px inter-row rhythm (mt-0.5)
                  // instead of the looser all-axis 8px gap on narrow widths.
                  <div className="mt-0.5 flex flex-wrap gap-x-2 gap-y-0.5 text-[11px] text-muted-foreground">
                    {s.name && <span>Name: {s.name}</span>}
                    {s.email && (
                      <span>
                        Email:{" "}
                        <a href={`mailto:${s.email}`} className={`${ACCENT_TEXT} hover:underline`}>
                          {s.email}
                        </a>
                      </span>
                    )}
                    {s.comment && <span>Comment: {s.comment}</span>}
                  </div>
                )}
              {/* All user IDs (if the key has more than one). */}
              {s.allUserIDs && s.allUserIDs.length > 1 && (
                <details className="mt-1">
                  <summary className="cursor-pointer text-[10px] text-muted-foreground transition-colors hover:text-foreground">
                    All user IDs ({s.allUserIDs.length})
                  </summary>
                  <ul className="mt-1 space-y-0.5 font-mono text-[11px] text-muted-foreground">
                    {s.allUserIDs.map((uid, j) => (
                      <li key={j} className="break-all">
                        {uid}
                      </li>
                    ))}
                  </ul>
                </details>
              )}
              {/* High-precision signing timestamp from the signature notation. */}
              {s.timestampIso && (
                <div className="mt-0.5 text-[11px] text-muted-foreground">
                  Signed at: <span className="font-mono">{formatTimestamp(s.timestampIso)}</span>
                </div>
              )}
              {/* Fingerprint (if available). */}
              {s.fingerprint && (
                <div className="mt-0.5 break-all font-mono text-[10px] text-muted-foreground">
                  {s.fingerprint}
                </div>
              )}
            </li>
          );
        })}
      </ul>
    </div>
  );
}

/* ----------------------------- FileDownloadList ----------------------------- */

/** Render the list of files extracted from a decrypted envelope. */
export function FileDownloadList({ files }: { files: EnvelopeFile[] }) {
  return (
    <div className="rounded-xl border bg-muted/40 p-4 shadow-sm">
      <div className="mb-1.5 flex items-center gap-2">
        <span
          aria-hidden="true"
          className="h-3.5 w-[3px] shrink-0 rounded-full bg-[#0055dc] dark:bg-[#5e94ff]"
        />
        <div className="text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
          Attached files ({files.length})
        </div>
      </div>
      <ul className="space-y-1.5">
        {files.map((f, i) => {
          const isImage = f.type.startsWith("image/");
          const url = envelopeFileToDataUrl(f);
          return (
            <li key={i} className="flex items-center gap-2.5 text-sm">
              {isImage ? (
                <a
                  href={url}
                  download={f.name}
                  className="flex items-center gap-2.5 hover:underline"
                >
                  <img
                    src={url}
                    alt={f.name}
                    className="size-8 rounded border border-border object-cover"
                  />
                  <span className={`font-medium ${ACCENT_TEXT}`}>{f.name}</span>
                </a>
              ) : (
                <a
                  href={url}
                  download={f.name}
                  className="flex items-center gap-2.5 hover:underline"
                >
                  <div className="grid size-8 place-items-center rounded border border-border bg-background text-[9px] font-medium text-muted-foreground">
                    {f.name.split(".").pop()?.toUpperCase().slice(0, 4) || "FILE"}
                  </div>
                  <span className={`font-medium ${ACCENT_TEXT}`}>{f.name}</span>
                </a>
              )}
              <span className="text-[11px] text-muted-foreground">{formatFileSize(f.size)}</span>
              <a
                href={url}
                download={f.name}
                className="ml-auto inline-flex min-h-11 items-center rounded-md border bg-background px-3 text-[11px] font-medium text-foreground shadow-xs transition-colors hover:bg-muted sm:min-h-0 sm:py-1"
                aria-label={`Download ${f.name}`}
              >
                Download
              </a>
            </li>
          );
        })}
      </ul>
    </div>
  );
}
