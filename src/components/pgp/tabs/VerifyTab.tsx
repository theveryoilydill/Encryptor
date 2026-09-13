"use client";

import { useCallback, useEffect, useState } from "react";

import { FileSearch } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import {
  CopyButton,
  ErrorBanner,
  ZipDownloadButton,
  KeySourcePill,
  SignerHashLegend,
} from "@/components/pgp/shared";
import type {
  PrivateKeyConfig,
  SignatureInfo,
  VerificationResult,
} from "@/components/pgp/contracts";
import { PROXIES } from "@/components/pgp/contracts";
import {
  detectArmoredFormat,
  verifyAutoDetectWithKeyFetch,
  type ArmoredFormat,
} from "@/lib/pgp/pgp";
import { formatTimestamp } from "@/lib/pgp/signer-info";
import { fetchKeysFromAllSourcesWithLocal } from "@/lib/pgp/key-lookup";
import { getKeyExpiryStatus } from "@/lib/pgp/key-details";
import { InputHint, detectPgpBlock } from "@/components/pgp/InputHint";
import { AsciiDropOverlay, useAsciiTextDrop } from "@/components/pgp/ascii-drop";

/** Plain-text verification report for the clipboard (additive): a compact,
 *  shareable summary of the current result — handy for pasting into an
 *  email or an issue tracker. Pure: derives everything from the result
 *  record (called on click, so the timestamp is always current). */
function buildVerificationReport(result: VerificationResult): string {
  const lines: string[] = [
    "Encryptor — signature verification report",
    `Checked at: ${new Date().toLocaleString()}`,
    result.verified === "valid"
      ? "Result: signature is valid"
      : result.verified === "invalid"
        ? "Result: signature is INVALID"
        : "Result: could not be verified (signer key not found)",
  ];
  result.signatures.forEach((s: SignatureInfo, i: number) => {
    const who = s.username ? `@${s.username}` : s.name || s.email || s.userID || "Unknown key";
    lines.push("", `Signer ${i + 1}: ${who}`);
    lines.push(
      `  Status: ${
        s.verified === "valid"
          ? "verified"
          : s.verified === "invalid"
            ? "invalid"
            : "unknown signer"
      }`,
    );
    if (s.keyID) lines.push(`  Key ID: ${s.keyID}`);
    if (s.fingerprint) lines.push(`  Fingerprint: ${s.fingerprint}`);
    if (s.email) lines.push(`  Email: ${s.email}`);
    if (s.timestampIso) lines.push(`  Signed at: ${formatTimestamp(s.timestampIso)}`);
    if (s.resolvedFrom) lines.push(`  Key source: ${s.resolvedFrom}`);
    if (s.self) lines.push("  Note: signed with your locally configured key");
  });
  return lines.join("\n");
}

export function VerifyTab({ privateKey }: { privateKey: PrivateKeyConfig | null }) {
  const [armored, setArmored] = useState("");
  const [plaintext, setPlaintext] = useState("");
  const [detected, setDetected] = useState<ArmoredFormat | null>(null);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<VerificationResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  // Smart-input hint dismissal, keyed to the exact input content: clearing
  // the textarea (or pasting different content) re-arms the hint without
  // needing a state-reset effect. (Separate from the existing `detected`
  // ArmoredFormat state above — that drives the plaintext field and stays
  // byte-identical in behavior.)
  const [hintDismissedFor, setHintDismissedFor] = useState<string | null>(null);

  // Drag & drop (R10): load armor onto the signature card (PGP-armored text
  // files only) and any text file onto the detached-signature plaintext
  // card (requirePgpArmor: false). Shared hook (ascii-drop.tsx); errors
  // reuse this tab's existing error banner. R11: a successful load ALSO
  // clears any stale error banner — a good drop should never leave an old
  // error up (both cards' onText handlers, onError paths untouched).
  const { dragDepth: sigDragDepth, dropProps: sigDropProps } = useAsciiTextDrop({
    onText: (text) => {
      setArmored(text);
      setError(null);
    },
    onError: (message) => setError(message),
  });
  const { dragDepth: plainDragDepth, dropProps: plainDropProps } = useAsciiTextDrop({
    onText: (text) => {
      setPlaintext(text);
      setError(null);
    },
    onError: (message) => setError(message),
    requirePgpArmor: false,
  });

  // Auto-detect format on input change
  useEffect(() => {
    if (!armored.trim()) {
      setDetected(null);
      return;
    }
    const f = detectArmoredFormat(armored);
    setDetected(f);
  }, [armored]);

  const handleVerify = useCallback(async () => {
    setError(null);
    setResult(null);
    if (!armored.trim()) {
      setError("Paste a signature or cleartext-signed message to verify.");
      return;
    }
    setBusy(true);
    try {
      const res = await verifyAutoDetectWithKeyFetch(
        armored,
        plaintext || undefined,
        async (keyIDs) =>
          // Verification keys: remote keyserver lookup + local self-signer
          // recognition (a locally-configured key resolves its own
          // signatures — shared one-liner with the Decrypt tab; replaces the
          // earlier inline local-key append, which only ever matched the
          // primary key ID and couldn't flag self-signed results).
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
      setResult(res);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }, [armored, plaintext, privateKey]);

  const showPlaintextField = detected === "detached-signature";

  // Cheap substring detection computed during render (no effect needed).
  // Hints never appear for empty input, nor for signed input (that is this
  // tab's job). Dismissal is keyed to the input text, so clearing the field
  // re-arms the hint.
  const detectedBlock = detectPgpBlock(armored);
  const showVerifyHint =
    armored.trim() !== "" &&
    (detectedBlock === "encrypted" ||
      detectedBlock === "publickey" ||
      detectedBlock === "privatekey") &&
    hintDismissedFor !== armored;

  return (
    <section
      className="space-y-6"
      onKeyDown={(e) => {
        // Ctrl/Cmd+Enter runs the primary action from anywhere in the tab.
        // Skips while a run is in flight — same guard as the disabled button.
        if ((e.ctrlKey || e.metaKey) && !e.altKey && !e.shiftKey && e.key === "Enter") {
          e.preventDefault();
          if (!busy) void handleVerify();
        }
      }}
    >
      {/* Signature card doubles as a .asc drop target (R10): relative +
          drop props + overlay (aria-hidden, pointer-events-none) — the
          textarea and paste path are untouched. */}
      <div
        className="relative rounded-xl border border-border bg-card p-4 shadow-sm sm:p-6"
        {...sigDropProps}
      >
        <AsciiDropOverlay active={sigDragDepth > 0} label="Drop to load signature" />
        <div className="mb-1.5 flex items-center gap-2">
          <span
            aria-hidden="true"
            className="h-3.5 w-[3px] shrink-0 rounded-full bg-[#0055dc] dark:bg-[#5e94ff]"
          />
          <Label className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
            Signature or signed message
          </Label>
        </div>
        {!armored.trim() && !result && (
          <div className="animate-fade-up mb-3 flex flex-col items-center justify-center rounded-xl border-2 border-dashed border-border bg-muted/30 p-6 text-center sm:p-8">
            <div className="grid size-12 place-items-center rounded-full bg-[#0055dc]/10 dark:bg-[#5e94ff]/10">
              <FileSearch
                aria-hidden="true"
                className="size-7 text-[#0055dc] dark:text-[#5e94ff]"
              />
            </div>
            <p className="mt-3 text-sm font-medium">
              Paste a signature to verify, or drop a .asc file
            </p>
          </div>
        )}
        <Textarea
          value={armored}
          onChange={(e) => setArmored(e.target.value)}
          placeholder={
            "Paste a cleartext-signed message (-----BEGIN PGP SIGNED MESSAGE-----)\n" +
            "or a detached signature (-----BEGIN PGP SIGNATURE-----)."
          }
          rows={8}
          spellCheck={false}
          className="text-xs leading-relaxed field-sizing-fixed bg-background dark:bg-input/20"
        />
        {showVerifyHint && detectedBlock && (
          <InputHint
            tone={detectedBlock === "encrypted" ? "info" : "amber"}
            onDismiss={() => setHintDismissedFor(armored)}
          >
            {detectedBlock === "encrypted"
              ? "This looks like an encrypted message. The Decrypt tab can open it and will verify signatures automatically."
              : "This looks like a PGP key rather than a signed message."}
          </InputHint>
        )}
      </div>

      {showPlaintextField && (
        // Plaintext card accepts ANY text file (no PGP armor sniff — the
        // field holds the signed plaintext, not armor).
        <div
          className="relative rounded-xl border border-border bg-card p-4 shadow-sm sm:p-6"
          {...plainDropProps}
        >
          <AsciiDropOverlay active={plainDragDepth > 0} label="Drop to load plaintext" />
          <div className="mb-1.5 flex items-center gap-2">
            <span
              aria-hidden="true"
              className="h-3.5 w-[3px] shrink-0 rounded-full bg-[#0055dc] dark:bg-[#5e94ff]"
            />
            <Label className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
              Original plaintext (required for detached signatures)
            </Label>
          </div>
          <Textarea
            value={plaintext}
            onChange={(e) => setPlaintext(e.target.value)}
            placeholder="Paste the plaintext that was signed."
            rows={6}
            spellCheck={false}
            className="text-xs leading-relaxed field-sizing-fixed bg-background dark:bg-input/20"
          />
        </div>
      )}

      {error && <ErrorBanner message={error} />}

      <div className="flex gap-2">
        <Button
          onClick={handleVerify}
          disabled={busy}
          className="bg-[#0055dc] text-white hover:bg-[#0046b8] transition-colors duration-150"
        >
          {busy ? "Verifying…" : "Verify"}
        </Button>
        {(result || error) && (
          <>
            <Button
              variant="ghost"
              onClick={() => {
                setArmored("");
                setPlaintext("");
                setResult(null);
                setError(null);
                setDetected(null);
              }}
              className="transition-colors duration-150"
            >
              Reset
            </Button>
            {result && (
              <CopyButton
                text={buildVerificationReport(result)}
                label="Copy report"
                ariaLabel="Copy verification report as plain text"
              />
            )}
            {result && (
              <ZipDownloadButton
                files={[]}
                operation="verify"
                output={armored}
                signers={result.signatures}
                verificationResult={result}
              />
            )}
          </>
        )}
      </div>

      {result && (
        // result-enter: one-time success ring when the verification result
        // first appears (result resets to null before each verify, so
        // re-runs replay it). Reduced-motion gated in globals.css.
        <div className="result-enter space-y-3">
          <div className="animate-scale-in rounded-xl border border-border bg-card px-4 py-3 shadow-sm">
            <div className="text-sm font-medium tracking-wide mb-2">
              {result.verified === "valid" ? (
                <span className="text-emerald-700 dark:text-emerald-400">✓ Signature is valid</span>
              ) : result.verified === "invalid" ? (
                <span className="text-red-700 dark:text-red-400">✗ Signature is invalid</span>
              ) : (
                <span className="text-foreground">? Signature could not be verified</span>
              )}
            </div>
            {result.signatures.length > 0 && (
              <ul className="space-y-2 text-xs">
                {result.signatures.map((s: SignatureInfo, i) => {
                  const color =
                    s.verified === "valid"
                      ? "text-emerald-700 dark:text-emerald-400"
                      : s.verified === "invalid"
                        ? "text-red-700 dark:text-red-400"
                        : "text-muted-foreground";
                  const label =
                    s.verified === "valid"
                      ? "verified"
                      : s.verified === "invalid"
                        ? "invalid signature"
                        : "unknown signer";
                  const displayName = s.username
                    ? `@${s.username}`
                    : s.name
                      ? s.name
                      : s.email
                        ? s.email
                        : s.userID
                          ? s.userID
                          : "Unknown key";
                  // Signer-key expiry (R10): parity with the Decrypt tab's
                  // SignerBadges (shared.tsx) — same DRY helper, same pill
                  // classes. Only records carrying real expiration data
                  // (currently the local-match path) get a pill; "none" /
                  // unknown → no pill.
                  const expiry =
                    typeof s.expiresAt === "number"
                      ? getKeyExpiryStatus(new Date(s.expiresAt))
                      : null;
                  return (
                    <li key={i} className="space-y-0.5">
                      <div className="flex items-center gap-2">
                        <span className="font-medium text-[#0055dc] dark:text-[#5e94ff]">
                          {displayName}
                        </span>
                        <span className={`font-medium tracking-wide ${color}`}>{label}</span>
                        {/* Where the signer's public key was resolved from —
                            same pill as the Decrypt tab's signed card. */}
                        <KeySourcePill source={s.resolvedFrom} />
                        {/* Self-signer marker — mirrors the Decrypt tab's
                            SignerBadges "you" pill (shared.tsx). */}
                        {s.self && (
                          <span className="inline-flex items-center rounded-full border border-[#0055dc]/30 bg-[#0055dc]/5 px-2 py-0.5 text-[10px] font-medium tracking-wide text-[#0055dc] dark:border-[#5e94ff]/40 dark:bg-[#5e94ff]/10 dark:text-[#5e94ff]">
                            you
                          </span>
                        )}
                        {/* Signer-key expiry (R10): mirrors SignerBadges
                            (shared.tsx) exactly — red Expired / amber
                            Expires-in-N-days pills, only when the record
                            carried real expiration data. */}
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
                          <span className="mr-1 font-sans text-[10px] tracking-wide">Key ID</span>
                          {s.keyID}
                        </span>
                      </div>
                      {(s.name || s.email || s.comment) && !s.username && (
                        <div className="text-[11px] text-muted-foreground flex flex-wrap gap-x-3">
                          {s.name && <span>Name: {s.name}</span>}
                          {s.email && (
                            <span>
                              Email:{" "}
                              <a
                                href={`mailto:${s.email}`}
                                className="text-[#0055dc] hover:underline dark:text-[#5e94ff]"
                              >
                                {s.email}
                              </a>
                            </span>
                          )}
                          {s.comment && <span>Comment: {s.comment}</span>}
                        </div>
                      )}
                      {s.allUserIDs && s.allUserIDs.length > 1 && (
                        <details className="mt-0.5">
                          <summary className="text-[10px] text-muted-foreground cursor-pointer hover:text-foreground">
                            All user IDs ({s.allUserIDs.length})
                          </summary>
                          <ul className="mt-1 space-y-0.5 text-[11px] text-muted-foreground font-mono">
                            {s.allUserIDs.map((uid, j) => (
                              <li key={j} className="break-all">
                                {uid}
                              </li>
                            ))}
                          </ul>
                        </details>
                      )}
                      {s.timestampIso && (
                        <div className="text-[11px] text-muted-foreground">
                          Signed at:{" "}
                          <span className="font-mono">{formatTimestamp(s.timestampIso)}</span>
                        </div>
                      )}
                      {s.fingerprint && (
                        <div className="text-[10px] text-muted-foreground font-mono break-all">
                          <span className="mr-1 font-sans text-[10px] tracking-wide">
                            Fingerprint
                          </span>
                          {s.fingerprint}
                        </div>
                      )}
                    </li>
                  );
                })}
              </ul>
            )}
            {/* What the key ID / fingerprint hex strings mean. */}
            {result.signatures.length > 0 && <SignerHashLegend />}
          </div>
        </div>
      )}
    </section>
  );
}
