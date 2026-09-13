"use client";

import { useCallback, useState } from "react";

import { FileSignature } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group";
import { ErrorBanner, OutputBlock } from "@/components/pgp/shared";
import type { PrivateKeyConfig } from "@/components/pgp/contracts";
import { signMessage } from "@/lib/pgp/pgp";

export function SignTab({
  privateKey,
  requestDecryptedKey,
}: {
  privateKey: PrivateKeyConfig | null;
  requestDecryptedKey: () => Promise<OpenPGP.PrivateKey>;
}) {
  const [plaintext, setPlaintext] = useState("");
  const [detached, setDetached] = useState(false);
  const [output, setOutput] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSign = useCallback(async () => {
    setError(null);
    setOutput("");
    if (!plaintext.trim()) {
      setError("Enter the text to sign below.");
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
      const signed = await signMessage({
        plaintext,
        privateKey: decryptedKey,
        detached,
      });
      setOutput(signed);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }, [plaintext, privateKey, detached, requestDecryptedKey]);

  return (
    <section
      className="space-y-6"
      onKeyDown={(e) => {
        // Ctrl/Cmd+Enter runs the primary action from anywhere in the tab.
        // Skips while a run is in flight — same guard as the disabled button.
        if ((e.ctrlKey || e.metaKey) && !e.altKey && !e.shiftKey && e.key === "Enter") {
          e.preventDefault();
          if (!busy) void handleSign();
        }
      }}
    >
      <div className="rounded-xl border border-border bg-card p-4 shadow-sm sm:p-6">
        <div className="mb-1.5 flex items-center gap-2">
          <span
            aria-hidden="true"
            className="h-3.5 w-[3px] shrink-0 rounded-full bg-[#0055dc] dark:bg-[#5e94ff]"
          />
          <Label className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
            Text to sign
          </Label>
        </div>
        {!plaintext.trim() && !output && (
          <div className="animate-fade-up mb-3 flex flex-col items-center justify-center rounded-xl border-2 border-dashed border-border bg-muted/30 p-6 text-center sm:p-8">
            <div className="grid size-12 place-items-center rounded-full bg-[#0055dc]/10 dark:bg-[#5e94ff]/10">
              <FileSignature
                aria-hidden="true"
                className="size-7 text-[#0055dc] dark:text-[#5e94ff]"
              />
            </div>
            <p className="mt-3 text-sm font-medium">Enter the text to sign below</p>
          </div>
        )}
        <Textarea
          value={plaintext}
          onChange={(e) => setPlaintext(e.target.value)}
          placeholder="Paste the text you want to sign."
          rows={8}
          spellCheck={false}
          className="text-xs leading-relaxed field-sizing-fixed bg-background dark:bg-input/20"
        />
      </div>

      <div className="rounded-xl border border-border bg-card p-4 shadow-sm sm:p-6">
        <RadioGroup
          value={detached ? "detached" : "cleartext"}
          onValueChange={(v) => setDetached(v === "detached")}
          className="flex flex-wrap gap-5 text-sm"
        >
          <label
            htmlFor="sign-mode-cleartext"
            className="flex items-center gap-2 cursor-pointer select-none"
          >
            <RadioGroupItem
              value="cleartext"
              id="sign-mode-cleartext"
              className="border-neutral-300 dark:border-neutral-600 data-[state=checked]:border-[#0055dc] dark:data-[state=checked]:border-[#5e94ff] data-[state=checked]:ring-1 data-[state=checked]:ring-[#0055dc]/30 dark:data-[state=checked]:ring-[#5e94ff]/30 [&_svg]:fill-[#0055dc] dark:[&_svg]:fill-[#5e94ff]"
            />
            <span>Cleartext signed</span>
          </label>
          <label
            htmlFor="sign-mode-detached"
            className="flex items-center gap-2 cursor-pointer select-none"
          >
            <RadioGroupItem
              value="detached"
              id="sign-mode-detached"
              className="border-neutral-300 dark:border-neutral-600 data-[state=checked]:border-[#0055dc] dark:data-[state=checked]:border-[#5e94ff] data-[state=checked]:ring-1 data-[state=checked]:ring-[#0055dc]/30 dark:data-[state=checked]:ring-[#5e94ff]/30 [&_svg]:fill-[#0055dc] dark:[&_svg]:fill-[#5e94ff]"
            />
            <span>Detached signature</span>
          </label>
        </RadioGroup>
      </div>

      {error && <ErrorBanner message={error} />}

      <div className="flex gap-2">
        <Button
          onClick={handleSign}
          disabled={busy}
          className="bg-[#0055dc] text-white hover:bg-[#0046b8] transition-colors duration-150 press-effect"
        >
          {busy ? "Signing…" : output ? "Re-sign message" : "Sign message"}
        </Button>
      </div>

      {output && (
        <OutputBlock
          title={detached ? "Detached signature" : "Cleartext signed message"}
          output={output}
          operation={detached ? "sign-detached" : "sign-cleartext"}
          onReset={() => {
            setOutput("");
            setPlaintext("");
            setError(null);
          }}
        />
      )}
    </section>
  );
}
