"use client";

/**
 * Smart input-detection hint chip + the pure PGP armor detector that feeds it.
 *
 * `detectPgpBlock` is intentionally dumb-and-fast (substring checks, first
 * match wins in a fixed priority order: encrypted → signed → public key →
 * private key) so tabs can call it during render with no memoization or
 * effects. It only answers "what does this pasted text look like?" — it
 * never gates or disables any operation.
 *
 * `InputHint` renders one dismissible line of guidance under a textarea.
 * Tones: "info" (brand accent, lightbulb) and "amber" (caution, alert icon).
 */
import { Lightbulb, TriangleAlert, X } from "lucide-react";
import type { ReactNode } from "react";

export type PgpBlockKind = "encrypted" | "signed" | "publickey" | "privatekey";

/** Armor headers, checked in priority order (first match wins). */
const PGP_BLOCK_MARKERS: ReadonlyArray<readonly [PgpBlockKind, string]> = [
  ["encrypted", "-----BEGIN PGP MESSAGE-----"],
  ["signed", "-----BEGIN PGP SIGNED MESSAGE-----"],
  ["publickey", "-----BEGIN PGP PUBLIC KEY BLOCK-----"],
  ["privatekey", "-----BEGIN PGP PRIVATE KEY BLOCK-----"],
];

/**
 * Detect which PGP armor block a pasted text contains. Returns the first
 * matching kind by priority order, or null when nothing recognizable is
 * present (including empty input).
 */
export function detectPgpBlock(text: string): PgpBlockKind | null {
  for (const [kind, marker] of PGP_BLOCK_MARKERS) {
    if (text.includes(marker)) return kind;
  }
  return null;
}

const TONES = {
  info: {
    frame:
      "border-[#0055dc]/20 bg-[#0055dc]/5 text-[#0055dc] dark:border-[#5e94ff]/25 dark:bg-[#5e94ff]/10 dark:text-[#5e94ff]",
    icon: Lightbulb,
  },
  amber: {
    frame:
      "border-amber-300/50 bg-amber-50 text-amber-800 dark:border-amber-500/30 dark:bg-amber-950/30 dark:text-amber-300",
    icon: TriangleAlert,
  },
} as const;

/**
 * One dismissible hint line. Renders nothing for empty children. Announced
 * politely via role="status"; the X button (24px hit area) is optional.
 */
export function InputHint({
  children,
  onDismiss,
  tone = "info",
}: {
  children: ReactNode;
  onDismiss?: () => void;
  tone?: "info" | "amber";
}) {
  if (!children) return null;
  const { frame, icon: Icon } = TONES[tone];
  return (
    <div
      role="status"
      className={`mt-2 flex animate-fade-up items-start gap-2 rounded-lg border px-3 py-2 text-xs ${frame}`}
    >
      <Icon aria-hidden className="mt-0.5 size-3.5 shrink-0" />
      <div className="flex-1">{children}</div>
      {onDismiss && (
        <button
          type="button"
          onClick={onDismiss}
          aria-label="Dismiss hint"
          title="Dismiss hint"
          className="flex size-6 shrink-0 items-center justify-center rounded transition-colors hover:bg-black/5 dark:hover:bg-white/10"
        >
          <X aria-hidden className="size-3.5" />
        </button>
      )}
    </div>
  );
}
