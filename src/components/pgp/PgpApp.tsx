"use client";

import { useCallback, useEffect, useState } from "react";
import { useTheme } from "next-themes";
import { Github, Loader2, Monitor, Moon, ShieldCheck, Sun } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Toaster } from "@/components/ui/toaster";
import { useToast } from "@/hooks/use-toast";
import {
  type KeyRequestState,
  type PrivateKeyConfig,
  type Recipient,
  type Tab,
} from "@/components/pgp/contracts";
import { ConfigureModal } from "@/components/pgp/ConfigureModal";
import { PassphrasePrompt } from "@/components/pgp/PassphrasePrompt";
import { ShortcutsDialog } from "@/components/pgp/ShortcutsDialog";
import { EncryptTab } from "@/components/pgp/tabs/EncryptTab";
import { DecryptTab } from "@/components/pgp/tabs/DecryptTab";
import { SignTab } from "@/components/pgp/tabs/SignTab";
import { VerifyTab } from "@/components/pgp/tabs/VerifyTab";
import { STORAGE_KEYS } from "@/lib/constants";
import { runCryptoSelfTest, type SelfTestResult } from "@/lib/pgp/self-test";
import { loadSettings, saveSettings, type AppSettings } from "@/lib/pgp/settings";

/** Last-active tab id, persisted so the app reopens on the mode the user
 *  was on. Only accepts the exact tab ids used below, else "encrypt". */
function loadLastTab(): Tab {
  try {
    const v = localStorage.getItem(STORAGE_KEYS.lastTab);
    if (v && TABS.some((t) => t.id === v)) return v as Tab;
  } catch {
    // ignore
  }
  return "encrypt";
}

/** Default value for the "include me as recipient" checkbox.
 *  Returns true unless the user has explicitly disabled it. */
function loadIncludeSelfDefault(): boolean {
  try {
    const v = localStorage.getItem(STORAGE_KEYS.includeSelf);
    if (v === "false") return false;
    return true;
  } catch {
    return true;
  }
}

const TABS: { id: Tab; label: string }[] = [
  { id: "encrypt", label: "Encrypt" },
  { id: "decrypt", label: "Decrypt" },
  { id: "sign", label: "Sign" },
  { id: "verify", label: "Verify" },
];

export default function PgpApp() {
  // Lazy initializers are safe here: page.tsx renders this component with
  // ssr:false, so localStorage is always available on first render.
  const [tab, setTab] = useState<Tab>(loadLastTab);
  const { toast } = useToast();
  const [recipients, setRecipients] = useState<Recipient[]>([]);
  // Lazy initializers are safe here: page.tsx renders this component with
  // ssr:false, so localStorage is always available on first render.
  // Only metadata + encrypted key are stored — NEVER the decrypted private
  // key or the passphrase.
  const [privateKey, setPrivateKey] = useState<PrivateKeyConfig | null>(() => {
    try {
      const raw = localStorage.getItem(STORAGE_KEYS.config);
      if (raw) {
        const parsed = JSON.parse(raw) as PrivateKeyConfig;
        if (parsed?.info && (parsed.source === "keybase" || parsed.encryptedArmored)) {
          return parsed;
        }
      }
    } catch {
      // ignore
    }
    return null;
  });
  const [configOpen, setConfigOpen] = useState(false);
  const [includeSelf, setIncludeSelf] = useState<boolean>(loadIncludeSelfDefault);
  // App preferences (compression + editor style). Owned here so the
  // ConfigureModal and the tabs stay in sync without a page reload.
  const [settings, setSettings] = useState<AppSettings>(loadSettings);
  const handleSetSettings = useCallback((next: AppSettings) => {
    setSettings(next);
    saveSettings(next);
  }, []);
  // Screen-reader-only tab-change announcement (see live region below).
  const currentTabLabel = TABS.find((t) => t.id === tab)?.label ?? "Encrypt";

  const handleSetIncludeSelf = useCallback((next: boolean) => {
    setIncludeSelf(next);
    try {
      localStorage.setItem(STORAGE_KEYS.includeSelf, next ? "true" : "false");
    } catch {
      // ignore
    }
  }, []);

  const handleSetPrivateKey = useCallback((next: PrivateKeyConfig | null) => {
    setPrivateKey(next);
    try {
      if (next) {
        localStorage.setItem(STORAGE_KEYS.config, JSON.stringify(next));
      } else {
        localStorage.removeItem(STORAGE_KEYS.config);
      }
    } catch {
      // ignore
    }
  }, []);

  // --- On-demand key decryption (Keybase-style) ---
  // When a tab needs the decrypted private key, it calls requestDecryptedKey().
  // This shows a passphrase prompt. The decrypted key exists only in the
  // promise resolver's scope and is cleared after the operation completes.
  const [keyRequest, setKeyRequest] = useState<KeyRequestState | null>(null);

  const requestDecryptedKey = useCallback((): Promise<OpenPGP.PrivateKey> => {
    return new Promise((resolve, reject) => {
      setKeyRequest({ resolve, reject });
    });
  }, []);

  // Alt+1..4 switches tabs; Ctrl/Cmd+, opens the key settings dialog.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && !e.altKey && !e.shiftKey && e.key === ",") {
        e.preventDefault();
        setConfigOpen(true);
        return;
      }
      if (!e.altKey || e.ctrlKey || e.metaKey || e.shiftKey) return;
      const idx = Number(e.key) - 1;
      if (idx >= 0 && idx < TABS.length) {
        e.preventDefault();
        setTab(TABS[idx].id);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  // Remember the last-used tab so the next visit reopens on it.
  useEffect(() => {
    try {
      localStorage.setItem(STORAGE_KEYS.lastTab, tab);
    } catch {
      // ignore
    }
  }, [tab]);

  // Keyserver warm-up at startup (all modes): the recipient search, signer
  // lookups and key fetches all go through the same origin-proxied routes.
  // Ping them once on mount with a static, non-identifying query so the
  // first real lookup doesn't pay the cold-start cost. Fire-and-forget.
  useEffect(() => {
    const warm = (url: string) => {
      void fetch(url, { priority: "low" }).catch(() => {
        // Warm-up is best-effort; failures are invisible to the user.
      });
    };
    warm("/api/keybase/search-all?q=w");
    warm("/api/keybase/fetchkey?key_id=0000000000000000");
  }, []);

  const handleSelfTest = useCallback(async () => {
    const result: SelfTestResult = await runCryptoSelfTest();
    if (result.ok) {
      toast({
        title: "Crypto self-test passed",
        description: `Key generation, encrypt, decrypt, sign and verify all succeeded in ${result.totalMs} ms.`,
      });
    } else {
      const failed = result.steps.find((s) => !s.ok);
      toast({
        title: "Crypto self-test failed",
        description: `${failed?.name ?? "Unknown step"}: ${failed?.error ?? "unknown error"}`,
        variant: "destructive",
      });
    }
  }, [toast]);

  return (
    <div className="flex min-h-dvh flex-col bg-background text-foreground">
      {/* Screen-reader-only announcement when the active tab changes. */}
      <span aria-hidden={false} className="sr-only" role="status" aria-live="polite">
        {currentTabLabel} tab selected
      </span>

      <Header onConfigure={() => setConfigOpen(true)} privateKey={privateKey} />

      <main className="flex-1 max-w-4xl mx-auto w-full px-4 sm:px-6 lg:px-8 py-6 lg:py-8">
        <Tabs value={tab} onChange={setTab} />

        {/* All four panels stay MOUNTED for the whole session; inactive ones
            get the `hidden` attribute (display:none — unfocusable, out of
            the a11y tree). Drafts and results survive tab switches: peeking
            at another mode can no longer silently discard a half-written
            message, attachments, or pasted armor. The enter animation still
            plays on every switch because .panel-enter is re-added to the
            newly-active panel (removing/adding the class replays it).
            Mount-time effects in the tabs are safe: they all no-op on empty
            input (auto-decrypt, format detection, metadata parsing). */}
        {TABS.map((t) => {
          const active = t.id === tab;
          return (
            <div
              key={t.id}
              role="tabpanel"
              id={`panel-${t.id}`}
              aria-labelledby={`tab-${t.id}`}
              hidden={!active}
              className={`mt-6 ${active ? "panel-enter" : ""}`}
            >
              {t.id === "encrypt" && (
                <EncryptTab
                  privateKey={privateKey}
                  recipients={recipients}
                  setRecipients={setRecipients}
                  includeSelf={includeSelf}
                  onIncludeSelfChange={handleSetIncludeSelf}
                  requestDecryptedKey={requestDecryptedKey}
                  settings={settings}
                />
              )}
              {t.id === "decrypt" && (
                <DecryptTab privateKey={privateKey} requestDecryptedKey={requestDecryptedKey} />
              )}
              {t.id === "sign" && (
                <SignTab privateKey={privateKey} requestDecryptedKey={requestDecryptedKey} />
              )}
              {t.id === "verify" && <VerifyTab privateKey={privateKey} />}
            </div>
          );
        })}
      </main>

      <Footer onSelfTest={handleSelfTest} />

      <ConfigureModal
        open={configOpen}
        onOpenChange={setConfigOpen}
        privateKey={privateKey}
        settings={settings}
        onSettingsChange={handleSetSettings}
        onSave={(next) => {
          handleSetPrivateKey(next);
          setConfigOpen(false);
        }}
        onClear={() => {
          handleSetPrivateKey(null);
          setConfigOpen(false);
        }}
      />

      {keyRequest && privateKey && (
        <PassphrasePrompt
          config={privateKey}
          request={{
            resolve: (key) => {
              keyRequest.resolve(key);
              setKeyRequest(null);
            },
            reject: (err) => {
              keyRequest.reject(err);
              setKeyRequest(null);
            },
          }}
          onKeyUpdated={handleSetPrivateKey}
        />
      )}

      <Toaster />
    </div>
  );
}

/* ---------------------------------- Header --------------------------------- */

function Header({
  onConfigure,
  privateKey,
}: {
  onConfigure: () => void;
  privateKey: PrivateKeyConfig | null;
}) {
  return (
    <header className="relative sticky top-0 z-40 border-b border-border bg-background/85 backdrop-blur-md">
      <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 h-14 flex items-center justify-between gap-2">
        <div className="flex items-center gap-2.5">
          <img src="/logo.svg" alt="Encryptor logo" width={28} height={28} className="rounded" />
          {/* h1: the page's only level-one heading (axe page-has-heading-one);
              styled identically to the previous span. */}
          <h1 className="text-base font-semibold tracking-tight">Encryptor</h1>
        </div>
        <div className="flex items-center gap-2">
          <ThemeToggle />
          <ShortcutsDialog />
          <Button
            variant="outline"
            size="sm"
            onClick={onConfigure}
            className="h-11 gap-2 transition-colors duration-150 hover:border-[#0055dc] hover:text-[#0055dc] dark:hover:border-[#5e94ff] dark:hover:text-[#5e94ff] press-effect sm:h-8"
          >
            <KeyIcon />
            {privateKey ? (
              <span>
                {privateKey.source === "keybase" ? `@${privateKey.username}` : privateKey.label}
              </span>
            ) : (
              <span className="hidden sm:inline">Configure private key</span>
            )}
          </Button>
        </div>
      </div>
      <span
        aria-hidden="true"
        className="pointer-events-none absolute inset-x-0 bottom-0 h-px bg-gradient-to-r from-transparent via-[#0055dc]/30 to-transparent dark:via-[#5e94ff]/30"
      />
    </header>
  );
}

function KeyIcon() {
  return (
    <svg
      width="14"
      height="14"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4" />
    </svg>
  );
}

/* ---------------------------------- Theme ---------------------------------- */

const THEME_ORDER = ["light", "dark", "system"] as const;

function ThemeToggle() {
  const { theme, setTheme } = useTheme();
  const current = (THEME_ORDER as readonly string[]).includes(theme ?? "")
    ? (theme as (typeof THEME_ORDER)[number])
    : "system";
  const next = THEME_ORDER[(THEME_ORDER.indexOf(current) + 1) % THEME_ORDER.length];
  const label =
    current === "light"
      ? "Light theme (switch to dark)"
      : current === "dark"
        ? "Dark theme (switch to system)"
        : "System theme (switch to light)";

  return (
    <Button
      variant="ghost"
      size="icon"
      onClick={() => setTheme(next)}
      title={label}
      aria-label={label}
      className="size-11 text-muted-foreground transition-colors hover:text-foreground press-effect sm:size-8"
    >
      {current === "light" && <Sun className="size-4" aria-hidden />}
      {current === "dark" && <Moon className="size-4" aria-hidden />}
      {current === "system" && <Monitor className="size-4" aria-hidden />}
    </Button>
  );
}

/* ----------------------------------- Tabs ---------------------------------- */

function Tabs({ value, onChange }: { value: Tab; onChange: (t: Tab) => void }) {
  return (
    <nav className="flex gap-1 border-b border-border" role="tablist" aria-label="Mode">
      {TABS.map((t) => {
        const active = t.id === value;
        const n = TABS.indexOf(t) + 1;
        return (
          <button
            key={t.id}
            id={`tab-${t.id}`}
            type="button"
            role="tab"
            aria-selected={active}
            aria-controls={`panel-${t.id}`}
            onClick={() => onChange(t.id)}
            title={`Alt+${n}`}
            className={`relative inline-flex items-center justify-center gap-1.5 px-5 py-2.5 -mb-px border-b-2 text-sm font-medium transition-colors duration-150 ${
              active
                ? "border-transparent text-[#0055dc] dark:text-[#5e94ff]"
                : "border-transparent text-muted-foreground hover:text-foreground hover:border-border"
            }`}
          >
            {t.label}
            {/* Alt+N hint chip — decorative (aria-hidden; the shortcut is
                announced by the title tooltip and documented in the shortcuts
                dialog). Hidden below sm so mobile touch targets stay clean;
                at 16px tall it never grows the button's 20px label line box. */}
            <kbd
              aria-hidden="true"
              className={`hidden items-center rounded border px-1 py-0.5 font-mono text-[10px] leading-none transition-colors duration-150 sm:inline-flex ${
                active
                  ? "border-current/30 bg-muted/50 text-[#0055dc] dark:text-[#5e94ff]"
                  : "border-border bg-muted/50 text-muted-foreground"
              }`}
            >
              {n}
            </kbd>
            {/* Animated accent underline — replaces the static active border
                (kept transparent below so the 2px layout slot is stable) and
                scales/fades in on activation. Sits inside the button's 2px
                border slot, flush with the nav divider; the focus-visible
                outline lives outside the button bounds, so no overlap. */}
            <span
              aria-hidden="true"
              className={`pointer-events-none absolute inset-x-3 -bottom-0.5 h-0.5 rounded-full bg-[#0055dc] transition-all duration-200 dark:bg-[#5e94ff] motion-reduce:scale-x-100 motion-reduce:transition-none ${
                active ? "scale-x-100 opacity-100" : "scale-x-50 opacity-0"
              }`}
            />
          </button>
        );
      })}
    </nav>
  );
}

/* ---------------------------------- Footer --------------------------------- */

function Footer({ onSelfTest }: { onSelfTest: () => Promise<void> }) {
  const [testing, setTesting] = useState(false);

  const run = useCallback(async () => {
    setTesting(true);
    try {
      await onSelfTest();
    } finally {
      setTesting(false);
    }
  }, [onSelfTest]);

  return (
    // Bottom padding respects the iOS home-indicator safe area (env() is 0 on
    // desktop, so the resting rhythm is identical to the previous py-4).
    <footer className="mt-auto border-t border-border bg-muted/30 pt-4 pb-[max(1rem,env(safe-area-inset-bottom))]">
      <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-col items-center gap-2">
        <p className="max-w-2xl text-[11px] text-muted-foreground text-center">
          All crypto runs in your browser. Keys and plaintext never touch our servers — only Keybase
          username lookups are proxied.
        </p>
        <div className="flex items-center gap-2">
          <Button
            variant="ghost"
            size="sm"
            onClick={run}
            disabled={testing}
            className="h-7 gap-1.5 px-2 text-[11px] text-muted-foreground transition-colors hover:text-[#0055dc] dark:hover:text-[#5e94ff] press-effect"
            title="Runs an in-memory key generation + encrypt + decrypt + sign + verify round-trip"
          >
            {testing ? (
              <Loader2 className="size-3 animate-spin" aria-hidden />
            ) : (
              <ShieldCheck className="size-3" aria-hidden />
            )}
            {testing ? "Testing…" : "Crypto self-test"}
          </Button>
          <a
            href="https://github.com/theveryoilydill/Encryptor"
            target="_blank"
            rel="noreferrer noopener"
            title="View source on GitHub"
            aria-label="View source on GitHub"
            className="inline-flex h-7 w-7 items-center justify-center rounded-md text-muted-foreground transition-colors hover:bg-accent/10 hover:text-foreground"
          >
            <Github className="size-3.5" aria-hidden />
          </a>
        </div>
      </div>
    </footer>
  );
}
