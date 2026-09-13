"use client";

import { useCallback, useEffect, useState, type ComponentProps } from "react";
import { useTheme } from "next-themes";
import { Loader2, Monitor, Moon, ShieldCheck, Sun } from "lucide-react";

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

	// Alt+1..4 switches tabs (ignored while typing with Alt in most platforms;
	// harmless if swallowed by the browser).
	useEffect(() => {
		const onKey = (e: KeyboardEvent) => {
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

				{/* key={tab} remounts only this stateless wrapper so the enter
            animation replays on every switch. The tab components are already
            conditionally rendered below (their internal state resets per
            switch today), so semantics are byte-identical to before. */}
				<div
					key={tab}
					className="panel-enter mt-6"
					role="tabpanel"
					id={`panel-${tab}`}
					aria-labelledby={`tab-${tab}`}
				>
					{tab === "encrypt" && (
						<EncryptTab
							privateKey={privateKey}
							recipients={recipients}
							setRecipients={setRecipients}
							includeSelf={includeSelf}
							onIncludeSelfChange={handleSetIncludeSelf}
							requestDecryptedKey={requestDecryptedKey}
						/>
					)}
					{tab === "decrypt" && (
						<DecryptTab privateKey={privateKey} requestDecryptedKey={requestDecryptedKey} />
					)}
					{tab === "sign" && (
						<SignTab privateKey={privateKey} requestDecryptedKey={requestDecryptedKey} />
					)}
					{tab === "verify" && <VerifyTab privateKey={privateKey} />}
				</div>
			</main>

			<Footer onSelfTest={handleSelfTest} />

			<ConfigureModal
				open={configOpen}
				onOpenChange={setConfigOpen}
				privateKey={privateKey}
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
					<span className="text-base font-semibold tracking-tight">Encryptor</span>
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

// Lucide 1.x dropped all brand icons, so the GitHub mark lives here now.
// # Mr. AI Acting on s183173's Behalf
function GitHubIcon(props: ComponentProps<"svg">) {
	return (
		<svg viewBox="0 0 24 24" fill="currentColor" aria-hidden {...props}>
			<path d="M12 0C5.37 0 0 5.37 0 12c0 5.3 3.438 9.8 8.205 11.385.6.113.82-.258.82-.577 0-.285-.01-1.04-.015-2.04-3.338.724-4.042-1.61-4.042-1.61-.546-1.385-1.335-1.755-1.335-1.755-1.087-.744.084-.729.084-.729 1.205.084 1.838 1.236 1.838 1.236 1.07 1.835 2.809 1.305 3.495.998.108-.776.417-1.305.76-1.605-2.665-.3-5.466-1.332-5.466-5.93 0-1.31.465-2.38 1.235-3.22-.135-.303-.54-1.523.105-3.176 0 0 1.005-.322 3.3 1.23.96-.267 1.98-.399 3-.405 1.02.006 2.04.138 3 .405 2.28-1.552 3.285-1.23 3.285-1.23.645 1.653.24 2.873.12 3.176.765.84 1.23 1.91 1.23 3.22 0 4.61-2.805 5.625-5.475 5.92.42.36.81 1.096.81 2.22 0 1.606-.015 2.896-.015 3.286 0 .315.21.69.825.57C20.565 21.795 24 17.295 24 12c0-6.63-5.37-12-12-12z" />
		</svg>
	);
}

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
						<GitHubIcon className="size-3.5" aria-hidden />
					</a>
				</div>
			</div>
		</footer>
	);
}
