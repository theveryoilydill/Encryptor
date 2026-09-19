"use client";

import { useCallback, useEffect, useState, type ComponentProps } from "react";
import { useTheme } from "next-themes";
import {
	Loader2,
	Monitor,
	Moon,
	Settings,
	ShieldCheck,
	Sun,
	Timer,
	TriangleAlert,
	Unlock,
	X,
} from "lucide-react";

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
import { LoginView } from "@/components/pgp/login/LoginView";
import { PassphrasePrompt } from "@/components/pgp/PassphrasePrompt";
import { SettingsDialog } from "@/components/pgp/SettingsDialog";
import { ShortcutsDialog } from "@/components/pgp/ShortcutsDialog";
import { EncryptTab } from "@/components/pgp/tabs/EncryptTab";
import { DecryptTab } from "@/components/pgp/tabs/DecryptTab";
import { SignTab } from "@/components/pgp/tabs/SignTab";
import { VerifyTab } from "@/components/pgp/tabs/VerifyTab";
import { STORAGE_KEYS } from "@/lib/constants";
import { readKey, unlockPrivateKey } from "@/lib/pgp/pgp";
import { getKeyExpiryStatus } from "@/lib/pgp/key-details";
import { runCryptoSelfTest, type SelfTestResult } from "@/lib/pgp/self-test";
import {
	forgetPassphrase,
	getCachedPassphrase,
	getCachedPassphraseIfFresh,
} from "@/lib/pgp/session-passphrase";
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

/** Persistent own-key expiry awareness (additive): the Configure dialog has
 *  always shown an Expired/Expiring badge, but users only see it when they
 *  open settings — signatures created with a stale key give no hint in the
 *  main app. This banner sits above the tabs. Dismissal is keyed to
 *  fingerprint+status (handled by the parent), so changing or renewing the
 *  key re-arms the reminder. */
function OwnKeyExpiryBanner({
	label,
	status,
	detail,
	onOpenSettings,
	onDismiss,
}: {
	/** Configured key display label (quoted in the headline). */
	label: string;
	/** "expired" (red) or "expiring" (amber) — callers gate to these two. */
	status: "expired" | "expiring";
	/** Human timing clause, e.g. "expired on 12 March 2026" or
	 *  "expires in 6 days (12 March 2026)". */
	detail: string;
	onOpenSettings: () => void;
	onDismiss: () => void;
}) {
	const expired = status === "expired";
	return (
		<div
			role="status"
			className={`animate-fade-up flex flex-col gap-2.5 rounded-xl border px-4 py-3 shadow-sm sm:flex-row sm:items-center sm:gap-3 ${
				expired
					? "border-red-300/70 bg-red-50 dark:border-red-900/50 dark:bg-red-950/30"
					: "border-amber-300/70 bg-amber-50 dark:border-amber-900/50 dark:bg-amber-950/30"
			}`}
		>
			<span
				aria-hidden="true"
				className={`grid size-8 shrink-0 place-items-center rounded-full ${
					expired
						? "bg-red-100 text-red-700 dark:bg-red-900/40 dark:text-red-300"
						: "bg-amber-100 text-amber-700 dark:bg-amber-900/40 dark:text-amber-300"
				}`}
			>
				{expired ? <TriangleAlert className="size-4" /> : <Timer className="size-4" />}
			</span>
			<div className="min-w-0 flex-1">
				<p
					className={`text-xs font-medium ${
						expired ? "text-red-800 dark:text-red-300" : "text-amber-800 dark:text-amber-300"
					}`}
				>
					Your key “{label}” {detail}.
				</p>
				<p className="mt-0.5 text-[11px] text-muted-foreground">
					Signatures made with it may be rejected by others — consider generating a new key.
				</p>
			</div>
			<div className="flex shrink-0 items-center gap-1.5">
				<Button
					type="button"
					variant="outline"
					size="sm"
					onClick={onOpenSettings}
					className="h-11 gap-1.5 bg-background/60 px-3 text-xs transition-colors sm:h-8 dark:bg-background/40"
				>
					Open key settings
				</Button>
				<Button
					type="button"
					variant="ghost"
					size="icon"
					onClick={onDismiss}
					aria-label="Dismiss key expiry reminder"
					title="Dismiss this reminder"
					className="size-11 text-muted-foreground transition-colors hover:text-foreground sm:size-8"
				>
					<X aria-hidden="true" className="size-4" />
				</Button>
			</div>
		</div>
	);
}

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
	// Dedicated settings dialog (round 11 feedback): app preferences no longer
	// share a dialog with key/auth setup. Ctrl+, opens THIS dialog; the key
	// dialog stays one click away on the key button.
	const [settingsOpen, setSettingsOpen] = useState(false);
	const [includeSelf, setIncludeSelf] = useState<boolean>(loadIncludeSelfDefault);
	// Own-key expiry banner dismissal (additive): keyed to
	// "<fingerprint>:<status>" so a different key — or the same key crossing
	// from "expiring" into "expired" — re-arms the reminder. In-memory only:
	// a reload shows the reminder again, which is the safe default for a
	// crypto key whose freshness matters.
	const [expiryDismissed, setExpiryDismissed] = useState<string | null>(null);
	const keyExpiry = privateKey?.info ? getKeyExpiryStatus(privateKey.info.expirationTime) : null;
	const expiryKey = `${privateKey?.info?.fingerprint}:${keyExpiry?.status ?? ""}`;
	const showExpiryBanner =
		(keyExpiry?.status === "expired" || keyExpiry?.status === "expiring") &&
		expiryDismissed !== expiryKey;
	// Human timing clause for the banner headline. Expiry timestamps come
	// back from openpgp.js as Date and from localStorage as an ISO string —
	// new Date() accepts both; getKeyExpiryStatus already vetted parseability.
	const expiryDate =
		keyExpiry && keyExpiry.status !== "none" && privateKey?.info?.expirationTime
			? new Date(privateKey.info.expirationTime as Date).toLocaleDateString(undefined, {
					year: "numeric",
					month: "long",
					day: "numeric",
				})
			: "";
	const expiryDaysLeft =
		keyExpiry?.status === "expiring"
			? Math.max(
					1,
					Math.ceil(
						(new Date(privateKey?.info?.expirationTime as Date).getTime() - Date.now()) / 86400000,
					),
				)
			: 0;
	const expiryDetail =
		keyExpiry?.status === "expired"
			? `expired on ${expiryDate}`
			: keyExpiry?.status === "expiring"
				? `expires in ${expiryDaysLeft} day${expiryDaysLeft === 1 ? "" : "s"} (${expiryDate})`
				: "";
	// App preferences (compression + editor style). Owned here so the
	// ConfigureModal and the tabs stay in sync without a page reload.
	const [settings, setSettings] = useState<AppSettings>(loadSettings);
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
		setPrivateKey((prev) => {
			// The session passphrase cache is scoped to one key: dropping the key or
			// switching to a different fingerprint must not keep the old secret.
			const fingerprintChanged = prev && next && prev.info?.fingerprint !== next.info?.fingerprint;
			if (!next || fingerprintChanged) forgetPassphrase();
			return next;
		});
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
	// This shows a passphrase prompt — unless the user opted into the session
	// passphrase cache and the cached passphrase unlocks the key, in which case
	// the key is unlocked silently. The decrypted key exists only in the
	// promise resolver's scope and is cleared after the operation completes.
	const [keyRequest, setKeyRequest] = useState<KeyRequestState | null>(null);
	// Header indicator state for the opt-in session passphrase cache (the cache
	// itself lives in lib/pgp/session-passphrase — memory only).
	const [passphraseCached, setPassphraseCached] = useState(false);
	// R9 auto-lock: epoch ms when the cached passphrase auto-locks (null = no
	// auto-lock armed — setting off, or pre-R9 behavior). Drives the header
	// countdown + the expiry interval; the freshness gate in session-passphrase
	// is the real enforcement on unlock attempts.
	const [passphraseCachedUntil, setPassphraseCachedUntil] = useState<number | null>(null);

	const requestDecryptedKey = useCallback((): Promise<{
		key: OpenPGP.PrivateKey;
		passphrase: string | null;
	}> => {
		// R9: consult the cache through the freshness gate — a stale entry is
		// forgotten (inside the gate) and the visible prompt appears instead.
		if (privateKey?.source !== "keybase" && privateKey?.encryptedArmored && getCachedPassphrase()) {
			const cached = getCachedPassphraseIfFresh(settings.autoLockMinutes);
			if (cached) {
				// Silent unlock attempt with the session-cached passphrase. On any
				// failure (wrong passphrase, unreadable key) drop the cache and fall
				// back to the visible prompt.
				return (async () => {
					try {
						const key = await readKey(privateKey!.encryptedArmored!);
						if (!key.isPrivate()) throw new Error("Stored key is not a private key.");
						return {
							key: await unlockPrivateKey(key as OpenPGP.PrivateKey, cached),
							passphrase: cached,
						};
					} catch {
						forgetPassphrase();
						setPassphraseCached(false);
						setPassphraseCachedUntil(null);
						return new Promise<{ key: OpenPGP.PrivateKey; passphrase: string | null }>(
							(resolve, reject) =>
								setKeyRequest({
									resolve: (key, passphrase) => resolve({ key, passphrase: passphrase ?? null }),
									reject,
								}),
						);
					}
				})();
			}
			// Stale → auto-locked: drop the header indicator too. Falls through to
			// the visible prompt below.
			setPassphraseCached(false);
			setPassphraseCachedUntil(null);
		}
		return new Promise<{ key: OpenPGP.PrivateKey; passphrase: string | null }>((resolve, reject) =>
			setKeyRequest({
				resolve: (key, passphrase) => resolve({ key, passphrase: passphrase ?? null }),
				reject,
			}),
		);
	}, [privateKey, settings.autoLockMinutes]);

	const handleForgetCachedPassphrase = useCallback(() => {
		forgetPassphrase();
		setPassphraseCached(false);
		setPassphraseCachedUntil(null);
		toast({ title: "Session passphrase forgotten" });
	}, [toast]);

	// Adopt a key coming from the login gate (generated, imported, pasted,
	// or restored from registry escrow): configure it app-wide and jump to
	// Encrypt so the key is immediately usable.
	const handleUseRegistryKey = useCallback(
		(config: PrivateKeyConfig) => {
			handleSetPrivateKey(config);
			setTab("encrypt");
		},
		[handleSetPrivateKey],
	);

	// R9 auto-lock enforcement for the UI state: the freshness gate covers real
	// unlock attempts; this lightweight interval covers the header indicator +
	// announcement when the deadline passes while the app is open.
	useEffect(() => {
		if (!passphraseCachedUntil) return;
		const tick = setInterval(() => {
			if (Date.now() >= passphraseCachedUntil) {
				forgetPassphrase();
				setPassphraseCached(false);
				setPassphraseCachedUntil(null);
				toast({ title: "Session passphrase auto-locked" });
			}
		}, 5000);
		return () => clearInterval(tick);
	}, [passphraseCachedUntil, toast]);

	const handleSetSettings = useCallback(
		(next: AppSettings) => {
			setSettings(next);
			saveSettings(next);
			// R9: keep an armed auto-lock deadline in sync when the preference
			// changes mid-session (re-arm from now; turning it off disarms).
			setPassphraseCachedUntil(
				passphraseCached && next.autoLockMinutes > 0
					? Date.now() + next.autoLockMinutes * 60_000
					: null,
			);
		},
		[passphraseCached],
	);

	// Alt+1..5 switches tabs; Ctrl/Cmd+, opens the app Settings dialog; the
	// key dialog stays on the header key button.
	useEffect(() => {
		const onKey = (e: KeyboardEvent) => {
			if ((e.ctrlKey || e.metaKey) && !e.altKey && !e.shiftKey && e.key === ",") {
				e.preventDefault();
				setSettingsOpen(true);
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

	// Crypto-library prewarm (round 11 feedback: "load crypto libraries on
	// startup"): compile the heavy lazily-imported modules while the user is
	// still reading the page instead of mid-operation — kbpgp (Keybase login
	// path), the BlockNote editor chunk, the markdown-editor chunk, and the
	// ML-KEM post-quantum module. Idle-callback so it never competes with
	// first paint; every import is fire-and-forget.
	useEffect(() => {
		const prewarm = () => {
			void import("@/lib/pgp/keybase-auth").catch(() => {});
			void import("@/components/pgp/BlockNoteEditor").catch(() => {});
			void import("@uiw/react-md-editor").catch(() => {});
			void import("@/lib/pgp/pq").catch(() => {});
		};
		const ric =
			typeof window.requestIdleCallback === "function"
				? window.requestIdleCallback
				: (cb: () => void) => window.setTimeout(cb, 200);
		const id = ric.call(window, prewarm);
		return () => {
			if (typeof window.cancelIdleCallback === "function") window.cancelIdleCallback(id as number);
			else window.clearTimeout(id as number);
		};
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

			<Header
				onConfigure={() => setConfigOpen(true)}
				onOpenSettings={() => setSettingsOpen(true)}
				privateKey={privateKey}
				passphraseCached={passphraseCached}
				passphraseCachedUntil={passphraseCachedUntil}
				onForgetCachedPassphrase={handleForgetCachedPassphrase}
			/>

			{privateKey ? (
				<main className="flex-1 max-w-4xl mx-auto w-full px-4 sm:px-6 lg:px-8 py-6 lg:py-8">
					{showExpiryBanner && privateKey && keyExpiry && (
						<div className="mb-4">
							<OwnKeyExpiryBanner
								label={privateKey.label}
								status={keyExpiry.status as "expired" | "expiring"}
								detail={expiryDetail}
								onOpenSettings={() => setConfigOpen(true)}
								onDismiss={() => setExpiryDismissed(expiryKey)}
							/>
						</div>
					)}
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
			) : (
				/* Sign-in gate: the minimal "Login/Get your keys" page.
                                   Nothing else is usable until a key is configured. */
				<LoginView onUseKey={handleUseRegistryKey} />
			)}

			<Footer onSelfTest={handleSelfTest} />

			<ConfigureModal
				open={configOpen}
				onOpenChange={setConfigOpen}
				privateKey={privateKey}
				requestDecryptedKey={requestDecryptedKey}
				onSave={(next) => {
					handleSetPrivateKey(next);
					setConfigOpen(false);
				}}
				onClear={() => {
					handleSetPrivateKey(null);
					setConfigOpen(false);
				}}
			/>

			<SettingsDialog
				open={settingsOpen}
				onOpenChange={setSettingsOpen}
				settings={settings}
				onSettingsChange={handleSetSettings}
				privateKey={privateKey}
			/>

			{keyRequest && privateKey && (
				<PassphrasePrompt
					config={privateKey}
					request={{
						resolve: (key, passphrase) => {
							keyRequest.resolve(key, passphrase ?? null);
							setKeyRequest(null);
						},
						reject: (err) => {
							keyRequest.reject(err);
							setKeyRequest(null);
						},
					}}
					onKeyUpdated={handleSetPrivateKey}
					onPassphraseCached={() => {
						setPassphraseCached(true);
						setPassphraseCachedUntil(
							settings.autoLockMinutes > 0 ? Date.now() + settings.autoLockMinutes * 60_000 : null,
						);
					}}
				/>
			)}

			<Toaster />
		</div>
	);
}

/* ---------------------------------- Header --------------------------------- */

function Header({
	onConfigure,
	onOpenSettings,
	privateKey,
	passphraseCached,
	passphraseCachedUntil,
	onForgetCachedPassphrase,
}: {
	onConfigure: () => void;
	onOpenSettings: () => void;
	privateKey: PrivateKeyConfig | null;
	passphraseCached: boolean;
	/** Epoch ms deadline for the auto-lock (null/undefined = none armed).
	 *  Shown as a live-ish countdown in the button tooltip (re-renders ride on
	 *  the parent's 5s auto-lock tick). */
	passphraseCachedUntil?: number | null;
	onForgetCachedPassphrase: () => void;
}) {
	const autoLockMinutesLeft = passphraseCachedUntil
		? Math.max(1, Math.ceil((passphraseCachedUntil - Date.now()) / 60000))
		: null;
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
					{passphraseCached && privateKey && (
						<Button
							type="button"
							variant="ghost"
							size="icon"
							onClick={onForgetCachedPassphrase}
							aria-label={
								autoLockMinutesLeft
									? `Forget the remembered session passphrase (auto-locks in ${autoLockMinutesLeft} min)`
									: "Forget the remembered session passphrase"
							}
							title={
								autoLockMinutesLeft
									? `Passphrase remembered for this session (memory only) — auto-locks in ${autoLockMinutesLeft} min — click to forget it now`
									: "Passphrase remembered for this session (memory only) — click to forget it now"
							}
							className="relative size-8 text-muted-foreground transition-colors hover:text-[#0055dc] dark:hover:text-[#5e94ff]"
						>
							<Unlock className="size-4" aria-hidden />
							{/* R9: tiny countdown badge next to the unlock glyph when an
                  auto-lock is armed — glanceable without opening the tooltip. */}
							{autoLockMinutesLeft !== null && (
								<span
									aria-hidden="true"
									className="absolute -right-1.5 -bottom-1 rounded-full border border-border bg-background px-1 text-[8px] font-medium leading-[1.3] text-muted-foreground"
								>
									{autoLockMinutesLeft}m
								</span>
							)}
						</Button>
					)}
					<ThemeToggle />
					<ShortcutsDialog />
					{/* Dedicated settings entry (round 11 feedback): the gear owns app
              preferences; the key button next to it owns key/auth. Both are
              hidden on the sign-in gate — signing in IS the configuration
              surface now (LoginView), so there is nothing to configure yet. */}
					{privateKey && (
						<Button
							variant="ghost"
							size="icon"
							onClick={onOpenSettings}
							title="Settings (Ctrl+,)"
							aria-label="Settings"
							className="size-11 text-muted-foreground transition-colors hover:text-[#0055dc] press-effect sm:size-8 dark:hover:text-[#5e94ff]"
						>
							<Settings aria-hidden className="size-4" />
						</Button>
					)}
					{privateKey && (
						<Button
							variant="outline"
							size="sm"
							onClick={onConfigure}
							className="h-11 gap-2 transition-colors duration-150 hover:border-[#0055dc] hover:text-[#0055dc] dark:hover:border-[#5e94ff] dark:hover:text-[#5e94ff] press-effect sm:h-8"
						>
							<KeyIcon />
							<span>
								{privateKey.source === "keybase" ? `@${privateKey.username}` : privateKey.label}
							</span>
						</Button>
					)}
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
