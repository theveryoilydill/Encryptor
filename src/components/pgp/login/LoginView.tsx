"use client";

/**
 * LoginView — "Login / Get your keys", the app's sign-in gate.
 *
 * Implements the owner's PR #25 mockup exactly: a minimal page with five
 * big source buttons — Encryptor Registry, Keybase registry, OpenPGP
 * registry (needs private key), Ubuntu Registry (needs private key), and
 * Local keys. Every flow converges on a PrivateKeyConfig configured
 * app-wide; the passphrase and decrypted key material never leave the
 * browser (only key metadata + the ENCRYPTED armored key are kept).
 *
 * This replaces both the old Keys tab (removed) and the setup half of the
 * old Configure dialog, per the review round: "Keep this minimal. Also
 * don't put the admin thing publicly."
 *
 * # Mr. AI Acting on s183173's Behalf
 */
import { useCallback, useEffect, useRef, useState } from "react";
import {
	Check,
	ChevronDown,
	Dice5,
	Eye,
	EyeOff,
	Globe,
	HardDrive,
	KeyRound,
	Loader2,
	Lock,
	Search,
	TriangleAlert,
	Upload,
} from "lucide-react";

import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import {
	Dialog,
	DialogContent,
	DialogDescription,
	DialogFooter,
	DialogHeader,
	DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { PassphraseStrengthMeter } from "@/components/pgp/PassphraseStrengthMeter";
import {
	PublishOutcome,
	PublishOutcomeCard,
	ReplacePanel,
	TurnstileGate,
	WritesLockedNotice,
	publicFromPrivate,
	useRegistryPublish,
	useWritesLocked,
} from "@/components/pgp/login/publish-flow";
import { PROXIES, type PrivateKeyConfig } from "@/components/pgp/contracts";
import { generatePassphrase } from "@/lib/pgp/passphrase";
import { generateSealKeyPair, wrapSealSecret, type QuantumSealConfig } from "@/lib/pgp/pq";
import {
	formatFingerprint,
	generateKeyPair,
	validateArmoredKey,
	type AnyKeyInfo,
} from "@/lib/pgp/pgp";
import {
	formatRegistryError,
	registryFetchEscrow,
	registryLookup,
	registryRevokeByToken,
	type RegistryLookupKey,
} from "@/lib/registry/client";
import { toast } from "@/hooks/use-toast";

type SourceId = "registry" | "keybase" | "openpgp" | "ubuntu" | "local";

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

/**
 * localStorage key holding the last identity (fingerprint or email) this
 * browser successfully restored with. Both are public-by-design registry
 * data (a fingerprint is displayed on every lookup; the email is what the
 * registry is searched by) — used ONLY to prefill the restore form so the
 * next sign-in skips a retype. Never key material, never a passphrase.
 */
const LAST_RESTORE_QUERY_KEY = "encryptor.restore.lastQuery";

/**
 * WAI-ARIA radio arrow-key navigation, shared by the segmented control and
 * the restore key-picker: Arrow/Home/End move both selection and focus;
 * Enter/Space stay with the native button. Returns the id to select, or
 * null for non-navigation keys.
 */
function radioNavId(e: React.KeyboardEvent, ids: string[], current: string | null): string | null {
	const len = ids.length;
	if (len === 0) return null;
	const idx = current != null ? ids.indexOf(current) : -1;
	let next = -1;
	if (e.key === "ArrowRight" || e.key === "ArrowDown") next = idx < 0 ? 0 : (idx + 1) % len;
	else if (e.key === "ArrowLeft" || e.key === "ArrowUp")
		next = idx < 0 ? len - 1 : (idx - 1 + len) % len;
	else if (e.key === "Home") next = 0;
	else if (e.key === "End") next = len - 1;
	return next < 0 ? null : ids[next];
}

/** Inline destructive-tinted error panel. */
function FormError({ message }: { message: string | null }) {
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

/** The five sign-in sources, styled per the owner's hand-drawn mockup. */
const SOURCES: {
	id: SourceId;
	label: string;
	note?: string;
	blurb: string;
	icon: typeof KeyRound;
	className: string;
}[] = [
	{
		id: "registry",
		label: "Encryptor Registry",
		blurb: "Restore an escrowed key, or publish one",
		icon: KeyRound,
		className:
			// blue-800 in light mode too: keeps the white opacity-75 blurb >= 4.5:1 AA.
			// Owner PR #25: "swap the keybase and encryptor button colors" — the
			// Encryptor card now wears the dark blue, Keybase the light blue.
			"border-blue-900/40 bg-blue-800 text-white hover:bg-blue-800/90 dark:border-blue-700/60 dark:bg-blue-800 dark:hover:bg-blue-800/90",
	},
	{
		id: "keybase",
		label: "Keybase registry",
		blurb: "Sign in with your Keybase account",
		icon: Globe,
		className:
			"border-sky-300/60 bg-sky-200 text-sky-950 hover:bg-sky-200/80 dark:border-sky-700/60 dark:bg-sky-900/60 dark:text-sky-100 dark:hover:bg-sky-900/80",
	},
	{
		id: "openpgp",
		label: "OpenPGP registry",
		note: "needs private key",
		blurb: "Paste the private key for your keys.openpgp.org entry",
		icon: Lock,
		className:
			"border-emerald-300/60 bg-emerald-200 text-emerald-950 hover:bg-emerald-200/80 dark:border-emerald-700/60 dark:bg-emerald-900/60 dark:text-emerald-100 dark:hover:bg-emerald-900/80",
	},
	{
		id: "ubuntu",
		label: "Ubuntu Registry",
		note: "needs private key",
		blurb: "Paste the private key for your keyserver.ubuntu.com entry",
		icon: Upload,
		className:
			"border-rose-300/60 bg-rose-200 text-rose-950 hover:bg-rose-200/80 dark:border-rose-700/60 dark:bg-rose-900/60 dark:text-rose-100 dark:hover:bg-rose-900/80",
	},
	{
		id: "local",
		label: "Local keys",
		blurb: "Generate a new pair, or paste one you manage locally",
		icon: HardDrive,
		className:
			"border-slate-300/60 bg-slate-200 text-slate-900 hover:bg-slate-200/80 dark:border-slate-700/60 dark:bg-slate-800/80 dark:text-slate-100 dark:hover:bg-slate-800",
	},
];

/** Two-choice segmented control (lighter than radix Tabs inside dialogs). */
function Segmented({
	value,
	onChange,
	options,
}: {
	value: string;
	onChange: (v: string) => void;
	options: { id: string; label: string }[];
}) {
	// radiogroup/radio semantics: this control switches MODES in place, it
	// does not swap tabpanels — role="tab" without an aria-controlled panel
	// fails axe "nested interactive/missing tabpanel" checks.
	// WAI-ARIA radio pattern: a single tab stop (the checked radio) with
	// arrow-key movement — screen readers announce "1 of N" and expect
	// arrows to move, exactly like a native radio group.
	const radioRefs = useRef<(HTMLButtonElement | null)[]>([]);
	const onRadioKeyDown = (e: React.KeyboardEvent<HTMLDivElement>) => {
		const ids = options.map((o) => o.id);
		const nextId = radioNavId(e, ids, value);
		if (!nextId) return;
		e.preventDefault();
		onChange(nextId);
		// focus follows selection (after React commits the new tabIndex map)
		const next = ids.indexOf(nextId);
		requestAnimationFrame(() => radioRefs.current[next]?.focus());
	};
	return (
		<div
			role="radiogroup"
			aria-label="Choose an action"
			onKeyDown={onRadioKeyDown}
			className="grid gap-1 rounded-lg bg-muted p-1"
			style={{ gridTemplateColumns: `repeat(${options.length}, minmax(0, 1fr))` }}
		>
			{options.map((o, i) => {
				const active = o.id === value;
				return (
					<button
						key={o.id}
						ref={(el) => {
							radioRefs.current[i] = el;
						}}
						type="button"
						role="radio"
						aria-checked={active}
						tabIndex={active ? 0 : -1}
						data-testid={`segment-${o.id}`}
						onClick={() => onChange(o.id)}
						className={`rounded-md px-3 py-1.5 text-sm font-medium transition-colors ${
							active
								? "bg-background text-foreground shadow-sm"
								: "text-muted-foreground hover:text-foreground"
						}`}
					>
						{o.label}
					</button>
				);
			})}
		</div>
	);
}

/**
 * Small "load a key file" affordance for the paste forms: reads a local
 * .asc/.txt export (gpg --export-secret-keys -a & co) into the textarea.
 * File contents NEVER leave the browser — same contract as pasting.
 */
function KeyFilePicker({ id, onLoaded }: { id: string; onLoaded: (text: string) => void }) {
	const inputRef = useRef<HTMLInputElement | null>(null);
	const [fileName, setFileName] = useState<string | null>(null);
	return (
		<>
			<input
				ref={inputRef}
				id={id}
				type="file"
				accept=".asc,.txt,application/pgp-keys,text/plain"
				className="sr-only"
				tabIndex={-1}
				aria-hidden="true"
				onChange={(e) => {
					const file = e.target.files?.[0];
					if (!file) return;
					setFileName(file.name);
					void file.text().then((t) => onLoaded(t));
					e.target.value = "";
				}}
			/>
			<Button
				type="button"
				variant="outline"
				size="sm"
				className="h-7 gap-1.5 px-2 text-[11px]"
				onClick={() => inputRef.current?.click()}
				title="Load an armored key from a .asc file"
			>
				<Upload aria-hidden className="size-3" />
				{fileName ? `Loaded ${fileName}` : "Load .asc file"}
			</Button>
		</>
	);
}

/* ------------------------------ main component ----------------------------- */

export function LoginView({ onUseKey }: { onUseKey: (config: PrivateKeyConfig) => void }) {
	const [open, setOpen] = useState<SourceId | null>(null);
	// Last non-null open id. The shared openpgp/ubuntu dialog derives its
	// `source` from `open` — which resets to "openpgp" the moment `open`
	// clears, BEFORE FocusScope unmounts and reads the latest
	// onCloseAutoFocus prop. Remembering the opener keeps that prop stable
	// through the close transition so focus returns to the right button.
	const lastOpenRef = useRef<SourceId | null>(null);
	if (open) lastOpenRef.current = open;

	const closeAndReset = useCallback(() => setOpen(null), []);

	return (
		<main className="flex flex-1 items-center justify-center px-4 py-10 sm:py-14">
			<div className="w-full max-w-xl">
				<div className="mb-8 text-center">
					<h2 className="text-2xl font-semibold tracking-tight">Login/Get your keys</h2>
					<p className="mx-auto mt-2 max-w-md text-sm leading-relaxed text-muted-foreground">
						Pick how you want to sign in. Everything runs in this browser — private keys and
						passphrases never touch the server.
					</p>
				</div>
				<nav aria-label="Sign-in sources" className="grid gap-3">
					{SOURCES.map((s) => {
						const Icon = s.icon;
						return (
							<button
								key={s.id}
								type="button"
								data-testid={`login-source-${s.id}`}
								onClick={() => setOpen(s.id)}
								className={`flex min-h-16 w-full items-center gap-3 rounded-2xl border px-5 py-4 text-left shadow-xs transition-all duration-150 press-effect focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[#0055dc] ${s.className}`}
							>
								<Icon aria-hidden="true" className="size-5 shrink-0 opacity-80" />
								<span className="min-w-0 flex-1">
									<span className="block text-base font-semibold leading-tight">
										{s.label}
										{s.note && (
											<span className="ml-2 align-middle text-xs font-normal opacity-75">
												({s.note})
											</span>
										)}
									</span>
									<span className="mt-0.5 block text-xs font-normal opacity-75">{s.blurb}</span>
								</span>
							</button>
						);
					})}
				</nav>

				<p className="mt-8 text-center text-[11px] leading-relaxed text-muted-foreground">
					All crypto runs locally. Only key <em>metadata</em> and passphrase-encrypted key backups
					are ever synced, and only when you explicitly publish or escrow them.
				</p>
			</div>

			{/* Sign-in dialogs — one per source, mounted on demand. */}
			<RegistryDialog
				open={open === "registry"}
				onOpenChange={(o) => !o && closeAndReset()}
				onUseKey={onUseKey}
			/>
			<KeybaseDialog
				open={open === "keybase"}
				onOpenChange={(o) => !o && closeAndReset()}
				onUseKey={onUseKey}
			/>
			<PasteKeyDialog
				open={open === "openpgp" || open === "ubuntu"}
				source={lastOpenRef.current === "ubuntu" ? "ubuntu" : "openpgp"}
				onOpenChange={(o) => !o && closeAndReset()}
				onUseKey={onUseKey}
			/>
			<LocalDialog
				open={open === "local"}
				onOpenChange={(o) => !o && closeAndReset()}
				onUseKey={onUseKey}
			/>
		</main>
	);
}

/** Shared dialog chrome: consistent width, scroll, and test hooks. */
function LoginDialog({
	open,
	onOpenChange,
	title,
	description,
	children,
	widthClass = "sm:max-w-lg",
	sourceId,
}: {
	open: boolean;
	onOpenChange: (open: boolean) => void;
	title: string;
	description: string;
	children: React.ReactNode;
	widthClass?: string;
	sourceId: string;
}) {
	return (
		<Dialog open={open} onOpenChange={onOpenChange}>
			<DialogContent
				className={`${widthClass} max-h-[85dvh] overflow-y-auto`}
				onCloseAutoFocus={(e) => {
					// Radix's built-in focus restore targets a DialogTrigger — the
					// gate opens these dialogs from plain source buttons (one shared
					// `open` state), so return focus to the button that opened this
					// dialog ourselves. Without this, Escape lands focus on <body>.
					e.preventDefault();
					const opener = document.querySelector<HTMLButtonElement>(
						`[data-testid=login-source-${sourceId}]`,
					);
					if (opener) opener.focus();
				}}
			>
				<DialogHeader>
					<DialogTitle>{title}</DialogTitle>
					<DialogDescription>{description}</DialogDescription>
				</DialogHeader>
				{children}
			</DialogContent>
		</Dialog>
	);
}

/* --------------------------- Encryptor Registry ---------------------------- */

/** Restore an escrowed key — or publish a new/rotated one. */
function RegistryDialog({
	open,
	onOpenChange,
	onUseKey,
}: {
	open: boolean;
	onOpenChange: (open: boolean) => void;
	onUseKey: (config: PrivateKeyConfig) => void;
}) {
	const [mode, setMode] = useState<"restore" | "publish" | "generate">("restore");
	// Self-service revocation lives behind a quiet disclosure (not a fourth
	// segment): it is the rare emergency-brake path, and the owner asked the
	// gate stay minimal. It completes the lifecycle the publish outcome card
	// promises — "this token is the only way to retract this key".
	const [revokeOpen, setRevokeOpen] = useState(false);
	const writesLocked = useWritesLocked();
	return (
		<LoginDialog
			sourceId="registry"
			open={open}
			onOpenChange={onOpenChange}
			title="Encryptor Registry"
			description="Sign in by restoring your passphrase-protected backup, publishing an existing key — or generating a brand-new one right here."
		>
			<div className="space-y-4">
				<Segmented
					value={mode}
					onChange={(v) => setMode(v as "restore" | "publish" | "generate")}
					options={[
						{ id: "restore", label: "Restore my key" },
						{ id: "publish", label: "Publish a key" },
						{ id: "generate", label: "Generate & publish" },
					]}
				/>
				{mode === "restore" ? (
					<RestoreForm onUseKey={onUseKey} onDone={() => onOpenChange(false)} />
				) : mode === "generate" ? (
					<GenerateForm onUseKey={onUseKey} onDone={() => onOpenChange(false)} initialPublish />
				) : (
					<PublishPasteForm onUseKey={onUseKey} onDone={() => onOpenChange(false)} />
				)}
				<div className="border-t border-border/60 pt-3">
					<button
						type="button"
						data-testid="revoke-disclosure"
						aria-expanded={revokeOpen}
						aria-controls="revoke-panel"
						onClick={() => setRevokeOpen((o) => !o)}
						className="flex items-center gap-1 text-xs text-muted-foreground underline-offset-2 transition-colors hover:text-foreground hover:underline"
					>
						Revoke a published key with your one-time token
						<ChevronDown
							aria-hidden
							className={`size-3.5 shrink-0 transition-transform duration-150 ${revokeOpen ? "rotate-180" : ""}`}
						/>
					</button>
					{revokeOpen && (
						<div
							id="revoke-panel"
							className="mt-3 rounded-lg border border-border/70 bg-muted/30 p-3"
						>
							<RevokeTokenForm
								writesLocked={writesLocked === true}
								onDone={() => onOpenChange(false)}
							/>
						</div>
					)}
				</div>
			</div>
		</LoginDialog>
	);
}

/** Restore flow: fingerprint/email → escrow lookup → local decrypt. */
function RestoreForm({
	onUseKey,
	onDone,
}: {
	onUseKey: (config: PrivateKeyConfig) => void;
	onDone: () => void;
}) {
	const [query, setQuery] = useState("");
	const [passphrase, setPassphrase] = useState("");
	const [matches, setMatches] = useState<RegistryLookupKey[] | null>(null);
	const [fingerprint, setFingerprint] = useState<string | null>(null);
	const [busy, setBusy] = useState(false);
	const [error, setError] = useState<string | null>(null);
	// Identity lines for the match cards, parsed LOCALLY from each match's
	// public armor (the lookup response includes it) — a picker full of
	// 40-hex fingerprints is unreadable; “Alice — alice@example.com” is
	// not. Fails soft: unparseable armor just hides the line (same rule as
	// the revoke preview's identity).
	const [idLines, setIdLines] = useState<Record<string, string | null>>({});
	// Passphrase field (focused when the decrypt step appears) + the match
	// cards (focus targets of the roving tabindex while arrow-browsing).
	const passRef = useRef<HTMLInputElement | null>(null);
	const matchRefs = useRef<(HTMLButtonElement | null)[]>([]);
	// Set ONLY at the call sites where the passphrase field should take focus
	// (card click / single-match auto-select) — never on arrow-key selection,
	// which must keep focus on the cards while browsing the list.
	const focusPassRef = useRef(false);

	// Prefill the last identity this browser restored with, AFTER hydration so
	// SSR markup stays deterministic (see LAST_RESTORE_QUERY_KEY).
	useEffect(() => {
		try {
			const saved = window.localStorage.getItem(LAST_RESTORE_QUERY_KEY);
			if (saved) setQuery(saved);
		} catch {
			/* storage unavailable (private mode) — skip the nicety */
		}
	}, []);

	// Move focus into the passphrase field when the decrypt step appears via
	// click or auto-select. The rAF waits one frame so the input is mounted.
	useEffect(() => {
		if (!focusPassRef.current || !fingerprint) return;
		focusPassRef.current = false;
		requestAnimationFrame(() => passRef.current?.focus());
	}, [fingerprint]);

	/** Arrow/Home/End browse the key cards (selection follows focus). */
	const onMatchesKeyDown = (e: React.KeyboardEvent<HTMLDivElement>) => {
		if (!matches) return;
		const ids = matches.map((m) => m.fingerprint);
		const nextId = radioNavId(e, ids, fingerprint);
		if (!nextId) return;
		e.preventDefault();
		setFingerprint(nextId);
		const i = ids.indexOf(nextId);
		requestAnimationFrame(() => matchRefs.current[i]?.focus());
	};

	const normalizeFpr = (raw: string) => raw.replace(/\s+/g, "").replace(/^0x/i, "").toUpperCase();
	const isFpr = (raw: string) => /^[0-9A-F]{40}$/.test(normalizeFpr(raw));

	const resolve = useCallback(async () => {
		setError(null);
		const raw = query.trim();
		if (!raw) return;
		setBusy(true);
		try {
			if (isFpr(raw)) {
				const fpr = normalizeFpr(raw);
				const escrow = await registryFetchEscrow(fpr);
				if (!escrow.encryptedPrivate) {
					setError(
						"No encrypted backup is escrowed for this fingerprint. Use “Publish a key” instead.",
					);
					return;
				}
				setFingerprint(fpr);
				setMatches(null);
			} else if (EMAIL_RE.test(raw)) {
				const found = await registryLookup({ email: raw.toLowerCase() });
				const live = found.filter((k) => !k.revoked);
				if (live.length === 0) {
					setError(
						found.length > 0
							? "That email only has revoked keys on the registry."
							: "No keys found for that email on the registry.",
					);
					return;
				}
				// Parse identity lines BEFORE the cards mount so the picker appears
				// fully formed — no label pop-in after paint.
				const pairs = await Promise.all(
					live.map(async (m) => {
						try {
							const v = await validateArmoredKey(m.armored);
							const u = v.info && "userIDs" in v.info ? v.info.userIDs[0] : undefined;
							return [
								m.fingerprint,
								u ? [u.name, u.email].filter(Boolean).join(" — ") || null : null,
							] as const;
						} catch {
							return [m.fingerprint, null] as const;
						}
					}),
				);
				setIdLines(Object.fromEntries(pairs));
				setMatches(live);
				// Single live key: preselect it so the passphrase step appears
				// immediately — one less click on the primary sign-in path.
				// Multiple keys still require an explicit pick below.
				if (live.length === 1) {
					focusPassRef.current = true;
					setFingerprint(live[0].fingerprint);
				} else {
					setFingerprint(null);
				}
			} else {
				setError("Enter a 40-character fingerprint or an email address.");
				return;
			}
		} catch (e) {
			setError(formatRegistryError(e, "Registry lookup failed"));
		} finally {
			setBusy(false);
		}
	}, [query]);

	const restoreBusyRef = useRef(false);
	const restore = useCallback(async () => {
		// busy guard: the passphrase field's Enter handler calls this directly,
		// bypassing the disabled submit button. This must be a REF, not the
		// `busy` state — two rapid Enters can land before React re-renders, so
		// a state read goes stale; a ref check is synchronous.
		if (restoreBusyRef.current || !fingerprint || !passphrase) return;
		restoreBusyRef.current = true;
		setBusy(true);
		setError(null);
		try {
			const escrow = await registryFetchEscrow(fingerprint);
			if (!escrow.encryptedPrivate) {
				setError("The escrow disappeared — publish or restore a key first.");
				return;
			}
			// Decrypt LOCALLY: the passphrase never leaves this browser. The
			// decrypted object is discarded — only the encrypted armor is kept.
			const openpgp = await import("openpgp");
			const key = await openpgp.readKey({ armoredKey: escrow.encryptedPrivate });
			await openpgp.decryptKey({ privateKey: key as never, passphrase });
			const info = await validateArmoredKey(escrow.encryptedPrivate);
			if (!info.ok || !info.info) throw new Error("Escrowed key failed local validation.");
			// This identity worked end-to-end on this device — remember it
			// (public data only; see LAST_RESTORE_QUERY_KEY) so the next
			// sign-in can prefill it.
			try {
				window.localStorage.setItem(LAST_RESTORE_QUERY_KEY, query.trim());
			} catch {
				/* storage unavailable */
			}
			const first = info.info.userIDs[0];
			onUseKey({
				source: "manual",
				label: first?.name || first?.email || formatFingerprint(info.info.fingerprint),
				encryptedArmored: escrow.encryptedPrivate,
				info: info.info,
			});
			toast({
				title: "Signed in",
				description: "Your escrowed key was decrypted locally and configured.",
			});
			onDone();
		} catch (e) {
			const msg = e instanceof Error ? e.message : String(e);
			setError(
				/checksum|passphrase|decrypt/i.test(msg) ? "Wrong passphrase for this escrowed key." : msg,
			);
		} finally {
			restoreBusyRef.current = false;
			setBusy(false);
		}
	}, [fingerprint, onDone, onUseKey, passphrase, query]);

	return (
		<div className="space-y-3" data-testid="restore-form">
			<div className="grid gap-1.5">
				<Label htmlFor="restore-query">Fingerprint or email</Label>
				<div className="flex gap-2">
					<Input
						id="restore-query"
						value={query}
						onChange={(e) => {
							setQuery(e.target.value);
							setMatches(null);
							setFingerprint(null);
							setError(null);
						}}
						placeholder="40-hex fingerprint or you@example.com"
						autoComplete="off"
						spellCheck={false}
						onKeyDown={(e) => {
							// Enter finds — the passphrase field's Enter already restores, so the
							// whole lookup flow stays keyboard-first.
							if (e.key === "Enter" && !busy && query.trim()) {
								e.preventDefault();
								void resolve();
							}
						}}
					/>
					<Button
						type="button"
						variant="outline"
						onClick={resolve}
						disabled={busy || !query.trim()}
					>
						{busy ? (
							<Loader2 aria-hidden className="size-4 animate-spin" />
						) : (
							<Search aria-hidden className="size-4" />
						)}
						<span className="sr-only sm:not-sr-only">Find</span>
					</Button>
				</div>
			</div>

			{matches && (
				<div className="grid gap-1.5">
					<p id="restore-matches-hint" role="status" className="text-xs text-muted-foreground">
						{matches.length === 1
							? "Found this key on the registry."
							: `${matches.length} live keys on the registry — pick one to decrypt.`}
					</p>
					<div
						role="radiogroup"
						aria-labelledby="restore-matches-hint"
						onKeyDown={onMatchesKeyDown}
						className="grid gap-1.5"
					>
						{matches.map((m, i) => {
							const selected = fingerprint === m.fingerprint;
							const createdStr = new Date(m.createdAt * 1000).toLocaleDateString();
							const updatedStr = new Date(m.updatedAt * 1000).toLocaleDateString();
							const idLine = idLines[m.fingerprint] ?? null;
							return (
								<button
									key={m.fingerprint}
									ref={(el) => {
										matchRefs.current[i] = el;
									}}
									type="button"
									role="radio"
									aria-checked={selected}
									tabIndex={fingerprint == null ? (i === 0 ? 0 : -1) : selected ? 0 : -1}
									data-testid="restore-match"
									onClick={() => {
										focusPassRef.current = true;
										setFingerprint(m.fingerprint);
									}}
									className={`flex w-full items-start gap-2 rounded-lg border px-3 py-2 text-left text-xs transition-all duration-150 press-effect focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[#0055dc] ${
										selected
											? "border-[#0055dc] bg-[#0055dc]/5 ring-1 ring-[#0055dc]/30"
											: "border-border hover:bg-muted/50"
									}`}
								>
									<Check
										aria-hidden
										className={`mt-0.5 size-3.5 shrink-0 ${
											selected ? "text-[#0055dc] dark:text-sky-300" : "invisible"
										}`}
									/>
									<span className="min-w-0 flex-1">
										{idLine && (
											<span className="block truncate text-[13px] font-medium leading-tight">
												{idLine}
											</span>
										)}
										<code
											className={
												idLine ? "font-mono text-[11px] text-muted-foreground" : "font-mono"
											}
										>
											{formatFingerprint(m.fingerprint)}
										</code>
										<span className="mt-0.5 block text-[11px] text-muted-foreground">
											created {createdStr}
											{updatedStr !== createdStr ? ` · updated ${updatedStr}` : ""}
										</span>
									</span>
								</button>
							);
						})}
					</div>
				</div>
			)}

			{fingerprint && (
				<div className="grid gap-1.5">
					<Label htmlFor="restore-pass">Backup passphrase</Label>
					<Input
						ref={passRef}
						id="restore-pass"
						type="password"
						value={passphrase}
						onChange={(e) => setPassphrase(e.target.value)}
						onKeyDown={(e) => e.key === "Enter" && restore()}
						placeholder="Passphrase used when the key was escrowed"
						autoComplete="off"
					/>
				</div>
			)}

			<FormError message={error} />

			{fingerprint && (
				<Button type="button" className="w-full" onClick={restore} disabled={busy || !passphrase}>
					{busy ? "Decrypting…" : "Decrypt & sign in"}
				</Button>
			)}
			<p className="text-[11px] leading-relaxed text-muted-foreground">
				The stored backup is a passphrase-encrypted private key. Decryption happens in this browser
				— the passphrase is never sent anywhere.
			</p>
		</div>
	);
}

/** Publish flow for a pasted private key (Encryptor Registry card). */
function PublishPasteForm({
	onUseKey,
	onDone,
}: {
	onUseKey: (config: PrivateKeyConfig) => void;
	onDone: () => void;
}) {
	const [armored, setArmored] = useState("");
	const [parsed, setParsed] = useState<{
		info: AnyKeyInfo;
		label: string;
		isDecrypted: boolean;
	} | null>(null);
	// Passphrase for the pasted key: when the key arrived decrypted it is
	// used to encrypt it locally (and as the replace-proof passphrase);
	// when it arrived encrypted it is only needed for the replace proof.
	const [passphrase, setPassphrase] = useState("");
	const [showPass, setShowPass] = useState(false);
	const [escrow, setEscrow] = useState(true);
	const [localEncryptNeeded, setLocalEncryptNeeded] = useState(false);
	const [encrypting, setEncrypting] = useState(false);
	const [readyArmor, setReadyArmor] = useState<string | null>(null);
	const [outcome, setOutcome] = useState<PublishOutcome | null>(null);
	const [replacePass, setReplacePass] = useState("");
	const [busy, setBusy] = useState(false);
	const [error, setError] = useState<string | null>(null);
	const pub = useRegistryPublish();
	const writesLocked = useWritesLocked();

	const check = useCallback(async (text: string) => {
		setError(null);
		setParsed(null);
		setReadyArmor(null);
		setLocalEncryptNeeded(false);
		if (!text.trim()) return;
		try {
			const v = await validateArmoredKey(text.trim());
			if (!v.ok || !v.info) {
				setError(v.error ?? "That doesn't parse as an armored key.");
				return;
			}
			if (!("isPrivate" in v.info) || v.info.isPrivate !== true) {
				setError("That's a PUBLIC key. Paste the matching private key to sign in with it.");
				return;
			}
			const first = v.info.userIDs[0];
			setParsed({
				info: v.info,
				label: first?.name || first?.email || formatFingerprint(v.info.fingerprint),
				isDecrypted: Boolean(v.info.isDecrypted),
			});
			setLocalEncryptNeeded(Boolean(v.info.isDecrypted));
		} catch (e) {
			setError(e instanceof Error ? e.message : "Could not read that key.");
		}
	}, []);

	/** Encrypt a decrypted paste locally so it can be escrowed + stored. */
	const encryptLocally = useCallback(async () => {
		if (!parsed || !armored.trim()) return;
		if (passphrase.length < 8) {
			setError("Choose a passphrase of at least 8 characters to protect the key.");
			return;
		}
		setEncrypting(true);
		setError(null);
		try {
			const openpgp = await import("openpgp");
			const key = await openpgp.readKey({ armoredKey: armored.trim() });
			const encrypted = await openpgp.encryptKey({ privateKey: key as never, passphrase });
			const reArmored = encrypted.armor();
			const v = await validateArmoredKey(reArmored);
			if (!v.ok || !v.info) throw new Error("Re-encrypted key failed validation.");
			setReadyArmor(reArmored);
			setLocalEncryptNeeded(false);
		} catch (e) {
			setError(e instanceof Error ? e.message : "Encryption failed.");
		} finally {
			setEncrypting(false);
		}
	}, [armored, parsed, passphrase]);

	const doPublish = useCallback(async () => {
		if (!parsed) return;
		const sourceArmor = readyArmor ?? armored.trim();
		if (localEncryptNeeded && !readyArmor) {
			setError(
				"Encrypt this decrypted key with a passphrase first — the registry never stores usable private key bytes.",
			);
			return;
		}
		setBusy(true);
		try {
			const publicArmored = await publicFromPrivate(sourceArmor);
			const escrowArmor = escrow ? sourceArmor : undefined;
			const attempt = await pub.publish({
				publicArmored,
				...(escrowArmor ? { encryptedPrivate: escrowArmor } : {}),
				signArmor: sourceArmor,
			});
			if (attempt.status === "published") {
				setOutcome(attempt.outcome);
				setPassphrase("");
			}
		} catch (e) {
			setError(formatRegistryError(e, "Publishing failed"));
		} finally {
			setBusy(false);
		}
	}, [armored, escrow, localEncryptNeeded, parsed, pub, readyArmor]);

	const doReplace = useCallback(async () => {
		if (!parsed) return;
		const sourceArmor = readyArmor ?? armored.trim();
		const proofPass = passphrase || replacePass;
		setBusy(true);
		try {
			const publicArmored = await publicFromPrivate(sourceArmor);
			const escrowArmor = escrow ? sourceArmor : undefined;
			const attempt = await pub.confirmReplace({
				publicArmored,
				...(escrowArmor ? { encryptedPrivate: escrowArmor } : {}),
				signArmor: sourceArmor,
				signPassphrase: proofPass,
			});
			if (attempt.status === "published") {
				setOutcome({ ...attempt.outcome, escrowLag: !escrow });
				setReplacePass("");
			}
		} catch (e) {
			setError(formatRegistryError(e, "Replace failed"));
		} finally {
			setBusy(false);
		}
	}, [armored, escrow, parsed, pub, readyArmor, replacePass, passphrase]);

	const useKey = useCallback(() => {
		if (!parsed) return;
		const sourceArmor = readyArmor ?? armored.trim();
		onUseKey({
			source: "manual",
			label: parsed.label,
			encryptedArmored: sourceArmor,
			info: parsed.info,
		});
		onDone();
	}, [armored, onDone, onUseKey, parsed, readyArmor]);

	return (
		<div className="space-y-3" data-testid="publish-paste-form">
			{outcome ? (
				<div className="space-y-3">
					{/* Mounted with the outcome card so screen readers hear the
                                            result instead of silent content swap (publish is async
                                            and happens away from focus). */}
					<span className="sr-only" role="status">
						Key published to the registry. Fingerprint {formatFingerprint(outcome.fingerprint)}. The
						one-time revocation token is on screen — save it now.
					</span>
					<PublishOutcomeCard outcome={outcome} />
					<Button type="button" className="w-full" onClick={useKey}>
						Use this key in Encryptor
					</Button>
				</div>
			) : (
				<>
					<div className="grid gap-1.5">
						<div className="flex items-center justify-between gap-2">
							<Label htmlFor="publish-armor">Private key (armored)</Label>
							<KeyFilePicker
								id="publish-armor-file"
								onLoaded={(t) => {
									setArmored(t);
									void check(t);
								}}
							/>
						</div>
						<Textarea
							id="publish-armor"
							value={armored}
							onChange={(e) => setArmored(e.target.value)}
							onBlur={() => void check(armored)}
							placeholder={
								"-----BEGIN PGP PRIVATE KEY BLOCK-----\n…\n-----END PGP PRIVATE KEY BLOCK-----"
							}
							rows={6}
							className="font-mono text-xs"
							spellCheck={false}
						/>
					</div>

					{parsed && (
						<p className="text-xs text-muted-foreground">
							<code className="font-mono">{formatFingerprint(parsed.info.fingerprint)}</code>
							{localEncryptNeeded
								? " · decrypted key — it will be encrypted locally before anything is stored or sent."
								: " · passphrase-protected"}
						</p>
					)}

					{!parsed && (
						<p className="text-[11px] leading-relaxed text-muted-foreground">
							No key yet? Switch to <strong>Generate &amp; publish</strong> above to create one
							here, then publish it.
						</p>
					)}

					{parsed && localEncryptNeeded && !readyArmor && (
						<div className="grid gap-1.5 rounded-lg border border-amber-500/40 bg-amber-500/5 p-3">
							<Label htmlFor="publish-new-pass">New backup passphrase</Label>
							<div className="flex gap-2">
								<Input
									id="publish-new-pass"
									type={showPass ? "text" : "password"}
									value={passphrase}
									onChange={(e) => setPassphrase(e.target.value)}
									autoComplete="new-password"
								/>
								<Button
									type="button"
									variant="outline"
									size="icon"
									onClick={() => setShowPass((s) => !s)}
									aria-label={showPass ? "Hide passphrase" : "Show passphrase"}
								>
									{showPass ? (
										<EyeOff aria-hidden className="size-4" />
									) : (
										<Eye aria-hidden className="size-4" />
									)}
								</Button>
								<Button
									type="button"
									variant="outline"
									size="icon"
									onClick={() => setPassphrase(generatePassphrase())}
									aria-label="Generate a strong passphrase"
									title="Generate a strong passphrase"
								>
									<Dice5 aria-hidden className="size-4" />
								</Button>
							</div>
							<PassphraseStrengthMeter passphrase={passphrase} idPrefix="publish-pass" />
							<Button
								type="button"
								size="sm"
								onClick={encryptLocally}
								disabled={encrypting || passphrase.length < 8}
							>
								{encrypting ? "Encrypting…" : "Encrypt locally"}
							</Button>
						</div>
					)}

					{parsed && !localEncryptNeeded && (
						<div className="flex items-start gap-2">
							<Checkbox
								id="publish-escrow"
								checked={escrow}
								onCheckedChange={(v) => setEscrow(v === true)}
								className="mt-0.5"
							/>
							<div className="grid gap-0.5">
								<Label htmlFor="publish-escrow" className="text-xs font-medium">
									Also store the encrypted backup (escrow)
								</Label>
								<p className="text-[11px] leading-relaxed text-muted-foreground">
									Lets you restore this key on any device with just the fingerprint + passphrase.
									The registry only ever holds the passphrase-encrypted blob.
								</p>
							</div>
						</div>
					)}

					{parsed && writesLocked === true && <WritesLockedNotice />}

					{parsed && !pub.replaceNeeded && (
						<Button
							type="button"
							className="w-full"
							onClick={doPublish}
							disabled={busy || pub.publishing || writesLocked === true}
						>
							{(busy || pub.publishing) && <Loader2 aria-hidden className="size-4 animate-spin" />}
							Publish to the registry
						</Button>
					)}

					{pub.replaceNeeded && (
						<ReplacePanel
							passphrase={replacePass || passphrase}
							onPassphraseChange={setReplacePass}
							onConfirm={doReplace}
							busy={busy || pub.replacing}
							error={pub.error}
							locked={writesLocked === true}
						/>
					)}

					{/* Always mounted once a key is parsed — including during the
                                            replace flow: the 409'd attempt consumed the single-use
                                            Turnstile token server-side, so a fresh one must be mintable
                                            right here or the replace dead-ends with an unfixable 403. */}
					{parsed && <TurnstileGate onToken={pub.setTsToken} attempt={pub.tsAttempt} />}

					<FormError message={error ?? (pub.replaceNeeded ? null : pub.error)} />
				</>
			)}
		</div>
	);
}

/**
 * Self-service retraction — the emergency brake the publish outcome card
 * promises: fingerprint + the one-time token shown at publish (works even
 * when the key material or passphrase is lost). Two-phase on purpose:
 * lookup first (so the confirm button never acts on a typo'd fingerprint),
 * then an explicit destructive confirm. NOT the admin path — the per-key
 * token IS the authorization, no shared secret involved.
 */
function RevokeTokenForm({ writesLocked, onDone }: { writesLocked: boolean; onDone: () => void }) {
	const [fpr, setFpr] = useState("");
	const [token, setToken] = useState("");
	const [reason, setReason] = useState("");
	const [found, setFound] = useState<RegistryLookupKey | null>(null);
	// Identity from the looked-up PUBLIC key's userIDs — a last-mile aid so
	// the confirm step shows WHO a fingerprint belongs to, not just that it
	// exists (the destructive action is irreversible; misidentification is
	// the one mistake the token cannot undo). Parsed locally, never sent.
	const [identity, setIdentity] = useState<string | null>(null);
	const [checking, setChecking] = useState(false);
	const [revoking, setRevoking] = useState(false);
	const [done, setDone] = useState(false);
	const [error, setError] = useState<string | null>(null);

	const normalizeFpr = (raw: string) => raw.replace(/\s+/g, "").replace(/^0x/i, "").toUpperCase();
	const validFpr = /^[0-9A-F]{40}$/.test(normalizeFpr(fpr));

	const setQuery = (v: string) => {
		// Any edit invalidates the preview — the confirm button must never
		// act on facts looked up for a DIFFERENT fingerprint or token.
		setFpr(v);
		setFound(null);
		setError(null);
	};

	const check = useCallback(async () => {
		const f = normalizeFpr(fpr);
		if (!/^[0-9A-F]{40}$/.test(f)) return;
		setChecking(true);
		setError(null);
		try {
			const hits = await registryLookup({ fingerprint: f });
			setFound(hits[0] ?? null);
			if (hits.length === 0) {
				setError("No key with that fingerprint is on the registry.");
				setIdentity(null);
				return;
			}
			try {
				const v = await validateArmoredKey(hits[0].armored);
				const u = v.info && "userIDs" in v.info ? v.info.userIDs[0] : undefined;
				setIdentity(u ? [u.name, u.email].filter(Boolean).join(" — ") || null : null);
			} catch {
				setIdentity(null); // identity is a nicety — never block the flow on it
			}
		} catch (e) {
			setError(formatRegistryError(e, "Registry lookup failed"));
		} finally {
			setChecking(false);
		}
	}, [fpr]);

	const revoke = useCallback(async () => {
		const f = normalizeFpr(fpr);
		if (!found || !token.trim()) return;
		setRevoking(true);
		setError(null);
		try {
			await registryRevokeByToken(f, token.trim(), reason.trim() || undefined);
			setDone(true);
		} catch (e) {
			setError(formatRegistryError(e, "Revocation failed"));
		} finally {
			setRevoking(false);
		}
	}, [fpr, found, reason, token]);

	if (done) {
		return (
			<div className="space-y-3" data-testid="revoke-done">
				<span className="sr-only" role="status">
					The key was permanently revoked on the registry.
				</span>
				<div className="rounded-lg border border-emerald-500/40 bg-emerald-500/5 p-3">
					<p className="text-xs font-medium text-emerald-800 dark:text-emerald-300">Key revoked.</p>
					<p className="mt-1 text-[11px] leading-relaxed text-muted-foreground">
						Lookups of <code className="font-mono">{formatFingerprint(normalizeFpr(fpr))}</code> now
						report it as revoked. The escrowed backup, if any, was purged. This cannot be undone.
					</p>
				</div>
				<Button type="button" className="w-full" onClick={onDone}>
					Done
				</Button>
			</div>
		);
	}

	return (
		<div className="space-y-3" data-testid="revoke-form">
			{writesLocked && <WritesLockedNotice />}
			<div className="grid gap-1.5">
				<Label htmlFor="revoke-fpr">Key fingerprint</Label>
				<Input
					id="revoke-fpr"
					value={fpr}
					onChange={(e) => setQuery(e.target.value)}
					onKeyDown={(e) => {
						if (e.key === "Enter" && validFpr && !found) {
							e.preventDefault();
							void check();
						}
					}}
					placeholder="40-character fingerprint (spaces and 0x are fine)"
					className="font-mono text-xs"
					autoComplete="off"
					spellCheck={false}
					disabled={writesLocked}
				/>
			</div>
			<div className="grid gap-1.5">
				<Label htmlFor="revoke-token">One-time revocation token</Label>
				<Input
					id="revoke-token"
					type="password"
					value={token}
					onChange={(e) => setToken(e.target.value)}
					placeholder="Shown once when the key was published"
					className="font-mono text-xs"
					autoComplete="off"
					disabled={writesLocked}
				/>
			</div>
			<div className="grid gap-1.5">
				<Label htmlFor="revoke-reason">
					Reason{" "}
					<span className="font-normal text-muted-foreground">(optional, shown publicly)</span>
				</Label>
				<Input
					id="revoke-reason"
					value={reason}
					onChange={(e) => setReason(e.target.value)}
					placeholder="e.g. key superseded, machine lost"
					autoComplete="off"
					maxLength={200}
					disabled={writesLocked}
				/>
			</div>
			{found && (
				<div className="space-y-2 rounded-lg border border-border p-3" data-testid="revoke-preview">
					<div className="grid gap-0.5 text-xs">
						<p>
							<span className="text-muted-foreground">Fingerprint: </span>
							<code className="font-mono">{formatFingerprint(found.fingerprint)}</code>
						</p>
						{identity && (
							<p>
								<span className="text-muted-foreground">Identity: </span>
								<span className="font-medium">{identity}</span>
							</p>
						)}
						<p>
							<span className="text-muted-foreground">Status: </span>
							{found.revoked ? (
								<span>
									already revoked
									{found.revokedAt
										? ` on ${new Date(found.revokedAt * 1000).toLocaleDateString()}`
										: ""}
									{found.revokeReason ? ` — “${found.revokeReason}”` : ""}
								</span>
							) : (
								<span className="font-medium">
									active on the registry
									{found.createdAt
										? ` since ${new Date(found.createdAt * 1000).toLocaleDateString()}`
										: ""}
								</span>
							)}
						</p>
					</div>
					{!found.revoked && (
						<>
							<p className="text-[11px] leading-relaxed text-muted-foreground">
								Revocation is <strong>permanent</strong>: the key is marked revoked for everyone,
								its escrowed backup is purged, and the fingerprint can never be re-published. Keep
								the token — it stops working after this.
							</p>
							<Button
								type="button"
								variant="destructive"
								size="sm"
								onClick={() => void revoke()}
								disabled={writesLocked || revoking || !token.trim()}
							>
								{revoking && <Loader2 aria-hidden className="size-4 animate-spin" />}
								{revoking ? "Revoking…" : "Permanently revoke this key"}
							</Button>
						</>
					)}
				</div>
			)}
			{!found && (
				<Button
					type="button"
					size="sm"
					onClick={() => void check()}
					disabled={checking || writesLocked || !validFpr}
				>
					{checking && <Loader2 aria-hidden className="size-4 animate-spin" />}
					{checking ? "Looking up…" : "Look up key"}
				</Button>
			)}
			<FormError message={error} />
		</div>
	);
}

/* --------------------------------- Keybase --------------------------------- */

/** Keybase password login — the real PDPKA flow via the app's proxies. */
function KeybaseDialog({
	open,
	onOpenChange,
	onUseKey,
}: {
	open: boolean;
	onOpenChange: (open: boolean) => void;
	onUseKey: (config: PrivateKeyConfig) => void;
}) {
	const [username, setUsername] = useState("");
	const [password, setPassword] = useState("");
	const [busy, setBusy] = useState(false);
	const [error, setError] = useState<string | null>(null);

	const submit = useCallback(async () => {
		setBusy(true);
		setError(null);
		try {
			// Let the spinner paint before scrypt blocks the main thread.
			await new Promise((r) => setTimeout(r, 50));
			const { loginWithPassword } = await import("@/lib/pgp/keybase-auth");
			const { me, privateKey: decrypted } = await loginWithPassword(username.trim(), password, {
				getsaltUrl: PROXIES.getsaltProxy,
				loginUrl: PROXIES.loginProxy,
			});
			if (!me.private_key_bundle) {
				throw new Error(
					"Your Keybase account has no private key bundle. Generate one in the Keybase app first.",
				);
			}
			const armored = decrypted.armor();
			const info = await validateArmoredKey(armored);
			if (!info.ok || !info.info)
				throw new Error(info.error ?? "Decrypted key could not be parsed.");
			// Store ONLY the username + metadata — never the decrypted key.
			onUseKey({
				source: "keybase",
				label: `@${me.username}`,
				username: me.username,
				info: info.info,
			});
			toast({ title: "Signed in", description: `Keybase key for @${me.username} is ready.` });
			onOpenChange(false);
		} catch (e) {
			setError(e instanceof Error ? e.message : "Keybase login failed.");
		} finally {
			setBusy(false);
		}
	}, [onOpenChange, onUseKey, password, username]);

	return (
		<LoginDialog
			sourceId="keybase"
			open={open}
			onOpenChange={onOpenChange}
			title="Keybase registry"
			description="Sign in with your Keybase username and password. The private key is decrypted locally — your password never leaves this browser."
		>
			<form
				className="grid gap-3"
				data-testid="keybase-form"
				onSubmit={(e) => {
					e.preventDefault();
					if (!busy && username.trim() && password) void submit();
				}}
			>
				<div className="grid gap-1.5">
					<Label htmlFor="kb-user">Keybase username</Label>
					<Input
						id="kb-user"
						value={username}
						onChange={(e) => setUsername(e.target.value)}
						placeholder="e.g. alice"
						autoComplete="off"
						spellCheck={false}
					/>
				</div>
				<div className="grid gap-1.5">
					<Label htmlFor="kb-pass">Keybase password</Label>
					<Input
						id="kb-pass"
						type="password"
						value={password}
						onChange={(e) => setPassword(e.target.value)}
						autoComplete="off"
					/>
				</div>
				<FormError message={error} />
				<DialogFooter>
					<Button type="submit" className="w-full" disabled={busy || !username.trim() || !password}>
						{busy && <Loader2 aria-hidden className="size-4 animate-spin" />}
						{busy ? "Signing in…" : "Sign in with Keybase"}
					</Button>
				</DialogFooter>
			</form>
		</LoginDialog>
	);
}

/* ------------------- OpenPGP / Ubuntu keyserver pastes -------------------- */

/**
 * Paste-a-private-key sign-in for keyservers. The keyserver only hosts the
 * PUBLIC half — signing in means supplying the matching private key here.
 */
function PasteKeyDialog({
	open,
	source,
	onOpenChange,
	onUseKey,
}: {
	open: boolean;
	source: "openpgp" | "ubuntu";
	onOpenChange: (open: boolean) => void;
	onUseKey: (config: PrivateKeyConfig) => void;
}) {
	const [armored, setArmored] = useState("");
	const [busy, setBusy] = useState(false);
	const [error, setError] = useState<string | null>(null);

	const copy =
		source === "openpgp"
			? {
					title: "OpenPGP registry",
					blurb:
						"keys.openpgp.org only hosts your PUBLIC key. To sign in here, paste the matching private key — it is validated and kept in this browser, never uploaded.",
					server: "keys.openpgp.org",
				}
			: {
					title: "Ubuntu Registry",
					blurb:
						"keyserver.ubuntu.com only hosts your PUBLIC key. To sign in here, paste the matching private key — it is validated and kept in this browser, never uploaded.",
					server: "keyserver.ubuntu.com",
				};

	const submit = useCallback(async () => {
		setBusy(true);
		setError(null);
		try {
			const v = await validateArmoredKey(armored.trim());
			if (!v.ok || !v.info) throw new Error(v.error ?? "That doesn't parse as an armored key.");
			if (!("isPrivate" in v.info) || v.info.isPrivate !== true) {
				throw new Error(
					"That's a PUBLIC key — the keyserver already has that. Paste the PRIVATE key.",
				);
			}
			const first = v.info.userIDs[0];
			onUseKey({
				source: "manual",
				label: first?.name || first?.email || formatFingerprint(v.info.fingerprint),
				encryptedArmored: armored.trim(),
				info: v.info,
			});
			toast({
				title: "Signed in",
				description: "The private key was validated and configured locally.",
			});
			onOpenChange(false);
		} catch (e) {
			setError(e instanceof Error ? e.message : "Could not read that key.");
		} finally {
			setBusy(false);
		}
	}, [armored, onOpenChange, onUseKey]);

	return (
		<LoginDialog
			sourceId={source}
			open={open}
			onOpenChange={onOpenChange}
			title={copy.title}
			description={copy.blurb}
		>
			<div className="grid gap-3" data-testid="paste-key-form">
				<div className="grid gap-1.5">
					<div className="flex items-center justify-between gap-2">
						<Label htmlFor={`paste-armor-${source}`}>Private key (armored)</Label>
						<KeyFilePicker id={`paste-armor-file-${source}`} onLoaded={setArmored} />
					</div>
					<Textarea
						id={`paste-armor-${source}`}
						value={armored}
						onChange={(e) => {
							setArmored(e.target.value);
							setError(null);
						}}
						placeholder={
							"-----BEGIN PGP PRIVATE KEY BLOCK-----\n…\n-----END PGP PRIVATE KEY BLOCK-----"
						}
						rows={7}
						className="font-mono text-xs"
						spellCheck={false}
					/>
				</div>
				<FormError message={error} />
				<Button
					type="button"
					className="w-full"
					onClick={submit}
					disabled={busy || !armored.trim()}
				>
					{busy && <Loader2 aria-hidden className="size-4 animate-spin" />}
					{busy ? "Validating…" : `Use this ${copy.server} key`}
				</Button>
				<p className="text-[11px] leading-relaxed text-muted-foreground">
					Tip: export with{" "}
					<code className="rounded bg-muted px-1">gpg --export-secret-keys -a</code>. If the key is
					passphrase-protected you'll be asked for it only when you actually sign or decrypt.
				</p>
			</div>
		</LoginDialog>
	);
}

/* -------------------------------- Local keys -------------------------------- */

/** Generate a fresh pair (with optional registry publish) or paste a key. */
function LocalDialog({
	open,
	onOpenChange,
	onUseKey,
}: {
	open: boolean;
	onOpenChange: (open: boolean) => void;
	onUseKey: (config: PrivateKeyConfig) => void;
}) {
	const [mode, setMode] = useState<"generate" | "paste">("generate");
	return (
		<LoginDialog
			sourceId="local"
			open={open}
			onOpenChange={onOpenChange}
			title="Local keys"
			description="Generate a new key pair in this browser, or paste one you manage with your own tools."
		>
			<div className="space-y-4">
				<Segmented
					value={mode}
					onChange={(v) => setMode(v as "generate" | "paste")}
					options={[
						{ id: "generate", label: "Generate" },
						{ id: "paste", label: "Paste" },
					]}
				/>
				{mode === "generate" ? (
					<GenerateForm onUseKey={onUseKey} onDone={() => onOpenChange(false)} />
				) : (
					<LocalPasteForm onUseKey={onUseKey} onDone={() => onOpenChange(false)} />
				)}
			</div>
		</LoginDialog>
	);
}

/** In-browser key generation with optional publish + escrow. */
function GenerateForm({
	onUseKey,
	onDone,
	initialPublish = false,
}: {
	onUseKey: (config: PrivateKeyConfig) => void;
	onDone: () => void;
	/** Preset for the registry dialog: "Encryptor Registry → Generate &
	 *  publish" implies the publish intent (the checkbox stays togglable). */
	initialPublish?: boolean;
}) {
	const [name, setName] = useState("");
	const [email, setEmail] = useState("");
	const [passphrase, setPassphrase] = useState("");
	const [showPass, setShowPass] = useState(false);
	const [expiry, setExpiry] = useState("0");
	const [publish, setPublish] = useState(initialPublish);
	const [escrow, setEscrow] = useState(true);
	const [generating, setGenerating] = useState(false);
	const [outcome, setOutcome] = useState<PublishOutcome | null>(null);
	// The generated key is held here while the one-time revocation token
	// is on screen — configuring it immediately would unmount the gate
	// (key set => app renders) and swallow the token before it can be
	// copied. "Start using Encryptor" commits it.
	const [pending, setPending] = useState<PrivateKeyConfig | null>(null);
	const [error, setError] = useState<string | null>(null);
	const pub = useRegistryPublish();
	const writesLocked = useWritesLocked();

	// Passphrase is OPTIONAL (owner feedback: "Don't require password for
	// local keys, but warn") — an empty passphrase generates an unprotected
	// key, surfaced by the inline warning + escrow gating below. The inline
	// warning and the escrow/quantum-seal gating react to hasPassphrase.
	const hasPassphrase = passphrase.length > 0;
	const canGenerate = !generating && (email.trim() === "" || EMAIL_RE.test(email.trim()));

	const submit = useCallback(async () => {
		setGenerating(true);
		setError(null);
		try {
			const seconds = Number(expiry) * 365 * 24 * 3600;
			const pair = await generateKeyPair({
				...(name.trim() ? { name: name.trim() } : {}),
				...(email.trim() ? { email: email.trim().toLowerCase() } : {}),
				passphrase,
				// Modern Ed25519 + X25519 (owner feedback: generated keys must not
				// be "EdDSA (legacy)"). Still v4 packets — 40-hex fingerprints, so
				// every registry/PGP-words/QR surface works unchanged.
				type: "curve25519",
				expirationSeconds: seconds > 0 ? seconds : undefined,
			});
			const label = name.trim() || email.trim() || "Ed25519 key";
			// Quantum-seal pair (ML-KEM-768) — generated alongside when a
			// passphrase exists so the secret half is wrapped by it. The PUBLIC
			// half publishes with the key (pqSealPk) so correspondents can seal
			// archive copies to it; the secret half stays on this device.
			let seal: QuantumSealConfig | null = null;
			if (hasPassphrase) {
				try {
					const sealPair = generateSealKeyPair();
					seal = await wrapSealSecret(sealPair.publicKey, sealPair.secretKey, passphrase);
				} catch {
					seal = null; // PQ is additive — never block key generation
				}
			}
			const config: PrivateKeyConfig = {
				source: "generated",
				label,
				encryptedArmored: pair.privateKey,
				info: pair.info,
				...(seal ? { pq: seal } : {}),
			};
			if (!publish) {
				onUseKey(config);
				toast({ title: "Signed in", description: `“${label}” is ready to use.` });
				onDone();
				return;
			}
			const attempt = await pub.publish({
				publicArmored: pair.publicKey,
				// Escrow needs a passphrase (the server only accepts fully
				// passphrase-encrypted private keys) — gated on hasPassphrase.
				...(hasPassphrase && escrow ? { encryptedPrivate: pair.privateKey } : {}),
				...(seal ? { pqSealPk: seal.pk } : {}),
				signArmor: pair.privateKey,
			});
			if (attempt.status === "published") {
				// Show the one-time token FIRST; commit the key when the
				// user dismisses the outcome card (see "Start using Encryptor").
				setPending(config);
				setOutcome(attempt.outcome);
			} else if (attempt.status === "replace-needed") {
				// A freshly generated fingerprint colliding with an existing
				// record is cryptographically impossible — treat it as an
				// anomaly instead of offering a possession-proof panel that
				// could not be signed by the new key anyway.
				setError(
					"The registry says this fingerprint already exists, which should be impossible for a fresh key — please retry.",
				);
			} else {
				// FAILURE — surface it and STAY on the form. (This used to fall
				// through to a silent sign-in: `pub.error` state read inside
				// this closure was stale-null after the awaited publish, so a
				// 429/503/403 failure closed the dialog and configured the key
				// anyway, dropping both the error and the outcome/token.)
				setError(attempt.error);
			}
		} catch (e) {
			setError(e instanceof Error ? e.message : "Key generation failed.");
		} finally {
			setGenerating(false);
		}
	}, [email, expiry, name, onDone, onUseKey, passphrase, pub, publish, escrow]);

	return (
		<div className="grid gap-3" data-testid="generate-form">
			{outcome ? (
				<div className="space-y-3">
					<span className="sr-only" role="status">
						Key generated and published to the registry. Fingerprint{" "}
						{formatFingerprint(outcome.fingerprint)}. The one-time revocation token is on screen —
						save it now.
					</span>
					<PublishOutcomeCard outcome={outcome} />
					<Button
						type="button"
						className="w-full"
						onClick={() => {
							if (pending) onUseKey(pending);
							onDone();
						}}
					>
						Start using Encryptor
					</Button>
				</div>
			) : (
				<>
					<div className="grid gap-3 sm:grid-cols-2">
						<div className="grid gap-1.5">
							<Label htmlFor="gen-name">Name (optional)</Label>
							<Input
								id="gen-name"
								value={name}
								onChange={(e) => setName(e.target.value)}
								autoComplete="off"
							/>
						</div>
						<div className="grid gap-1.5">
							<Label htmlFor="gen-email">Email (optional)</Label>
							<Input
								id="gen-email"
								type="email"
								value={email}
								onChange={(e) => setEmail(e.target.value)}
								placeholder="you@example.com"
								autoComplete="off"
							/>
						</div>
					</div>
					<div className="grid gap-1.5">
						<Label htmlFor="gen-pass">
							Passphrase (optional — protects the key on this device)
						</Label>
						<div className="flex gap-2">
							<Input
								id="gen-pass"
								type={showPass ? "text" : "password"}
								value={passphrase}
								onChange={(e) => setPassphrase(e.target.value)}
								autoComplete="new-password"
							/>
							<Button
								type="button"
								variant="outline"
								size="icon"
								onClick={() => setShowPass((s) => !s)}
								aria-label={showPass ? "Hide passphrase" : "Show passphrase"}
							>
								{showPass ? (
									<EyeOff aria-hidden className="size-4" />
								) : (
									<Eye aria-hidden className="size-4" />
								)}
							</Button>
							<Button
								type="button"
								variant="outline"
								size="icon"
								onClick={() => setPassphrase(generatePassphrase())}
								aria-label="Generate a strong passphrase"
								title="Generate a strong passphrase"
							>
								<Dice5 aria-hidden className="size-4" />
							</Button>
						</div>
						<PassphraseStrengthMeter passphrase={passphrase} idPrefix="gen-pass" />
						{!hasPassphrase && (
							<p className="flex items-start gap-1.5 text-[11px] leading-relaxed text-amber-700 dark:text-amber-400">
								<TriangleAlert aria-hidden className="mt-0.5 size-3.5 shrink-0" />
								<span>
									No passphrase — the private key will be stored unencrypted on this device. Anyone
									using this browser profile can read your messages.
								</span>
							</p>
						)}
					</div>
					<div className="grid gap-1.5">
						<Label htmlFor="gen-expiry">Expires</Label>
						<select
							id="gen-expiry"
							value={expiry}
							onChange={(e) => setExpiry(e.target.value)}
							className="h-9 rounded-md border border-input bg-transparent px-3 py-1 text-sm shadow-xs"
						>
							<option value="0">Never</option>
							<option value="1">In 1 year</option>
							<option value="2">In 2 years</option>
							<option value="5">In 5 years</option>
						</select>
					</div>
					<div className="space-y-2 rounded-lg border border-border p-3">
						<div className="flex items-start gap-2">
							<Checkbox
								id="gen-publish"
								checked={publish}
								onCheckedChange={(v) => setPublish(v === true)}
								className="mt-0.5"
							/>
							<div className="grid gap-0.5">
								<Label htmlFor="gen-publish" className="text-xs font-medium">
									Also publish to the Encryptor registry
								</Label>
								<p className="text-[11px] leading-relaxed text-muted-foreground">
									Puts the public key where anyone can find it by email or fingerprint.
								</p>
							</div>
						</div>
						{publish && (
							<div className="flex items-start gap-2 pl-6">
								<Checkbox
									id="gen-escrow"
									checked={escrow && hasPassphrase}
									onCheckedChange={(v) => setEscrow(v === true)}
									disabled={!hasPassphrase}
									className="mt-0.5"
								/>
								<div className="grid gap-0.5">
									<Label htmlFor="gen-escrow" className="text-xs font-medium">
										Store encrypted backup (escrow)
									</Label>
									<p className="text-[11px] leading-relaxed text-muted-foreground">
										Restore from any device with fingerprint + passphrase.
										{!hasPassphrase && " Needs a passphrase — add one above."}
									</p>
								</div>
							</div>
						)}
					</div>
					{publish && <TurnstileGate onToken={pub.setTsToken} attempt={pub.tsAttempt} />}
					{publish && writesLocked === true && <WritesLockedNotice />}
					<FormError message={error ?? pub.error} />
					<Button
						type="button"
						className="w-full"
						onClick={submit}
						disabled={!canGenerate || (publish && writesLocked === true)}
					>
						{generating && <Loader2 aria-hidden className="size-4 animate-spin" />}
						{generating ? "Generating…" : publish ? "Generate & publish" : "Generate & sign in"}
					</Button>
				</>
			)}
		</div>
	);
}

/** Paste a locally managed key (GnuPG & co) — no registry involved. */
function LocalPasteForm({
	onUseKey,
	onDone,
}: {
	onUseKey: (config: PrivateKeyConfig) => void;
	onDone: () => void;
}) {
	const [armored, setArmored] = useState("");
	const [busy, setBusy] = useState(false);
	const [error, setError] = useState<string | null>(null);

	const submit = useCallback(async () => {
		setBusy(true);
		setError(null);
		try {
			const v = await validateArmoredKey(armored.trim());
			if (!v.ok || !v.info) throw new Error(v.error ?? "That doesn't parse as an armored key.");
			if (!("isPrivate" in v.info) || v.info.isPrivate !== true) {
				throw new Error("That's a public key. Paste a private key to sign/decrypt.");
			}
			const first = v.info.userIDs[0];
			onUseKey({
				source: "manual",
				label: first?.name || first?.email || formatFingerprint(v.info.fingerprint),
				encryptedArmored: armored.trim(),
				info: v.info,
			});
			toast({ title: "Signed in", description: "Your local key is configured." });
			onDone();
		} catch (e) {
			setError(e instanceof Error ? e.message : "Could not read that key.");
		} finally {
			setBusy(false);
		}
	}, [armored, onDone, onUseKey]);

	return (
		<div className="grid gap-3" data-testid="local-paste-form">
			<div className="grid gap-1.5">
				<div className="flex items-center justify-between gap-2">
					<Label htmlFor="local-armor">Private key (armored)</Label>
					<KeyFilePicker id="local-armor-file" onLoaded={setArmored} />
				</div>
				<Textarea
					id="local-armor"
					value={armored}
					onChange={(e) => setArmored(e.target.value)}
					placeholder={
						"-----BEGIN PGP PRIVATE KEY BLOCK-----\n…\n-----END PGP PRIVATE KEY BLOCK-----"
					}
					rows={7}
					className="font-mono text-xs"
					spellCheck={false}
				/>
			</div>
			<FormError message={error} />
			<Button type="button" className="w-full" onClick={submit} disabled={busy || !armored.trim()}>
				{busy && <Loader2 aria-hidden className="size-4 animate-spin" />}
				{busy ? "Validating…" : "Use this key"}
			</Button>
		</div>
	);
}
