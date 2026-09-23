"use client";

/**
 * Dedicated settings dialog — deliberately SEPARATE from key setup.
 *
 * # Mr. AI Acting on s183173's Behalf
 *
 * The key/auth dialog (ConfigureModal) owns everything about the KEY:
 * Keybase login, manual paste, generation, details, share, download/clear.
 * THIS dialog owns everything about the APP: composer behavior (editor,
 * auto sign), encryption preferences (compression, quantum-sealed copy),
 * session security (passphrase auto-lock) and data (backup/restore).
 *
 * Navigation is two-layered (feedback round 11): a text search that filters
 * rows live, and section chips that jump straight to a section. On desktop
 * the sections live in a scrollable single column with a sticky chip rail;
 * the chips scrollIntoView the target section inside the dialog body.
 */
import { useMemo, useRef, useState } from "react";
import {
	ChevronsDown,
	CircleHelp,
	Download,
	FileCog,
	KeyRound,
	Loader2,
	RotateCcw,
	Search,
	ShieldHalf,
	SlidersHorizontal,
	TriangleAlert,
	Upload,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import {
	Dialog,
	DialogContent,
	DialogDescription,
	DialogHeader,
	DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
	Select,
	SelectContent,
	SelectItem,
	SelectTrigger,
	SelectValue,
} from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import type { PrivateKeyConfig } from "@/components/pgp/contracts";
import { applyConfigBackup, buildConfigBackup, parseConfigBackup } from "@/lib/pgp/config-backup";
import { STORAGE_KEYS } from "@/lib/constants";
import {
	AUTOLOCK_OPTIONS,
	COMPRESSION_OPTIONS,
	EDITOR_OPTIONS,
	type AppSettings,
	type AutoLockMinutes,
	type CompressionLevel,
	type MarkdownEditorKind,
} from "@/lib/pgp/settings";
import { downloadBlob } from "@/lib/pgp/zip-bundle";
import { toast } from "@/hooks/use-toast";

const SECTIONS = [
	{ id: "composer", label: "Composer", icon: FileCog },
	{ id: "encryption", label: "Encryption", icon: ShieldHalf },
	{ id: "security", label: "Security", icon: KeyRound },
	{ id: "data", label: "Data", icon: Download },
	{ id: "help", label: "Help", icon: CircleHelp },
] as const;

type SectionId = (typeof SECTIONS)[number]["id"];

/* ------------------------------- setting rows ------------------------------ */

interface RowProps {
	title: string;
	description?: string;
	children: React.ReactNode;
}

function SettingRow({ title, description, children }: RowProps) {
	return (
		<div className="flex flex-col gap-2 py-3 sm:flex-row sm:items-center sm:justify-between sm:gap-6">
			<div className="min-w-0">
				<p className="text-sm font-medium">{title}</p>
				{description && (
					<p className="mt-0.5 max-w-md text-xs leading-relaxed text-muted-foreground">
						{description}
					</p>
				)}
			</div>
			<div className="shrink-0">{children}</div>
		</div>
	);
}

/* ------------------------------ backup section ----------------------------- */

function BackupRestoreSection({ privateKey }: { privateKey: PrivateKeyConfig | null }) {
	const [importBusy, setImportBusy] = useState(false);
	const fileInputRef = useRef<HTMLInputElement>(null);
	// Two-step confirm for "Restore defaults": the first click arms the
	// confirm state; a second click within a 4s window completes it.
	const [confirmReset, setConfirmReset] = useState(false);
	const resetTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

	const handleExportBackup = () => {
		try {
			const json = buildConfigBackup();
			const now = new Date();
			const yyyy = now.getFullYear();
			const mm = String(now.getMonth() + 1).padStart(2, "0");
			const dd = String(now.getDate()).padStart(2, "0");
			downloadBlob(
				new Blob([json], { type: "application/json" }),
				`encryptor-backup-${yyyy}-${mm}-${dd}.json`,
			);
			toast({ title: "Backup downloaded" });
		} catch (e) {
			toast({
				title: "Backup failed",
				description: (e as Error)?.message || "Backup unavailable",
				variant: "destructive",
			});
		}
	};

	const handleImportFile = async (event: React.ChangeEvent<HTMLInputElement>) => {
		const input = event.target;
		const file = input.files?.[0] ?? null;
		if (!file) {
			input.value = "";
			return;
		}
		setImportBusy(true);
		try {
			const text = await file.text();
			const parsed = parseConfigBackup(text);
			if (!parsed.ok) {
				toast({
					title: "Import failed",
					description: parsed.error,
					variant: "destructive",
				});
				return;
			}
			const applied = applyConfigBackup(parsed.data);
			toast({
				title: "Settings imported",
				description: `${applied} setting${applied === 1 ? "" : "s"} restored.`,
			});
			// Give the success toast a beat to paint, then reload so PgpApp
			// re-reads localStorage (config, include-self, recents, last tab).
			setTimeout(() => window.location.reload(), 700);
		} catch (e) {
			toast({
				title: "Import failed",
				description: (e as Error)?.message || "Import unavailable",
				variant: "destructive",
			});
		} finally {
			setImportBusy(false);
			input.value = ""; // allow re-picking the same file
		}
	};

	/** Two-step destructive reset: clear ONLY the known STORAGE_KEYS, toast,
	 *  then reload after ~700ms exactly like the import flow. */
	const handleRestoreDefaults = () => {
		if (!confirmReset) {
			setConfirmReset(true);
			if (resetTimerRef.current) clearTimeout(resetTimerRef.current);
			resetTimerRef.current = setTimeout(() => setConfirmReset(false), 4000);
			return;
		}
		if (resetTimerRef.current) clearTimeout(resetTimerRef.current);
		setConfirmReset(false);
		try {
			for (const key of Object.values(STORAGE_KEYS)) {
				try {
					localStorage.removeItem(key);
				} catch {
					// ignore individual removal failures
				}
			}
			toast({ title: "Settings restored to defaults" });
			setTimeout(() => window.location.reload(), 700);
		} catch (e) {
			toast({
				title: "Reset failed",
				description: (e as Error)?.message || "Reset unavailable",
				variant: "destructive",
			});
		}
	};

	return (
		<div className="space-y-3 py-3">
			<div>
				<p className="text-sm font-medium">Backup &amp; restore</p>
				<p className="mt-0.5 max-w-md text-xs leading-relaxed text-muted-foreground">
					Download all Encryptor settings — recipients, your key, and preferences — as a JSON file.
					Importing replaces the current settings.
				</p>
			</div>
			{privateKey?.encryptedArmored && (
				<p className="flex items-start gap-1.5 text-xs text-amber-700 dark:text-amber-400">
					<TriangleAlert aria-hidden className="mt-0.5 size-3.5 shrink-0" />
					Backups include your passphrase-encrypted private key.
				</p>
			)}
			<div className="flex flex-wrap gap-2">
				<Button
					type="button"
					variant="outline"
					size="sm"
					onClick={handleExportBackup}
					className="h-11 gap-1.5 px-3 text-xs transition-colors sm:h-8"
					title="Download all settings as a JSON backup file"
					aria-label="Export backup"
				>
					<Download className="size-3.5" aria-hidden />
					Export backup
				</Button>
				<Button
					type="button"
					variant="outline"
					size="sm"
					onClick={() => fileInputRef.current?.click()}
					disabled={importBusy}
					className="h-11 gap-1.5 px-3 text-xs transition-colors sm:h-8"
					title="Restore settings from a JSON backup file"
					aria-label="Import backup"
				>
					<Upload className="size-3.5" aria-hidden />
					{importBusy ? "Importing…" : "Import backup"}
				</Button>
				<Button
					type="button"
					variant="outline"
					size="sm"
					onClick={handleRestoreDefaults}
					className={`h-11 gap-1.5 px-3 text-xs transition-colors sm:h-8 text-destructive hover:text-destructive ${
						confirmReset
							? "border-destructive/40 bg-destructive/10 hover:bg-destructive/15 dark:bg-destructive/10 dark:hover:bg-destructive/20"
							: ""
					}`}
					title="Clear all saved settings (recipients, key, preferences)"
				>
					<RotateCcw className="size-3.5" aria-hidden />
					{confirmReset ? "Click again to confirm" : "Restore defaults"}
				</Button>
				<input
					ref={fileInputRef}
					type="file"
					accept="application/json,.json"
					className="sr-only"
					tabIndex={-1}
					onChange={(e) => void handleImportFile(e)}
				/>
			</div>
		</div>
	);
}

/* ------------------------------- the dialog -------------------------------- */

export function SettingsDialog({
	open,
	onOpenChange,
	settings,
	onSettingsChange,
	privateKey,
	onEnableQuantumSeal,
	onReplayTour,
}: {
	open: boolean;
	onOpenChange: (open: boolean) => void;
	settings: AppSettings;
	onSettingsChange: (next: AppSettings) => void;
	privateKey: PrivateKeyConfig | null;
	/** One-click post-quantum setup (PgpApp owns the passphrase prompt +
	 *  generation). Resolves true when the key gained a quantum-seal pair.
	 *  Optional for stories/tests that render the dialog standalone. */
	onEnableQuantumSeal?: () => Promise<boolean>;
	/** Opens the guided tour over the app (closes this dialog first). */
	onReplayTour?: () => void;
}) {
	const [query, setQuery] = useState("");
	const scrollRef = useRef<HTMLDivElement>(null);

	// Search filter: a row is visible when the query is empty OR matches the
	// row's title/description/keywords (case-insensitive substring). Sections
	// with zero visible rows hide entirely; the chips reflect that too.
	const q = query.trim().toLowerCase();
	const visible = useMemo(() => {
		const hits = (text: string | undefined) => (text ? text.toLowerCase().includes(q) : false);
		return {
			composer: !q || hits("composer editor markdown notion vscode auto sign signature"),
			encryption: !q || hits("encryption compression zlib zip quantum sealed post pq ml-kem"),
			security: !q || hits("security passphrase auto lock cache session"),
			data: !q || hits("data backup restore import export reset defaults"),
			help: !q || hits("help tour onboarding walkthrough guided shortcuts"),
		} as Record<SectionId, boolean>;
	}, [q]);

	const jumpTo = (id: SectionId) => {
		const el = scrollRef.current?.querySelector<HTMLElement>(`[data-settings-section="${id}"]`);
		el?.scrollIntoView({ behavior: "smooth", block: "start" });
	};

	return (
		<Dialog open={open} onOpenChange={onOpenChange}>
			<DialogContent className="flex max-h-[85dvh] flex-col gap-0 overflow-hidden p-0 sm:max-w-xl">
				<DialogHeader className="border-b px-5 py-3.5">
					<DialogTitle className="flex items-center gap-2 text-base font-semibold">
						<SlidersHorizontal aria-hidden className="size-4 text-[#0055dc] dark:text-[#5e94ff]" />
						Settings
					</DialogTitle>
					<DialogDescription className="mt-1 text-xs">
						App preferences — key setup lives in the key dialog (top-right).
					</DialogDescription>
				</DialogHeader>

				{/* Search + section jump rail */}
				<div className="border-b px-5 py-3">
					<div className="relative">
						<Search
							aria-hidden="true"
							className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground"
						/>
						<Input
							type="search"
							value={query}
							onChange={(e) => setQuery(e.target.value)}
							placeholder="Search settings…"
							aria-label="Search settings"
							className="min-h-11 pl-9 sm:min-h-9"
						/>
					</div>
					<nav aria-label="Settings sections" className="mt-2.5 flex flex-wrap gap-1.5">
						{SECTIONS.map(({ id, label }) => {
							const hidden = !visible[id];
							return (
								<button
									key={id}
									type="button"
									onClick={() => jumpTo(id)}
									disabled={hidden}
									className={`rounded-full border px-2.5 py-1 text-[11px] font-medium transition-colors ${
										hidden
											? "cursor-not-allowed border-transparent text-muted-foreground/40"
											: "border-border bg-muted/40 text-muted-foreground hover:border-[#0055dc]/40 hover:text-[#0055dc] dark:hover:border-[#5e94ff]/40 dark:hover:text-[#5e94ff]"
									}`}
								>
									{label}
								</button>
							);
						})}
					</nav>
				</div>

				<div ref={scrollRef} className="min-h-0 flex-1 overflow-y-auto px-5 py-2">
					{visible.composer && (
						<section
							data-settings-section="composer"
							className="scroll-mt-4 border-b py-2 last:border-b-0"
						>
							<p className="py-1 text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">
								Composer
							</p>
							<SettingRow
								title="Message editor"
								description="Notion-style block editor, or a VS Code-style source editor with a live split preview."
							>
								<Select
									value={settings.markdownEditor}
									onValueChange={(v) =>
										onSettingsChange({
											...settings,
											markdownEditor: v as MarkdownEditorKind,
										})
									}
								>
									<SelectTrigger className="w-full sm:w-56" aria-label="Message editor">
										<SelectValue />
									</SelectTrigger>
									<SelectContent>
										{EDITOR_OPTIONS.map((o) => (
											<SelectItem key={o.value} value={o.value}>
												{o.label}
											</SelectItem>
										))}
									</SelectContent>
								</Select>
							</SettingRow>
							<SettingRow
								title="Auto sign messages"
								description="Sign every encrypted message with your key. Turn off to encrypt without signing — no passphrase needed."
							>
								<Switch
									checked={settings.autoSign}
									onCheckedChange={(v) => onSettingsChange({ ...settings, autoSign: v === true })}
									aria-label="Auto sign messages"
								/>
							</SettingRow>
						</section>
					)}

					{visible.encryption && (
						<section
							data-settings-section="encryption"
							className="scroll-mt-4 border-b py-2 last:border-b-0"
						>
							<p className="py-1 text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">
								Encryption
							</p>
							<SettingRow
								title="Message compression"
								description="Maximum packs messages tightest; recipients that don't advertise support fall back to uncompressed automatically."
							>
								<Select
									value={settings.compression}
									onValueChange={(v) =>
										onSettingsChange({
											...settings,
											compression: v as CompressionLevel,
										})
									}
								>
									<SelectTrigger className="w-full sm:w-56" aria-label="Message compression">
										<SelectValue />
									</SelectTrigger>
									<SelectContent>
										{COMPRESSION_OPTIONS.map((o) => (
											<SelectItem key={o.value} value={o.value}>
												{o.label}
											</SelectItem>
										))}
									</SelectContent>
								</Select>
							</SettingRow>
							<SettingRow
								title="Quantum-sealed copy"
								description="Also produce an ML-KEM-768 (post-quantum) sealed copy of every message you encrypt — harvest-now-decrypt-later protection for your archive."
							>
								<Switch
									checked={settings.pqSealedCopy}
									onCheckedChange={(v) =>
										onSettingsChange({ ...settings, pqSealedCopy: v === true })
									}
									aria-label="Quantum-sealed copy"
								/>
							</SettingRow>
							{settings.pqSealedCopy && !privateKey?.pq && (
								<QuantumSealInlineEnable onEnable={onEnableQuantumSeal} />
							)}
							{settings.pqSealedCopy && (
								<p className="pb-2 text-xs text-muted-foreground">
									{privateKey?.pq ? (
										<>
											<ChevronsDown
												aria-hidden
												className="mr-1 inline size-3.5 text-violet-600 dark:text-violet-400"
											/>
											Your key has a quantum-seal pair — sealed copies appear under the encrypted
											output.
										</>
									) : (
										<>
											<TriangleAlert
												aria-hidden
												className="mr-1 inline size-3.5 text-amber-600 dark:text-amber-400"
											/>
											Your current key has no quantum-seal pair yet — sealed copies stay off until
											you enable it above (keys created in-app already have it).
										</>
									)}
								</p>
							)}
						</section>
					)}

					{visible.security && (
						<section
							data-settings-section="security"
							className="scroll-mt-4 border-b py-2 last:border-b-0"
						>
							<p className="py-1 text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">
								Security
							</p>
							<SettingRow
								title="Passphrase auto-lock"
								description="How long the remembered passphrase stays in memory before it is dropped. Tick “Remember for this session” once on the passphrase prompt."
							>
								<Select
									value={String(settings.autoLockMinutes)}
									onValueChange={(v) =>
										onSettingsChange({
											...settings,
											autoLockMinutes: Number(v) as AutoLockMinutes,
										})
									}
								>
									<SelectTrigger className="w-full sm:w-56" aria-label="Passphrase auto-lock">
										<SelectValue />
									</SelectTrigger>
									<SelectContent>
										{AUTOLOCK_OPTIONS.map((o) => (
											<SelectItem key={o.value} value={String(o.value)}>
												{o.label}
											</SelectItem>
										))}
									</SelectContent>
								</Select>
							</SettingRow>
						</section>
					)}

					{visible.data && (
						<section
							data-settings-section="data"
							className="scroll-mt-4 border-b py-2 last:border-b-0"
						>
							<p className="py-1 text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">
								Data
							</p>
							<BackupRestoreSection privateKey={privateKey} />
						</section>
					)}

					{visible.help && (
						<section
							data-settings-section="help"
							className="scroll-mt-4 border-b py-2 last:border-b-0"
						>
							<p className="py-1 text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">
								Help
							</p>
							<SettingRow
								title="Guided tour"
								description="A short walkthrough of the app's main areas, shown once after key setup."
							>
								<Button
									variant="outline"
									size="sm"
									onClick={onReplayTour}
									disabled={!onReplayTour}
									data-testid="replay-guided-tour"
									className="h-11 gap-1.5 px-3 text-xs sm:h-8"
								>
									<CircleHelp aria-hidden className="size-3.5" />
									Replay tour
								</Button>
							</SettingRow>
						</section>
					)}

					{/* Everything filtered out: say so instead of a blank pane. */}
					{!visible.composer &&
						!visible.encryption &&
						!visible.security &&
						!visible.data &&
						!visible.help && (
							<div className="py-10 text-center">
								<p className="text-sm font-medium">No matching setting</p>
								<p className="mt-1 text-xs text-muted-foreground">
									Try “editor”, “compression”, “lock”, or “backup”.
								</p>
							</div>
						)}
				</div>

				<div className="border-t px-5 py-3">
					<Label className="sr-only">Settings dialog footer</Label>
					<p className="text-[11px] text-muted-foreground">
						Changes apply immediately and are saved in this browser only.
					</p>
				</div>
			</DialogContent>
		</Dialog>
	);
}

/* --------------------- quantum-seal inline enable (new) -------------------- */

/** One-click post-quantum setup inside Settings: shown when sealed copies are
 *  on but the active key has no ML-KEM-768 pair. Replaces the old dead-end
 *  hint ("generate one in the key dialog") — the passphrase prompt + pair
 *  generation + pqSealedCopy handling all live in PgpApp. */
function QuantumSealInlineEnable({ onEnable }: { onEnable?: () => Promise<boolean> }) {
	const [busy, setBusy] = useState(false);
	if (!onEnable) return null;
	return (
		<div className="pb-2">
			<Button
				type="button"
				variant="outline"
				size="sm"
				disabled={busy}
				onClick={() => {
					setBusy(true);
					void onEnable().finally(() => setBusy(false));
				}}
				className="h-11 gap-1.5 border-violet-300/70 px-3 text-xs text-violet-800 transition-colors hover:bg-violet-50 hover:text-violet-900 sm:h-8 dark:border-violet-900/60 dark:text-violet-300 dark:hover:bg-violet-950/40 dark:hover:text-violet-200"
				title="Generate an ML-KEM-768 key pair for this key (asks for your passphrase once)"
			>
				{busy ? (
					<>
						<Loader2 aria-hidden className="size-3.5 animate-spin motion-reduce:animate-none" />
						Generating…
					</>
				) : (
					<>
						<ShieldHalf aria-hidden className="size-3.5" />
						Enable quantum seal for this key
					</>
				)}
			</Button>
		</div>
	);
}
