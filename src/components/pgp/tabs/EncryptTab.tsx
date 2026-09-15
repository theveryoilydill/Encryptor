"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
	Blocks,
	BookmarkPlus,
	ChevronDown,
	FileDown,
	FileUp,
	History,
	LayoutTemplate,
	Loader2,
	Lock,
	ShieldCheck,
	SquareCode,
	Sparkles,
	Trash2,
	TriangleAlert,
	X,
} from "lucide-react";

import { Button } from "@/components/ui/button";
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible";
import { RecipientPicker } from "@/components/pgp/RecipientPicker";
import {
	AttachmentList,
	CopyButton,
	DownloadButton,
	ErrorBanner,
	InputSizeCounter,
	OutputBlock,
} from "@/components/pgp/shared";
import { MessageEditor } from "@/components/pgp/MessageEditor";
import type { PrivateKeyConfig, Recipient } from "@/components/pgp/contracts";
import {
	DropdownMenu,
	DropdownMenuContent,
	DropdownMenuItem,
	DropdownMenuLabel,
	DropdownMenuSeparator,
	DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import {
	Dialog,
	DialogContent,
	DialogDescription,
	DialogFooter,
	DialogHeader,
	DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { useToast } from "@/hooks/use-toast";
import {
	deleteUserTemplate,
	downloadFileName,
	exportTemplates,
	importTemplates,
	loadUserTemplates,
	MAX_TEMPLATE_BODY_CHARS,
	saveUserTemplate,
	type UserTemplate,
} from "@/lib/pgp/user-templates";
import { clearComposerDraft, loadComposerDraft, saveComposerDraft } from "@/lib/pgp/composer-draft";
import {
	appendSealedOutput,
	clearSealedHistory,
	loadSealedHistory,
	removeSealedEntry,
	MAX_SEALED_ENTRIES,
	type SealedHistoryEntry,
} from "@/lib/pgp/sealed-history";
import { encryptAndSign, encryptMessage } from "@/lib/pgp/pgp";
import { sealForConfig } from "@/lib/pgp/pq";
import {
	buildPlaintextForEncryption,
	formatFileSize,
	readFileAsBase64,
	type EnvelopeFile,
} from "@/lib/pgp/envelope";
import { LIMITS } from "@/lib/constants";
import type { AppSettings, MarkdownEditorKind } from "@/lib/pgp/settings";
import { InputHint, detectPgpBlock } from "@/components/pgp/InputHint";
import { getKeyExpiryStatus, parseLooseDate } from "@/lib/pgp/key-details";

/** Curated starter templates for the composer. Insert-only (they seed an
 *  empty message or append after the current text); placeholders are meant
 *  to be filled in. Deliberately generic — the composer is a markdown
 *  editor, so emphasis/headers serialize losslessly into the envelope. */
const COMPOSER_TEMPLATES: { name: string; description: string; body: string }[] = [
	{
		name: "Credentials handoff",
		description: "Share access details — one secret per message",
		body: [
			"**Service / site:** ",
			"**Account ID or username:** ",
			"**Secret to hand off:** ",
			"**Rotate after:** ",
			"",
			"_Once this message is confirmed received, delete the secret from wherever it was first written — this copy should be the only one left._",
		].join("\n"),
	},
	{
		name: "Meeting details",
		description: "Time, place, and agenda",
		body: [
			"**When:** ",
			"**Where / link:** ",
			"",
			"**Agenda**",
			"1. ",
			"2. ",
			"",
			"_Please reply encrypted if you include anything confidential._",
		].join("\n"),
	},
	{
		name: "Sensitive document note",
		description: "Wrap a private body with handling instructions",
		body: [
			"The attached material is confidential.",
			"",
			"---",
			"",
			"(body)",
			"",
			"---",
			"",
			"_Handling: decrypt, read, and delete this copy. Do not forward — share a fresh encrypted copy instead._",
		].join("\n"),
	},
];

/** Small right-aligned utility above the composer: the template menu works
 *  for BOTH editor styles (Notion blocks + VS Code textarea) because it
 *  rides the same setPlaintext path as typing. Two sections: the user's
 *  own saved templates (localStorage, deletable) and the curated starters. */
function TemplateMenu({
	onInsert,
	currentMessage,
}: {
	onInsert: (body: string) => void;
	currentMessage: string;
}) {
	const [templates, setTemplates] = useState<UserTemplate[]>([]);
	const [saveOpen, setSaveOpen] = useState(false);
	const [name, setName] = useState("");
	const [saveError, setSaveError] = useState<string | null>(null);

	// Load once on mount; save/delete refresh the local state directly.
	useEffect(() => {
		setTemplates(loadUserTemplates());
	}, []);

	const canSave = currentMessage.trim().length > 0;

	const openSaveDialog = () => {
		// Prefill with the first words of the message — a name, not the body.
		const firstWords = currentMessage.trim().replace(/\s+/g, " ").slice(0, 32);
		setName(firstWords.length > 0 ? firstWords : "");
		setSaveError(null);
		setSaveOpen(true);
	};

	const handleSave = () => {
		const result = saveUserTemplate(name, currentMessage.slice(0, MAX_TEMPLATE_BODY_CHARS));
		if (!result.ok) {
			setSaveError(result.error);
			return;
		}
		setTemplates(result.templates);
		setSaveOpen(false);
	};

	const handleDelete = (id: string) => {
		setTemplates(deleteUserTemplate(id));
	};

	// Backup: export downloads a versioned JSON file; import merges a picked
	// file (deduped by name+body — re-importing the same file is a no-op).
	const { toast } = useToast();
	const importInputRef = useRef<HTMLInputElement>(null);

	const handleExport = () => {
		const blob = new Blob([exportTemplates()], { type: "application/json" });
		const url = URL.createObjectURL(blob);
		const a = document.createElement("a");
		a.href = url;
		a.download = downloadFileName();
		a.click();
		URL.revokeObjectURL(url);
		toast({
			title: `Exported ${templates.length} template${templates.length === 1 ? "" : "s"}`,
			description: "Saved as a .json file you can re-import on any device.",
		});
	};

	const handleImportFile = async (file: File) => {
		try {
			const result = importTemplates(await file.text());
			if (!result.ok) {
				toast({ title: "Import failed", description: result.error, variant: "destructive" });
				return;
			}
			setTemplates(result.templates);
			toast({
				title: `Imported ${result.added} template${result.added === 1 ? "" : "s"}`,
				description:
					result.skipped > 0
						? `${result.skipped} duplicate${result.skipped === 1 ? "" : "s"} or invalid skipped.`
						: undefined,
			});
		} catch {
			toast({
				title: "Import failed",
				description: "Couldn't read that file.",
				variant: "destructive",
			});
		}
	};

	return (
		<DropdownMenu>
			<DropdownMenuTrigger asChild>
				<Button
					type="button"
					variant="ghost"
					size="sm"
					className="h-7 gap-1.5 rounded-lg px-2 text-[11px] text-muted-foreground transition-colors hover:text-foreground focus-visible:ring-2 focus-visible:ring-[#0055dc]/40 dark:focus-visible:ring-[#5e94ff]/40"
				>
					<LayoutTemplate aria-hidden="true" className="size-3.5" />
					Insert template
				</Button>
			</DropdownMenuTrigger>
			<DropdownMenuContent
				align="end"
				// Cap at the viewport so the Backup row is always reachable — the
				// long "your templates + starters + backup" list scrolls instead of
				// clipping below the fold (repo-wide thin scrollbar applies).
				className="max-h-[min(26rem,var(--radix-dropdown-menu-content-available-height))] w-72 overflow-y-auto"
			>
				<DropdownMenuLabel className="flex items-center gap-1.5 text-[11px] font-normal text-muted-foreground">
					<BookmarkPlus aria-hidden="true" className="size-3" />
					Your templates
				</DropdownMenuLabel>
				{templates.length === 0 && (
					<p className="px-2 pb-1 text-[11px] leading-relaxed text-muted-foreground">
						Nothing saved yet — use "Save current message" to keep any message as a reusable
						template (stored in this browser).
					</p>
				)}
				{templates.map((t) => (
					<DropdownMenuItem
						key={t.id}
						onSelect={(e) => {
							// Clicks on the delete button bubble here (Radix fires
							// onSelect for any child click) — keep the menu open and
							// skip the insert when the trash icon was the target.
							if ((e.target as HTMLElement).closest("button[data-template-delete]")) {
								e.preventDefault();
								return;
							}
							onInsert(t.body);
						}}
						className="group flex items-start gap-1 py-2"
					>
						<span className="flex min-w-0 flex-1 flex-col gap-0.5">
							<span className="truncate text-xs font-medium">{t.name}</span>
							<span className="truncate text-[11px] text-muted-foreground">
								{t.body.replace(/\s+/g, " ").slice(0, 48)}
							</span>
						</span>
						<button
							type="button"
							data-template-delete
							aria-label={`Delete template ${t.name}`}
							title="Delete template"
							onClick={(e) => {
								e.stopPropagation();
								e.preventDefault();
								handleDelete(t.id);
							}}
							className="flex size-6 shrink-0 items-center justify-center rounded text-muted-foreground opacity-0 transition-opacity hover:bg-black/5 hover:text-red-600 focus-visible:opacity-100 focus-visible:ring-2 focus-visible:ring-red-500/40 group-hover:opacity-100 dark:hover:bg-white/10 dark:hover:text-red-400"
						>
							<Trash2 aria-hidden="true" className="size-3.5" />
						</button>
					</DropdownMenuItem>
				))}
				<DropdownMenuItem
					onSelect={openSaveDialog}
					disabled={!canSave}
					className="gap-1.5 py-2 text-xs font-medium text-[#0055dc] focus:text-[#0055dc] dark:text-[#5e94ff] dark:focus:text-[#5e94ff]"
				>
					<Sparkles aria-hidden="true" className="size-3.5" />
					Save current message as template…
				</DropdownMenuItem>
				<DropdownMenuSeparator />
				<DropdownMenuLabel className="text-[11px] font-normal text-muted-foreground">
					Starter templates
				</DropdownMenuLabel>
				{COMPOSER_TEMPLATES.map((t) => (
					<DropdownMenuItem
						key={t.name}
						onClick={() => onInsert(t.body)}
						className="flex-col items-start gap-0.5 py-2"
					>
						<span className="text-xs font-medium">{t.name}</span>
						<span className="text-[11px] text-muted-foreground">{t.description}</span>
					</DropdownMenuItem>
				))}
				<DropdownMenuSeparator />
				<DropdownMenuLabel className="text-[11px] font-normal text-muted-foreground">
					Backup
				</DropdownMenuLabel>
				{/* Export always works (even with zero templates — an empty backup is
				     still a valid file); import feeds the merge + toast flow. */}
				<DropdownMenuItem onSelect={handleExport} className="gap-1.5 py-2 text-xs">
					<FileDown aria-hidden="true" className="size-3.5" />
					Export templates
				</DropdownMenuItem>
				<DropdownMenuItem
					onSelect={() => {
						// Radix closes the menu on select; open the picker after that,
						// otherwise the focus restore can swallow the file dialog.
						setTimeout(() => importInputRef.current?.click(), 0);
					}}
					className="gap-1.5 py-2 text-xs"
				>
					<FileUp aria-hidden="true" className="size-3.5" />
					Import templates…
				</DropdownMenuItem>
			</DropdownMenuContent>

			{/* Backup file input lives OUTSIDE the DropdownMenuContent: Radix
			    unmounts the content on close, which would null the ref before the
			    deferred picker click could fire. */}
			<input
				ref={importInputRef}
				type="file"
				accept="application/json,.json"
				aria-hidden="true"
				tabIndex={-1}
				className="hidden"
				onChange={(e) => {
					const f = e.target.files?.[0];
					if (f) void handleImportFile(f);
					e.target.value = ""; // re-arm: picking the same file twice must fire
				}}
			/>
			{/* Name prompt for "Save current message as template". Plain
			    Dialog (not an inline menu editor) so mobile keyboards, focus
			    trapping, and Escape handling all behave. */}
			<Dialog open={saveOpen} onOpenChange={setSaveOpen}>
				<DialogContent className="sm:max-w-sm">
					<DialogHeader>
						<DialogTitle>Save template</DialogTitle>
						<DialogDescription>
							Stored in this browser only. Insert it anytime from this menu.
						</DialogDescription>
					</DialogHeader>
					<Input
						value={name}
						onChange={(e) => setName(e.target.value)}
						placeholder="Template name"
						aria-label="Template name"
						maxLength={60}
						onKeyDown={(e) => {
							if (e.key === "Enter") {
								e.preventDefault();
								handleSave();
							}
						}}
					/>
					{saveError && (
						<p role="alert" className="text-xs text-red-600 dark:text-red-400">
							{saveError}
						</p>
					)}
					<DialogFooter>
						<Button type="button" variant="outline" onClick={() => setSaveOpen(false)}>
							Cancel
						</Button>
						<Button type="button" onClick={handleSave}>
							Save template
						</Button>
					</DialogFooter>
				</DialogContent>
			</Dialog>
		</DropdownMenu>
	);
}

export function EncryptTab({
	privateKey,
	recipients,
	setRecipients,
	includeSelf,
	onIncludeSelfChange,
	requestDecryptedKey,
	settings,
	onEditorKindChange,
}: {
	privateKey: PrivateKeyConfig | null;
	recipients: Recipient[];
	setRecipients: (updater: (prev: Recipient[]) => Recipient[]) => void;
	includeSelf: boolean;
	onIncludeSelfChange: (v: boolean) => void;
	requestDecryptedKey: () => Promise<{ key: OpenPGP.PrivateKey; passphrase: string | null }>;
	/** App preferences (compression + editor style) — owned by PgpApp so a
	 *  settings change re-renders the open tab immediately. */
	settings: AppSettings;
	/** Live editor-style switch (round 12): the segmented control above the
	 *  composer writes through to PgpApp's settings owner, so the choice
	 *  persists and stays in sync with the Settings dialog. */
	onEditorKindChange: (kind: MarkdownEditorKind) => void;
}) {
	const { toast } = useToast();
	const [plaintext, setPlaintext] = useState("");
	const [attachments, setAttachments] = useState<EnvelopeFile[]>([]);
	// Mirror of the attachment list for SYNCHRONOUS readers — the editor's
	// image-paste bridge must return the FINAL (deduped) filename in the same
	// tick it registers the file, but React state updates are async and the
	// updater function must stay pure. The ref is updated eagerly on every
	// mutation path and re-synced to the committed state after each render.
	const attachmentsRef = useRef<EnvelopeFile[]>(attachments);
	useEffect(() => {
		attachmentsRef.current = attachments;
	}, [attachments]);
	const [output, setOutput] = useState("");
	// Quantum-sealed copy of the LAST output (settings.pqSealedCopy + a key
	// with a quantum-seal pair): an ML-KEM-768 outer layer only the owner
	// can open. Empty string = no sealed copy for the current output.
	const [sealedCopy, setSealedCopy] = useState("");
	const [busy, setBusy] = useState(false);
	const [error, setError] = useState<string | null>(null);
	// Drag & drop depth counter (avoids flicker when crossing child elements).
	const [dragDepth, setDragDepth] = useState(0);
	// Smart-input hint dismissal, keyed to the exact message content: clearing
	// the textarea (or typing different content) re-arms the hint without
	// needing a state-reset effect.
	const [hintDismissedFor, setHintDismissedFor] = useState<string | null>(null);
	// Draft rescue banner (the sessionStorage mirror itself lives in
	// lib/pgp/composer-draft — session-only, dies with the tab).
	const [draftNotice, setDraftNotice] = useState(false);
	// Success summary for the LAST output (recipient count + signed),
	// rendered as a compact strip above the output block.
	const [outputMeta, setOutputMeta] = useState<{
		keys: number;
		signed: boolean;
		labels: string[];
	} | null>(null);
	// Recent sealed outputs — a ciphertext-only local history (lib/pgp/
	// sealed-history): the armored result of each encrypt is kept so an
	// earlier sealed message can be restored after the output block is
	// reset or replaced by a newer one. Collapsed by default.
	const [sealedHistory, setSealedHistory] = useState<SealedHistoryEntry[]>([]);
	const [historyOpen, setHistoryOpen] = useState(false);
	useEffect(() => {
		setSealedHistory(loadSealedHistory());
	}, []);

	// Expiry pre-flight (R8): recipients whose key has an expired PRIMARY key.
	// Same detection the recipient chips' "Expired" badge uses
	// (getKeyExpiryStatus), so the banner and the badge can never disagree.
	// Deliberately NON-blocking: openpgp.js can still succeed when only the
	// primary is expired but a subkey remains valid — the banner warns, the
	// catch below maps the genuine failures to friendly guidance.
	const expiredRecipients = useMemo(
		() =>
			recipients.filter(
				(r) =>
					typeof r.expiresAt === "number" &&
					getKeyExpiryStatus(new Date(r.expiresAt))?.status === "expired",
			),
		[recipients],
	);

	// Derive the user's own public key from the configured private key.
	// Shown as a recipient chip when "Include me" is checked.
	const selfRecipient = useMemo<Recipient | null>(() => {
		if (!privateKey) return null;
		const info = privateKey.info;
		return {
			source: "local",
			label:
				privateKey.source === "keybase"
					? `@${privateKey.username} (you)`
					: `${privateKey.label} (you)`,
			armored: "", // not needed — we'll inject it directly in handleEncrypt
			fingerprint: info.fingerprint,
			keyID: info.keyID,
			algorithm: info.algorithm,
			expiresAt:
				// parseLooseDate (key-details.ts): the persisted config's
				// expirationTime is a Date right after configure but an ISO STRING
				// after a localStorage reload round-trip — calling .getTime()
				// directly on the string crashed the whole tab on load (R11 fix).
				// It also rejects non-Date/number garbage; a fresh Infinity (never
				// expiring) isn't a string/Date → null, matching the never-expires
				// posture of every other expiresAt consumer.
				parseLooseDate(info.expirationTime)?.getTime() ?? null,
		};
	}, [privateKey]);

	/** Read + store files, returning the stored entries (with unique names).
	 *  Shared by the add-files button/drop and the editor's image paste. */
	const addFilesReturning = useCallback(
		async (fileList: FileList | File[]): Promise<EnvelopeFile[]> => {
			const files = Array.from(fileList);
			const newOnes: EnvelopeFile[] = [];
			let sizeError: string | null = null;
			for (const f of files) {
				if (f.size > LIMITS.maxFileBytes) {
					sizeError = `"${f.name}" is ${formatFileSize(f.size)} — max ${LIMITS.maxFileLabel} per file.`;
					continue;
				}
				try {
					const data = await readFileAsBase64(f);
					newOnes.push({
						name: f.name || "unnamed",
						type: f.type || "application/octet-stream",
						data,
						size: f.size,
					});
				} catch (e) {
					sizeError = `Failed to read "${f.name}": ${(e as Error).message}`;
				}
			}
			if (newOnes.length > 0) {
				setAttachments((prev) => {
					// Deduplicate names so inline image markers always reference the
					// right attachment (same rule the old paste path used).
					const usedNames = new Set(prev.map((a) => a.name));
					for (const n of newOnes) {
						if (!usedNames.has(n.name)) {
							usedNames.add(n.name);
							continue;
						}
						const dot = n.name.lastIndexOf(".");
						let counter = 1;
						let unique = n.name;
						while (usedNames.has(unique)) {
							unique =
								dot > 0
									? `${n.name.slice(0, dot)}-${counter}${n.name.slice(dot)}`
									: `${n.name}-${counter}`;
							counter++;
						}
						usedNames.add(unique);
						n.name = unique;
					}
					return [...prev, ...newOnes];
				});
			}
			if (sizeError) setError(sizeError);
			return newOnes;
		},
		[],
	);

	const addFiles = useCallback(
		async (fileList: FileList | File[]) => {
			setError(null);
			if (Array.from(fileList).length === 0) return;
			await addFilesReturning(fileList);
		},
		[addFilesReturning],
	);

	/** Editor paste bridge: store a pasted image (as a data URL) as an
	 *  attachment and return the stored entry so the editor can reference it
	 *  with an envelope:// marker. Sync by contract — throws on read errors.
	 *
	 *  BUGFIX (was "VS Code is super broken"): this used to return the
	 *  PRE-dedupe name while the state updater stored the DEDUPED one, so
	 *  the second pasted image's marker pointed at the FIRST image's file —
	 *  recipients silently saw the wrong image (browser-verified). The
	 *  unique name is now computed against attachmentsRef BEFORE the state
	 *  update and the FINAL entry is returned. */
	const handleNewImageDataUrl = useCallback((dataUrl: string): EnvelopeFile => {
		// Parse "data:<mime>;base64,<data>".
		const match = /^data:([^;,]+);base64,([\s\S]*)$/.exec(dataUrl);
		if (!match) throw new Error("Unsupported image data URL.");
		const type = match[1];
		const data = match[2];
		const size = Math.floor(data.length * 0.75);
		if (size > LIMITS.maxFileBytes) {
			throw new Error(`Image is ${formatFileSize(size)} — max ${LIMITS.maxFileLabel}.`);
		}
		const ext = type.split("/")[1]?.replace("jpeg", "jpg") || "png";
		const baseName = `pasted-image.${ext}`;
		// Dedupe against the mirrored list (sync, no stale closure).
		const usedNames = new Set(attachmentsRef.current.map((a) => a.name));
		const dot = baseName.lastIndexOf(".");
		let unique = baseName;
		let counter = 1;
		while (usedNames.has(unique)) {
			unique =
				dot > 0
					? `${baseName.slice(0, dot)}-${counter}${baseName.slice(dot)}`
					: `${baseName}-${counter}`;
			counter++;
		}
		const stored: EnvelopeFile = { name: unique, type, data, size };
		// Eager mirror update so a same-tick follow-up paste sees this name.
		attachmentsRef.current = [...attachmentsRef.current, stored];
		// Guarded commit (idempotent under StrictMode double-invoke).
		setAttachments((prev) => (prev.some((a) => a.name === stored.name) ? prev : [...prev, stored]));
		return stored;
	}, []);

	// Orphan garbage collection (was "VS Code is super broken", part 2):
	// deleting an image out of the message used to leave its file attached —
	// it still got encrypted into the envelope (bloat + surprise files for
	// recipients, verified in the browser). Whenever the message text no
	// longer references an auto-named PASTED image, drop it. Files added via
	// "Add files" keep their original names and are NEVER touched here.
	useEffect(() => {
		const referenced = new Set<string>();
		const re = /!\[[^\]]*\]\(envelope:\/\/([^)\s]+)\)/g;
		for (const m of plaintext.matchAll(re)) {
			try {
				referenced.add(decodeURIComponent(m[1]));
			} catch {
				referenced.add(m[1]);
			}
		}
		setAttachments((prev) => {
			const kept = prev.filter(
				(a) => !/^pasted-image(-\d+)?\.[a-z0-9]+$/.test(a.name) || referenced.has(a.name),
			);
			return kept.length === prev.length ? prev : kept;
		});
	}, [plaintext]);

	// Draft rescue: load ONCE on mount (an accidental reload mid-composition
	// restores the message instead of losing it), then keep the mirror fresh
	// with a short debounce. Armor-ish content is never mirrored — the rescue
	// path is for composed messages only (see composer-draft.ts for the
	// session-only privacy posture).
	useEffect(() => {
		const draft = loadComposerDraft();
		if (draft && draft.trim()) {
			setPlaintext(draft);
			setDraftNotice(true);
		}
	}, []);
	useEffect(() => {
		if (!plaintext.trim() || detectPgpBlock(plaintext) !== null) {
			clearComposerDraft();
			return;
		}
		const t = setTimeout(() => saveComposerDraft(plaintext), 600);
		return () => clearTimeout(t);
	}, [plaintext]);

	const handleAddFiles = useCallback(
		(files: FileList | null) => {
			if (files) void addFiles(files);
		},
		[addFiles],
	);

	// Insert a starter template: seed an empty composer or append after the
	// current text. Rides the same setPlaintext path as typing, so it works
	// for both editor styles and the draft mirror stays consistent.
	const insertTemplate = useCallback((body: string) => {
		setPlaintext((prev) => {
			const trimmed = prev.trimEnd();
			return trimmed ? `${trimmed}\n\n${body}` : body;
		});
	}, []);

	const handleEncrypt = useCallback(async () => {
		setError(null);
		setOutput("");
		setSealedCopy("");
		setOutputMeta(null);
		if (!plaintext.trim() && attachments.length === 0) {
			setError("Enter a message to encrypt, or attach a file.");
			return;
		}
		const signing = settings.autoSign;
		const needsOwnKey = signing || includeSelf;
		if (needsOwnKey && !privateKey) {
			setError(
				signing
					? "Auto sign is on — configure your private key (top-right button) or turn signing off in Settings to encrypt without signing."
					: '"Include me" needs your configured key — configure it (top-right button) or untick "Include me".',
			);
			return;
		}
		// Recipient validation BEFORE the passphrase prompt (R10): openpgp would
		// surface this as a raw "no encryption keys" error mid-flight — catch it
		// early with actionable guidance instead.
		if (recipients.length === 0 && !(includeSelf && privateKey)) {
			setError(
				'No recipients — add at least one public key, or tick "Include me" so you can still decrypt what you send.',
			);
			return;
		}

		setBusy(true);
		try {
			// Request the decrypted key only when a signature or the self-copy
			// actually needs it (auto sign off + no include-me ⇒ no passphrase
			// prompt at all). The decrypted key exists only in this local
			// variable and is cleared when the function returns.
			let decryptedKey: OpenPGP.PrivateKey | null = null;
			if (needsOwnKey) {
				decryptedKey = (await requestDecryptedKey()).key;
			}

			// Build the recipient key list. If "include me" is checked, derive
			// the public key from the decrypted private key.
			const recipientKeys: string[] = recipients.map((r) => r.armored);
			if (includeSelf && decryptedKey) {
				try {
					const pubArmored = decryptedKey.toPublic().armor();
					recipientKeys.push(pubArmored);
				} catch {
					// skip self-inclusion on error
				}
			}

			// Wrap plaintext + attachments in the envelope wire format.
			const plaintextForEncryption = buildPlaintextForEncryption(plaintext, attachments);
			const compression = settings.compression === "off" ? "uncompressed" : settings.compression;

			let armored: string;
			if (signing && decryptedKey) {
				// Pass the PrivateKey object directly to avoid re-armoring +
				// re-parsing, which can lose key material for Keybase P3SKB keys.
				armored = await encryptAndSign({
					plaintext: plaintextForEncryption,
					recipientPublicKeys: recipientKeys,
					signerPrivateKey: decryptedKey,
					// User preference: compress by default, at maximum supported
					// compression; "off" maps to the explicit uncompressed preference.
					compression,
				});
			} else {
				armored = await encryptMessage({
					plaintext: plaintextForEncryption,
					recipientPublicKeys: recipientKeys,
					compression,
				});
			}

			// Quantum-sealed copy (opt-in): an ML-KEM-768 outer layer over the
			// armored output, sealed to the configured key's quantum-seal
			// public half. Needs no secret — sealing is passphrase-free.
			let pqCopy: string | null = null;
			if (settings.pqSealedCopy && privateKey?.pq) {
				try {
					pqCopy = await sealForConfig(armored, privateKey.pq, privateKey.info.fingerprint);
					setSealedCopy(pqCopy);
				} catch {
					// The classical output stays usable even if the PQ layer fails.
				}
			}
			setOutput(armored);
			// Display-only recipient labels for the "Sealed to: …" tooltip —
			// capped like every other display list so a 50-recipient paste can't
			// blow up the strip.
			const recipientLabels = [
				...recipients.map((r) => r.label),
				...(includeSelf && decryptedKey ? [`${privateKey?.label ?? "me"} (you)`] : []),
			]
				.slice(0, 8)
				.map((l) => l.trim().slice(0, 48));
			setOutputMeta({ keys: recipientKeys.length, signed: signing, labels: recipientLabels });
			// Ciphertext-only local history: record the sealed output (and its
			// PQ copy, when produced) BEFORE the plaintext is wiped — the entry
			// holds nothing but the armor the user is about to see anyway.
			const recorded = appendSealedOutput({
				armor: armored,
				sealedArmor: pqCopy,
				keys: recipientKeys.length,
				signed: signing,
				pqSealed: pqCopy !== null,
				labels: recipientLabels,
			});
			setSealedHistory(recorded.entries);
			setHistoryOpen(true);

			// The user can always decrypt their own copy (Include me) — so the
			// plaintext is deleted from the composer as soon as the ciphertext
			// exists. Only the output remains in memory.
			setPlaintext("");
			setAttachments([]);
			setHintDismissedFor(null);
		} catch (e) {
			const msg = (e as Error).message ?? String(e);
			// Expired-key failures surface as openpgp internals — translate to
			// actionable guidance (R8). Triggered e.g. when every encryption
			// subkey of a recipient is expired: "Could not find valid encryption
			// key packet in key <KEYID>: Subkey is expired".
			if (
				/could not find valid encryption key packet|subkey is expired|key is expired/i.test(msg)
			) {
				setError(
					"A recipient key is expired — OpenPGP refused to encrypt to it. Remove the expired recipient (or ask its owner for an updated public key) and encrypt again.",
				);
			} else {
				setError(msg);
			}
		} finally {
			setBusy(false);
		}
	}, [
		plaintext,
		attachments,
		recipients,
		privateKey,
		includeSelf,
		requestDecryptedKey,
		settings.autoSign,
		settings.compression,
		settings.pqSealedCopy,
	]);

	// Cheap substring detection on the MESSAGE textarea, computed during render
	// (no effect needed). Hints never appear for empty input; signed input is
	// not flagged here (signing already-encrypted input is a legitimate flow).
	// Dismissal is keyed to the message text, so clearing the field re-arms
	// the hint.
	const detectedBlock = detectPgpBlock(plaintext);
	const showEncryptHint =
		plaintext.trim() !== "" &&
		(detectedBlock === "encrypted" ||
			detectedBlock === "publickey" ||
			detectedBlock === "privatekey") &&
		hintDismissedFor !== plaintext;

	// Approximate input size for the output-block savings stat (R10): the
	// message bytes plus each attachment's original size — the same numbers
	// the envelope wire format wraps. Armor is ASCII so the output's string
	// length ≈ byte length; the comparison is an honest "did compression do
	// anything" signal, not an exact accounting (markers/base64 framing add
	// a small fixed overhead on the input side too).
	const inputBytes = useMemo(
		() =>
			new TextEncoder().encode(plaintext).length + attachments.reduce((sum, a) => sum + a.size, 0),
		[plaintext, attachments],
	);

	return (
		<section
			className="relative space-y-6"
			onKeyDown={(e) => {
				// Ctrl/Cmd+Enter runs the primary action from anywhere in the tab
				// (editor, attachment list, button). Skips while a run is in flight
				// — same guard as the button's disabled state.
				if ((e.ctrlKey || e.metaKey) && !e.altKey && !e.shiftKey && e.key === "Enter") {
					e.preventDefault();
					if (!busy) void handleEncrypt();
				}
			}}
			onDragEnter={(e) => {
				if (!e.dataTransfer.types.includes("Files")) return;
				e.preventDefault();
				setDragDepth((d) => d + 1);
			}}
			onDragOver={(e) => {
				if (!e.dataTransfer.types.includes("Files")) return;
				e.preventDefault();
			}}
			onDragLeave={(e) => {
				if (!e.dataTransfer.types.includes("Files")) return;
				setDragDepth((d) => Math.max(0, d - 1));
			}}
			onDrop={(e) => {
				if (!e.dataTransfer.types.includes("Files")) return;
				e.preventDefault();
				setDragDepth(0);
				if (e.dataTransfer.files.length > 0) {
					void addFiles(e.dataTransfer.files);
				}
			}}
		>
			{dragDepth > 0 && (
				<div
					aria-hidden
					className="pointer-events-none absolute inset-0 z-10 flex items-center justify-center rounded-xl border-2 border-dashed border-[#0055dc] bg-[#0055dc]/5 dark:border-[#5e94ff] dark:bg-[#5e94ff]/10 animate-fade-up"
				>
					<span className="rounded-lg bg-background/95 px-4 py-2 text-sm font-medium text-[#0055dc] shadow-sm dark:text-[#5e94ff]">
						Drop files to attach
					</span>
				</div>
			)}
			{draftNotice && (
				<div
					role="status"
					className="animate-fade-up flex items-start justify-between gap-3 rounded-xl border border-[#0055dc]/30 bg-[#0055dc]/5 px-4 py-3 shadow-sm dark:border-[#5e94ff]/40 dark:bg-[#5e94ff]/10"
				>
					<p className="text-xs leading-relaxed text-[#0055dc] dark:text-[#5e94ff]">
						<span className="font-medium">Draft restored</span> — your unsent message was recovered
						from this tab&apos;s earlier visit. It lives in session memory only and disappears when
						the tab closes.
					</p>
					<button
						type="button"
						onClick={() => {
							setPlaintext("");
							setDraftNotice(false);
						}}
						className="shrink-0 rounded-md px-2 py-1 text-xs font-medium text-[#0055dc] transition-colors hover:bg-[#0055dc]/10 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[#0055dc] dark:text-[#5e94ff] dark:hover:bg-[#5e94ff]/10 dark:focus-visible:outline-[#5e94ff]"
					>
						Discard
					</button>
				</div>
			)}
			<RecipientPicker
				recipients={recipients}
				setRecipients={setRecipients}
				selfRecipient={selfRecipient}
				includeSelf={includeSelf}
				onIncludeSelfChange={onIncludeSelfChange}
			/>

			<div className="rounded-xl">
				{/* Composer utility row: editor-style quick toggle (left, writes
								through to app settings) + starter templates (right). */}
				<div className="mb-1.5 flex items-center justify-between gap-2">
					<div
						role="group"
						aria-label="Composer style"
						className="flex items-center gap-0.5 rounded-lg border bg-muted/40 p-1"
					>
						<ComposerStyleButton
							kind="notion"
							active={settings.markdownEditor === "notion"}
							icon={Blocks}
							label="Notion-style block editor"
							onSelect={onEditorKindChange}
						/>
						<ComposerStyleButton
							kind="vscode"
							active={settings.markdownEditor === "vscode"}
							icon={SquareCode}
							label="VS Code-style markdown editor"
							onSelect={onEditorKindChange}
						/>
					</div>
					<TemplateMenu onInsert={insertTemplate} currentMessage={plaintext} />
				</div>
				<MessageEditor
					value={plaintext}
					onChange={setPlaintext}
					files={attachments}
					onNewImageDataUrl={handleNewImageDataUrl}
					editorKind={settings.markdownEditor}
					placeholder="Type the message you want to encrypt + sign…"
				/>
				{/* Char/word/size counter (visual feedback only). */}
				<InputSizeCounter text={plaintext} />
				{showEncryptHint && detectedBlock && (
					<InputHint
						tone={detectedBlock === "encrypted" ? "amber" : "info"}
						onDismiss={() => setHintDismissedFor(plaintext)}
					>
						{detectedBlock === "encrypted"
							? "This looks like an already-encrypted message. Encrypting it again is rarely what you want."
							: "This looks like a PGP key. Keys are imported in the key configuration dialog, not encrypted as messages."}
					</InputHint>
				)}
			</div>

			<AttachmentList
				attachments={attachments}
				onAddFiles={handleAddFiles}
				onRemove={(idx) => setAttachments((prev) => prev.filter((_, i) => i !== idx))}
			/>

			{/* Expiry pre-flight warning (R8): fires as soon as an expired key is
          on the recipient list — before any passphrase is requested. Amber,
          matching the own-key "expiring" banner family; non-blocking. */}
			{expiredRecipients.length > 0 && (
				<div
					role="status"
					className="animate-fade-up flex items-start gap-2.5 rounded-xl border border-amber-300/70 bg-amber-50 px-4 py-3 shadow-sm dark:border-amber-900/50 dark:bg-amber-950/30"
				>
					<TriangleAlert
						aria-hidden="true"
						className="mt-0.5 size-4 shrink-0 text-amber-600 dark:text-amber-400"
					/>
					<p className="text-xs leading-relaxed text-amber-900 dark:text-amber-200">
						<span className="font-medium">
							{expiredRecipients.length === 1
								? "A recipient key has expired."
								: `${expiredRecipients.length} recipient keys have expired.`}
						</span>{" "}
						{expiredRecipients
							.map(
								(r) => `“${r.label}” (expired ${new Date(r.expiresAt ?? 0).toLocaleDateString()})`,
							)
							.join(", ")}{" "}
						— encryption may fail. Ask the owner for an updated public key.
					</p>
				</div>
			)}

			{error && <ErrorBanner message={error} />}

			<div className="flex gap-2">
				<Button
					onClick={handleEncrypt}
					disabled={busy}
					className="bg-[#0055dc] text-white shadow-sm shadow-[#0055dc]/20 hover:bg-[#0046b8] transition-all duration-150 press-effect"
				>
					{busy ? (
						<>
							<Loader2
								aria-hidden="true"
								className="size-4 animate-spin motion-reduce:animate-none"
							/>
							Encrypting…
						</>
					) : (
						<>
							<Lock aria-hidden="true" className="size-4" />
							{output
								? settings.autoSign
									? "Encrypt & sign again"
									: "Encrypt again"
								: settings.autoSign
									? "Encrypt & sign"
									: "Encrypt"}
						</>
					)}
				</Button>
			</div>

			{output && outputMeta && (
				<div
					role="status"
					className="animate-fade-up flex flex-wrap items-center gap-2 rounded-xl border border-emerald-300/70 bg-emerald-50 px-4 py-2.5 shadow-sm dark:border-emerald-900/50 dark:bg-emerald-950/30"
				>
					<ShieldCheck
						aria-hidden="true"
						className="size-4 shrink-0 text-emerald-600 dark:text-emerald-400"
					/>
					<p className="text-xs font-medium text-emerald-900 dark:text-emerald-200">
						Message sealed — plaintext cleared from the composer.
					</p>
					<span
						title={
							outputMeta.labels.length > 0
								? `Sealed to: ${outputMeta.labels.join(", ")}`
								: undefined
						}
						className="cursor-help rounded-full bg-emerald-100 px-2 py-0.5 text-[11px] font-medium text-emerald-700 underline decoration-dotted decoration-emerald-400/60 underline-offset-2 dark:bg-emerald-900/40 dark:text-emerald-300 dark:decoration-emerald-500/50"
					>
						{outputMeta.keys} {outputMeta.keys === 1 ? "key" : "keys"}
					</span>
					{outputMeta.signed && (
						<span className="rounded-full bg-emerald-100 px-2 py-0.5 text-[11px] font-medium text-emerald-700 dark:bg-emerald-900/40 dark:text-emerald-300">
							signed
						</span>
					)}
				</div>
			)}

			{output && (
				<OutputBlock
					title={settings.autoSign ? "Encrypted + signed message" : "Encrypted message"}
					output={output}
					files={[]}
					// The plaintext was deleted from the composer on success —
					// only the ciphertext remains in memory, so there is no
					// preview. "Show raw text" IS the view.
					operation="encrypt"
					inputBytes={inputBytes}
					// Quantum-sealed copy REPLACES the output box (no second
					// box): violet PQ treatment + in-box Sealed/Recipient switch.
					sealedCopy={sealedCopy || undefined}
					sealedNote="Post-quantum outer layer for your archive — even a future quantum computer can't open it without the key on this device."
				/>
			)}

			{sealedHistory.length > 0 && (
				<section
					className="animate-fade-up overflow-hidden rounded-xl border border-border bg-card shadow-sm"
					aria-label="Recent sealed outputs"
				>
					<Collapsible open={historyOpen} onOpenChange={setHistoryOpen}>
						<div className="flex items-center gap-1 pr-3">
							<CollapsibleTrigger className="group flex min-w-0 flex-1 items-center gap-2.5 px-4 py-3 text-left transition-colors hover:bg-muted/40 focus-visible:outline-2 focus-visible:outline-offset-[-2px] focus-visible:outline-[#0055dc]">
								<span className="flex size-7 shrink-0 items-center justify-center rounded-lg bg-[#0055dc]/8 text-[#0055dc] dark:bg-[#5e94ff]/10 dark:text-[#5e94ff]">
									<History aria-hidden="true" className="size-4" />
								</span>
								<span className="min-w-0 text-sm font-medium">Recent sealed outputs</span>
								<span className="shrink-0 rounded-full bg-muted px-2 py-0.5 text-[11px] font-medium text-muted-foreground">
									{sealedHistory.length}
								</span>
								<ChevronDown
									aria-hidden="true"
									className="ml-auto size-4 shrink-0 text-muted-foreground transition-transform duration-200 group-data-[state=open]:rotate-180"
								/>
							</CollapsibleTrigger>
							<Button
								variant="ghost"
								size="sm"
								onClick={() => {
									setSealedHistory(clearSealedHistory());
									toast({ title: "Sealed-output history cleared" });
								}}
								className="shrink-0 text-muted-foreground hover:text-foreground"
							>
								<Trash2 aria-hidden="true" className="size-4" />
								Clear
							</Button>
						</div>
						<CollapsibleContent>
							<ul className="divide-y divide-border border-t border-border">
								{sealedHistory.map((entry) => (
									<li
										key={entry.id}
										className="flex flex-wrap items-center gap-x-3 gap-y-2 px-4 py-2.5 transition-colors odd:bg-muted/25 hover:bg-muted/40"
									>
										<time
											dateTime={new Date(entry.at).toISOString()}
											className="w-[7.5rem] shrink-0 font-mono text-[11px] text-muted-foreground"
										>
											{formatHistoryTime(entry.at)}
										</time>
										<span className="flex min-w-0 flex-1 flex-wrap items-center gap-1.5">
											<span
												title={
													entry.labels && entry.labels.length > 0
														? `Sealed to: ${entry.labels.join(", ")}`
														: undefined
												}
												className="cursor-help rounded-full bg-[#0055dc]/8 px-2 py-0.5 text-[10px] font-medium text-[#0055dc] underline decoration-dotted decoration-[#0055dc]/40 underline-offset-2 dark:bg-[#5e94ff]/10 dark:text-[#5e94ff] dark:decoration-[#5e94ff]/40"
											>
												{entry.keys} {entry.keys === 1 ? "key" : "keys"}
											</span>
											{entry.signed && (
												<span className="rounded-full bg-emerald-100 px-2 py-0.5 text-[10px] font-medium text-emerald-700 dark:bg-emerald-900/40 dark:text-emerald-300">
													signed
												</span>
											)}
											{entry.pqSealed && (
												<span className="rounded-full bg-violet-100 px-2 py-0.5 text-[10px] font-medium text-violet-700 dark:bg-violet-900/40 dark:text-violet-300">
													PQ
												</span>
											)}
											<span className="font-mono text-[10px] text-muted-foreground">
												~{Math.max(1, Math.round(entry.armor.length / 1024))} KB
											</span>
										</span>
										<span className="flex shrink-0 items-center gap-1">
											<Button
												variant="ghost"
												size="sm"
												onClick={() => {
													setOutput(entry.armor);
													setSealedCopy(entry.sealedArmor ?? "");
													setOutputMeta({
														keys: entry.keys,
														signed: entry.signed,
														labels: entry.labels ?? [],
													});
													setError(null);
													toast({
														title: "Sealed output restored",
														description:
															"The ciphertext is back in the output box — copy or download it from there.",
													});
												}}
												className="h-7 px-2 text-xs text-[#0055dc] hover:bg-[#0055dc]/8 hover:text-[#0055dc] dark:text-[#5e94ff] dark:hover:bg-[#5e94ff]/10"
											>
												<History aria-hidden="true" className="size-3.5" />
												Restore
											</Button>
											<CopyButton
												text={entry.armor}
												label="Copy"
												ariaLabel="Copy sealed output to clipboard"
											/>
											<DownloadButton text={entry.armor} title="sealed output" />
											<Button
												variant="ghost"
												size="icon"
												onClick={() => setSealedHistory(removeSealedEntry(entry.id))}
												aria-label="Remove this entry from the sealed-output history"
												className="size-7 text-muted-foreground hover:text-red-600 dark:hover:text-red-400"
											>
												<X aria-hidden="true" className="size-3.5" />
											</Button>
										</span>
									</li>
								))}
							</ul>
							<p className="border-t border-border bg-muted/25 px-4 py-2 text-[11px] text-muted-foreground">
								Ciphertext only, kept in this browser (last {MAX_SEALED_ENTRIES}). Plaintext is
								never stored — restoring puts the armor back in the output box above.
							</p>
						</CollapsibleContent>
					</Collapsible>
				</section>
			)}
		</section>
	);
}

/**
 * One segment of the composer-style segmented control (round 12). Icon-led
 * with a text label that collapses to icon-only on narrow screens so the
 * control fits beside the template menu at 390 px. `aria-pressed` carries
 * the active state; the active segment gets a raised background + shadow.
 */
function ComposerStyleButton({
	kind,
	active,
	icon: Icon,
	label,
	onSelect,
}: {
	kind: MarkdownEditorKind;
	active: boolean;
	icon: typeof Blocks;
	label: string;
	onSelect: (kind: MarkdownEditorKind) => void;
}) {
	return (
		<button
			type="button"
			onClick={() => onSelect(kind)}
			aria-pressed={active}
			title={label}
			className={`inline-flex h-7 items-center gap-1 rounded-md px-2 text-[11px] font-medium transition-all duration-150 focus-visible:outline-2 focus-visible:-outline-offset-2 focus-visible:outline-[#0055dc] dark:focus-visible:outline-[#5e94ff] ${
				active
					? "bg-background text-foreground shadow-sm"
					: "text-muted-foreground hover:text-foreground"
			}`}
		>
			<Icon className="size-3.5 shrink-0" aria-hidden />
			<span className="hidden min-[420px]:inline">{kind === "notion" ? "Notion" : "Code"}</span>
		</button>
	);
}

/**
 * Compact timestamp for a sealed-history row: same clock-face for today
 * ("14:32"), a day label otherwise ("Sep 12 · 14:32"). Pure formatting —
 * no state, no effects.
 */
function formatHistoryTime(at: number): string {
	const d = new Date(at);
	if (Number.isNaN(d.getTime())) return "";
	const now = new Date();
	const time = new Intl.DateTimeFormat(undefined, {
		hour: "2-digit",
		minute: "2-digit",
		hour12: false,
	}).format(d);
	const sameDay =
		d.getFullYear() === now.getFullYear() &&
		d.getMonth() === now.getMonth() &&
		d.getDate() === now.getDate();
	if (sameDay) return time;
	const day = new Intl.DateTimeFormat(undefined, { month: "short", day: "numeric" }).format(d);
	return `${day} \u00b7 ${time}`;
}
