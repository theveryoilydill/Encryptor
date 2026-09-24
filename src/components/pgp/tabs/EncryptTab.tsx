"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { createPortal } from "react-dom";
import {
	ArrowRight,
	BookmarkPlus,
	Check,
	ChevronDown,
	CircleSlash,
	Copy,
	Download,
	FileDown,
	FileUp,
	History,
	LayoutTemplate,
	List,
	Loader2,
	Lock,
	ClipboardCopy as CopyMarkdownIcon,
	Maximize2,
	Minimize2,
	Paperclip,
	Pencil,
	Search,
	ShieldCheck,
	ShieldX,
	Sparkles,
	StickyNote,
	Trash2,
	TriangleAlert,
	X,
} from "lucide-react";

import { Button } from "@/components/ui/button";
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible";
import { ToastAction } from "@/components/ui/toast";
import { RecipientPicker } from "@/components/pgp/RecipientPicker";
import {
	AttachmentList,
	CopyButton,
	DownloadButton,
	DraftRestoredNote,
	ErrorBanner,
	InputSizeCounter,
	OutputBlock,
} from "@/components/pgp/shared";
import { MessageEditor } from "@/components/pgp/MessageEditor";
import { VaultImportDialog } from "@/components/pgp/VaultImportDialog";
import type { PrivateKeyConfig, Recipient } from "@/components/pgp/contracts";
import { PROXIES } from "@/components/pgp/contracts";
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
import {
	appendSealedOutput,
	clearSealedHistory,
	importSealedEntries,
	loadSealedHistory,
	removeSealedEntry,
	updateSealedEntryNote,
	MAX_SEALED_ENTRIES,
	MAX_SEALED_NOTE_CHARS,
	parseVaultManifest,
	type ParsedVaultManifest,
	type SealedHistoryEntry,
} from "@/lib/pgp/sealed-history";
import { clearDraft, loadDraft, saveDraft } from "@/lib/pgp/drafts";
import {
	decryptAndAutoVerify,
	describeEncryptedMessage,
	encryptAndSign,
	encryptMessage,
	listPrivateKeyIds,
} from "@/lib/pgp/pgp";
import {
	isQuantumSealed,
	parseSealedArmor,
	sealForConfig,
	unwrapSealSecretAuto,
	unsealWithSecretKey,
} from "@/lib/pgp/pq";
import { fetchKeysFromAllSourcesWithLocal } from "@/lib/pgp/key-lookup";
import { downloadBlob } from "@/lib/pgp/zip-bundle";
import {
	buildPlaintextForEncryption,
	formatFileSize,
	readFileAsBase64,
	type EnvelopeFile,
} from "@/lib/pgp/envelope";
import { LIMITS } from "@/lib/constants";
import type { AppSettings } from "@/lib/pgp/settings";
import { InputHint, detectPgpBlock } from "@/components/pgp/InputHint";
import { getKeyExpiryStatus, parseLooseDate } from "@/lib/pgp/key-details";

/** Vault health-check verdicts (round 17) — runtime-only, keyed by entry id. */
type VaultHealthVerdict = "ok" | "not-mine" | "failed" | "running";

/** Curated starter templates for the composer (round-12 product pass:
 *  eight complete fill-in documents). Applying one REPLACES the composer
 *  content; [bracketed] placeholders are meant to be filled in, and the
 *  meeting-minutes starter ships GFM task-list checkboxes. Deliberately
 *  generic — the composer is a markdown editor, so emphasis/headers/
 *  checkboxes serialize losslessly into the envelope. Keep secrets OUT of
 *  templates: anything saved here lives in plain text on this device. */
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
		name: "Meeting minutes",
		description: "Decisions made, tasks owned — checkbox list included",
		body: [
			"**Meeting:** [title]",
			"**Date:** [date] — **Attendees:** [names]",
			"",
			"**Decisions**",
			"- [decision one]",
			"- [decision two]",
			"",
			"**Action items**",
			"- [ ] [task] — [owner], due [date]",
			"- [ ] [task] — [owner], due [date]",
			"- [ ] [task] — [owner], due [date]",
			"",
			"_Share these encrypted whenever the minutes mention anything confidential._",
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
	{
		name: "Password rotation notice",
		description: "Tell a teammate a password was rotated",
		body: [
			"**Service / site:** [service name]",
			"**Account / username:** [account ID]",
			"**Rotated on:** [date]",
			"",
			"**New password:** [paste the new password]",
			"",
			"**What to do:** sign in once with the password above, then update any saved logins. Stop using the old password immediately.",
			"",
			"_One-time secret — if you did not expect this rotation, reply encrypted before using the account._",
		].join("\n"),
	},
	{
		name: "Recovery codes handoff",
		description: "Deliver backup 2FA codes for safekeeping",
		body: [
			"**Service / site:** [service name]",
			"**Account / username:** [account ID]",
			"**Generated on:** [date]",
			"",
			"**Recovery codes** (each works once):",
			"- `[code 1]`",
			"- `[code 2]`",
			"- `[code 3]`",
			"- `[code 4]`",
			"",
			"_Whoever holds this message holds the way back in — store it offline, confirm receipt, and delete every other copy._",
		].join("\n"),
	},
	{
		name: "API / server access handoff",
		description: "Tokens, hosts, and scopes in one place",
		body: [
			"**Environment:** [production / staging]",
			"**Host / endpoint:** [host or URL]",
			"**Port:** [port]",
			"",
			"**API key or token:** [paste the token]",
			"**Secret (if separate):** [paste the secret]",
			"",
			"**Scope:** [what this access allows — e.g. read-only on the metrics API]",
			"**Valid until:** [expiry date, or “revoke after handoff”]",
			"",
			"_Rotate or revoke the credential once the work is done — access should never outlive its purpose._",
		].join("\n"),
	},
	{
		name: "Wi-Fi / device credentials",
		description: "Network names, passwords, and device logins",
		body: [
			"**Wi-Fi network (SSID):** [network name]",
			"**Wi-Fi password:** [password]",
			"**Guest network (if any):** [network name / password]",
			"",
			"**Device:** [laptop / phone / router model]",
			"**Device login:** [username] / [password or PIN]",
			"",
			"**Notes:** [anything a guest needs — captive portal, MAC filtering, hours]",
			"",
			"_For visitor access only — change the Wi-Fi password once the visit is over._",
		].join("\n"),
	},
	{
		name: "Incident note",
		description: "Report what happened, encrypted end to end",
		body: [
			"**Incident:** [short title]",
			"**Detected:** [date + time] — **Reported by:** [name]",
			"**Severity:** [low / medium / high / critical]",
			"",
			"**What happened:**",
			"[factual description — what was affected, how it was found]",
			"",
			"**Containment so far:**",
			"- [action taken]",
			"- [action taken]",
			"",
			"**Next steps**",
			"- [ ] [follow-up task] — [owner], due [date]",
			"",
			"_Keep distribution tight: share over this encrypted channel only, and log who received it._",
		].join("\n"),
	},
];

/** GitHub-style anchor slug for a heading title: lowercase, strip every
 *  character that is not a letter, number, space or hyphen, then spaces
 *  become hyphens. Mirrors the anchors GitHub generates for its own
 *  headings, so TOC links keep working when the message is pasted into a
 *  GitHub issue, README or comment.
 *
 *  # Mr. AI Acting on s183173's Behalf
 */
function githubSlug(title: string): string {
	return title
		.toLowerCase()
		.replace(/[^\p{L}\p{N}\s-]/gu, "")
		.replace(/\s+/g, "-");
}

/** Build a GitHub-style table of contents from the composer's markdown:
 *  every ATX heading (`#` through `######`) becomes an indented
 *  `- [Title](#slug)` row (2 spaces of indent per level below h1).
 *  Returns "" when the message has no headings — the caller toasts
 *  instead of inserting an empty TOC. */
function buildTableOfContents(markdown: string): string {
	const rows: string[] = [];
	for (const line of markdown.split("\n")) {
		const match = /^(#{1,6})\s+(.*)$/.exec(line);
		if (!match) continue;
		const title = match[2].trim();
		rows.push(`${"  ".repeat(match[1].length - 1)}- [${title}](#${githubSlug(title)})`);
	}
	return rows.join("\n");
}

/** Small right-aligned utility above the composer: the template menu works
 *  for BOTH editor styles (Notion blocks + VS Code textarea) because it
 *  rides the same setPlaintext path as typing. Applying a template
 *  REPLACES the composer content — templates are complete fill-in
 *  documents, not snippets to merge. Two sections: the user's own saved
 *  templates (localStorage, deletable) and the curated starters, plus a
 *  plain-text disclosure (templates are unencrypted on this device). */
function TemplateMenu({
	onApply,
	currentMessage,
}: {
	onApply: (body: string) => void;
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
				{/* Plain-text disclosure (round-12 product pass): saved templates live
                                    in this browser's storage UNENCRYPTED. One line up front keeps the
                                    "no secrets in templates" rule visible wherever templates are used. */}
				<p
					role="note"
					className="mx-1.5 mb-1 flex items-start gap-1.5 rounded-md bg-amber-50 px-2 py-1.5 text-[11px] font-medium leading-relaxed text-amber-700 dark:bg-amber-950/40 dark:text-amber-300"
				>
					<TriangleAlert aria-hidden="true" className="mt-0.5 size-3 shrink-0" />
					<span>
						Templates are stored in plain text on this device — never include real secrets.
					</span>
				</p>
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
							onApply(t.body);
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
						onClick={() => onApply(t.body)}
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
					<p
						role="note"
						className="flex items-start gap-1.5 rounded-md bg-amber-50 px-2.5 py-2 text-[11px] leading-relaxed text-amber-700 dark:bg-amber-950/40 dark:text-amber-300"
					>
						<TriangleAlert aria-hidden="true" className="mt-0.5 size-3.5 shrink-0" />
						<span>Saved in plain text on this device — remove secrets before saving.</span>
					</p>
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

/** True when a keyboard event started inside a nested Radix surface (a
 *  dialog, dropdown menu or listbox) that must keep Escape / shortcuts for
 *  itself — shared by the full-screen overlay's window + React handlers. */
function isNestedDialogTarget(target: EventTarget | null): boolean {
	const el = target as HTMLElement | null;
	return !!el?.closest?.(
		'[role="dialog"]:not([data-composer-overlay]), [data-radix-popper-content-wrapper], [role="menu"], [role="listbox"]',
	);
}

export function EncryptTab({
	privateKey,
	recipients,
	setRecipients,
	includeSelf,
	onIncludeSelfChange,
	requestDecryptedKey,
	onOpenInDecrypt,
	settings,
}: {
	privateKey: PrivateKeyConfig | null;
	recipients: Recipient[];
	setRecipients: (updater: (prev: Recipient[]) => Recipient[]) => void;
	includeSelf: boolean;
	onIncludeSelfChange: (v: boolean) => void;
	requestDecryptedKey: () => Promise<{ key: OpenPGP.PrivateKey; passphrase: string | null }>;
	/** Vault "Open in Decrypt" deep-link (round 14): the row hands over the
	 *  entry's armor (sealed copy preferred) plus a Date.now() seq; PgpApp
	 *  switches to the Decrypt tab and feeds the payload to DecryptTab's
	 *  pendingLoad effect. Optional — the tab renders fine unwired. */
	onOpenInDecrypt?: (payload: { armor: string; seq: number }) => void;
	/** App preferences (compression + editor style) — owned by PgpApp so a
	 *  settings change re-renders the open tab immediately. */
	settings: AppSettings;
}) {
	const { toast } = useToast();
	// Draft resilience (sessionStorage, see lib/pgp/drafts.ts): the composer
	// rehydrates whatever was typed before a refresh, and the restore is
	// surfaced (and discardable) rather than silent. The initializer runs
	// once per tab mount; the save effect below keeps storage in step.
	const [initialDraft] = useState(() => loadDraft("encrypt"));
	const [draftRestored, setDraftRestored] = useState(() => initialDraft !== null);
	const [plaintext, setPlaintext] = useState(initialDraft?.text ?? "");
	const [attachments, setAttachments] = useState<EnvelopeFile[]>(initialDraft?.files ?? []);
	// Debounced draft persistence — one write per pause in typing, not per
	// keystroke. Empty/whitespace text clears the stored draft instead of
	// writing an empty one, so "cleared the message" never resurrects. The
	// transient "Draft saved" tick in the counter row makes the (otherwise
	// silent) autosave visible without ever interrupting typing.
	const [draftSaved, setDraftSaved] = useState(false);
	useEffect(() => {
		const t = setTimeout(() => {
			if (plaintext.trim() === "") {
				clearDraft("encrypt");
				setDraftSaved(false);
			} else {
				saveDraft("encrypt", plaintext, attachments);
				setDraftSaved(true);
			}
		}, 600);
		return () => clearTimeout(t);
	}, [plaintext, attachments]);
	useEffect(() => {
		if (!draftSaved) return;
		const t = setTimeout(() => setDraftSaved(false), 2000);
		return () => clearTimeout(t);
	}, [draftSaved]);
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
	// Vault-manifest drag counter (round 19): the same depth-counter pattern as
	// the tab-level attachment dropzone, scoped to the vault section. While it
	// is > 0 the violet "Drop a vault manifest to import" overlay is hot and the
	// tab-level blue overlay stands down - a manifest drag must never read as
	// an attachment drag.
	const [vaultDragDepth, setVaultDragDepth] = useState(0);
	// Per-row note editor (round 22): id of the entry whose note editor is
	// open + the draft text. One editor at a time keeps the compact rows
	// predictable; the draft is discarded on cancel/row-switch.
	const [noteEditingId, setNoteEditingId] = useState<string | null>(null);
	const [noteDraft, setNoteDraft] = useState("");
	// Smart-input hint dismissal, keyed to the exact message content: clearing
	// the textarea (or typing different content) re-arms the hint without
	// needing a state-reset effect.
	const [hintDismissedFor, setHintDismissedFor] = useState<string | null>(null);

	// Full-screen composer overlay ("blow up the editor"): when expanded, the
	// whole composer — editor + utility row incl. the template menu — moves
	// into a portal dialog filling the viewport. The state lives HERE in the
	// tab; the editor engine simply re-mounts with the same value props, so
	// text, files and attachments survive expand AND collapse untouched.
	const [composerExpanded, setComposerExpanded] = useState(false);
	// Body scroll lock while the overlay is up; the previous inline value is
	// restored on cleanup (also fires if the tab unmounts mid-expanded).
	useEffect(() => {
		if (!composerExpanded) return;
		const prev = document.body.style.overflow;
		document.body.style.overflow = "hidden";
		return () => {
			document.body.style.overflow = prev;
		};
	}, [composerExpanded]);
	// Escape collapses the overlay from ANYWHERE: opening it unmounts the
	// expand button, which can drop focus on <body> — an overlay-local
	// handler would then never see the key (and an aria-modal dialog that
	// ignores Escape is an a11y bug). Window-level capture, same guard as
	// the overlay's own handler so nested Radix surfaces keep their Escape.
	useEffect(() => {
		if (!composerExpanded) return;
		const onWindowEscape = (e: KeyboardEvent) => {
			if (e.key !== "Escape" || e.defaultPrevented) return;
			if (isNestedDialogTarget(e.target)) return;
			e.preventDefault();
			setComposerExpanded(false);
		};
		window.addEventListener("keydown", onWindowEscape, true);
		return () => window.removeEventListener("keydown", onWindowEscape, true);
	}, [composerExpanded]);

	// Global Ctrl/Cmd+Shift+E — "shortcut to expand should apply everywhere":
	// the tab components stay mounted across tab switches, so a window-level
	// capture listener lets the composer open from ANY tab. Same dialog-safe
	// guards as the section handler; the section + overlay handlers see
	// defaultPrevented and skip, so the toggle never double-fires.
	//
	// # Mr. AI Acting on s183173's Behalf
	useEffect(() => {
		const onKey = (e: KeyboardEvent) => {
			if (
				(e.ctrlKey || e.metaKey) &&
				e.shiftKey &&
				!e.altKey &&
				(e.key === "E" || e.key === "e") &&
				!e.defaultPrevented
			) {
				const target = e.target as HTMLElement | null;
				if (
					target?.closest(
						'[role="dialog"]:not([data-composer-overlay]), [data-radix-popper-content-wrapper], [role="menu"], [role="listbox"]',
					)
				) {
					return;
				}
				e.preventDefault();
				setComposerExpanded((v) => !v);
			}
		};
		window.addEventListener("keydown", onKey, true);
		return () => window.removeEventListener("keydown", onKey, true);
	}, []);
	// Success summary for the LAST output (recipient count + signed),
	// rendered as a compact strip above the output block.
	const [outputMeta, setOutputMeta] = useState<{
		keys: number;
		signed: boolean;
		labels: string[];
		// Seal-time provenance (round 15): who signed (display label from the
		// configured key) and how many files were wrapped in — feeds the
		// strip chips; Restore passes both back through so a restored output
		// keeps its chips.
		signer?: string;
		files?: number;
		// Round 16: the signing key's full fingerprint (sanitized hex) —
		// drives the verify-style tooltips: the vault ROW chip shows the
		// FULL grouped fingerprint, the STRIP chip the short key id (last
		// 16 hex chars). Absent → the round-15 "captured at seal time"
		// wording.
		signerFp?: string;
	} | null>(null);
	// Recent sealed outputs — a ciphertext-only local history (lib/pgp/
	// sealed-history): the armored result of each encrypt is kept so an
	// earlier sealed message can be restored after the output block is
	// reset or replaced by a newer one. Collapsed by default.
	const [sealedHistory, setSealedHistory] = useState<SealedHistoryEntry[]>([]);
	// Clear is destructive (wipes every saved sealed output), so the first
	// click only arms it — second click within 3s confirms; blur disarms.
	// Cheap insurance against a mis-tap next to the collapsible trigger.
	const [confirmClear, setConfirmClear] = useState(false);
	const [historyOpen, setHistoryOpen] = useState(false);
	useEffect(() => {
		setSealedHistory(loadSealedHistory());
	}, []);

	// Vault search (round 23): a client-side filter over the entry metadata
	// people actually remember — recipient labels, the sticky note, the
	// signer label. The armor/fingerprint bytes are NOT searched: the note
	// field is the intended place for "what was this?" context.
	const [vaultQuery, setVaultQuery] = useState("");
	const filteredHistory = useMemo(() => {
		const q = vaultQuery.trim().toLowerCase();
		if (!q) return sealedHistory;
		return sealedHistory.filter((e) => {
			const haystack = [e.note ?? "", e.signer ?? "", ...(e.labels ?? [])]
				.join(" \n ")
				.toLowerCase();
			return haystack.includes(q);
		});
	}, [sealedHistory, vaultQuery]);

	// Vault summary-strip totals (round 16): computed over the (≤8) entries
	// with a cheap useMemo — combined armor bytes (classical + PQ copies)
	// feed the "~X KB sealed" segment; the signed / quantum-sealed /
	// attached counts only render when non-zero.
	const sealedTotals = useMemo(() => {
		let bytes = 0;
		let signed = 0;
		let pq = 0;
		let files = 0;
		for (const e of sealedHistory) {
			bytes += e.armor.length + (e.sealedArmor?.length ?? 0);
			if (e.signer) signed += 1;
			if (e.pqSealed) pq += 1;
			files += e.files ?? 0;
		}
		return { bytes, signed, pq, files };
	}, [sealedHistory]);

	// Vault health check (round 17): per-entry decrypt verdicts keyed by
	// entry id. RUNTIME ONLY — never persisted. Any vault mutation replaces
	// the sealedHistory array identity (append / remove / clear), so this
	// effect wipes the map and a stale verdict can never outlive the
	// ciphertext it described.
	const [healthMap, setHealthMap] = useState<Record<string, VaultHealthVerdict>>({});
	const [healthRunning, setHealthRunning] = useState(false);
	useEffect(() => {
		setHealthMap({});
	}, [sealedHistory]);
	// "N/M decryptable" tallies for the strip segment + closing toast: only
	// entries holding a verdict count (during a run the map fills entry by
	// entry; after it every entry carries one).
	const healthTotals = useMemo(() => {
		let ok = 0;
		let notMine = 0;
		let failed = 0;
		for (const e of sealedHistory) {
			const v = healthMap[e.id];
			if (v === "ok") ok += 1;
			else if (v === "not-mine") notMine += 1;
			else if (v === "failed") failed += 1;
		}
		return { checked: ok + notMine + failed, ok, notMine, failed };
	}, [sealedHistory, healthMap]);

	// Vault manifest import (round 18): the parsed manifest awaiting review
	// in the confirm dialog (null = dialog closed), plus the hidden file
	// input's ref. Parsing happens in handleVaultImportFile; the vault only
	// changes in runVaultImport, through importSealedEntries.
	const [pendingImport, setPendingImport] = useState<ParsedVaultManifest | null>(null);
	const vaultImportInputRef = useRef<HTMLInputElement>(null);

	// Read + validate a picked/dropped manifest, then open the review
	// dialog. Hostile or garbage files toast "Not a vault manifest" and
	// the vault stays untouched — nothing is half-applied.
	const handleVaultImportFile = useCallback(
		async (file: File | undefined | null) => {
			if (!file) return;
			try {
				const parsed = parseVaultManifest(JSON.parse(await file.text()));
				setPendingImport(parsed);
			} catch {
				toast({
					title: "Not a vault manifest",
					description: "Pick a JSON file produced by this vault's Export button.",
					variant: "destructive",
				});
			}
		},
		[toast],
	);

	// Apply the reviewed import. The toast wording comes straight from
	// importSealedEntries' counts — what ACTUALLY landed, duplicated or was
	// cap-dropped (merge), and kept (replace).
	const runVaultImport = useCallback(
		(mode: "merge" | "replace") => {
			const pending = pendingImport;
			if (!pending) return;
			setPendingImport(null);
			const result = importSealedEntries(pending.entries, sealedHistory, mode);
			setSealedHistory(result.entries);
			if (mode === "merge") {
				toast({
					title: `Imported — ${result.added} added · ${result.duplicates} ${
						result.duplicates === 1 ? "duplicate" : "duplicates"
					} skipped${result.dropped > 0 ? ` · ${result.dropped} dropped (cap)` : ""}`,
					description:
						result.dropped > 0
							? `The vault keeps the newest ${MAX_SEALED_ENTRIES} entries — older incoming rows lose their slot.`
							: undefined,
				});
			} else {
				toast({
					title: `Vault replaced — ${result.added} ${result.added === 1 ? "entry" : "entries"}`,
					description:
						result.dropped > 0
							? `${result.dropped} over the ${MAX_SEALED_ENTRIES}-entry cap ${result.dropped === 1 ? "was" : "were"} not kept.`
							: undefined,
				});
			}
		},
		[pendingImport, sealedHistory, toast],
	);

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

	/** Editor drop bridge (round 18): BlockNoteEditor consumes file drops
	 *  itself — images insert inline, non-images are forwarded here — so
	 *  the tab-level onDrop never fires for an editor-internal drop. The
	 *  drag-overlay reset MOVED here for exactly that reason: an EMPTY
	 *  files list still means "the editor consumed the drop" (image-only
	 *  drop) and the "Drop files to attach" overlay must not stick. */
	const handleComposerFilesDropped = useCallback(
		(files: File[]) => {
			setDragDepth(0);
			if (files.length > 0) void addFiles(files);
		},
		[addFiles],
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
	 *  update and the FINAL entry is returned.
	 *
	 *  Round 18: an optional suggestedName (a dropped file's REAL name) is
	 *  sanitized via sanitizeDroppedImageName and used when provided. */
	const handleNewImageDataUrl = useCallback(
		(dataUrl: string, suggestedName?: string): EnvelopeFile => {
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
			// Round 18: dropped images keep their REAL filename (sanitized by
			// sanitizeDroppedImageName); plain pastes have no name and fall back
			// to the classic pasted-image.<ext> the orphan GC relies on.
			const baseName = sanitizeDroppedImageName(suggestedName, ext);
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
			setAttachments((prev) =>
				prev.some((a) => a.name === stored.name) ? prev : [...prev, stored],
			);
			return stored;
		},
		[],
	);

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

	const handleAddFiles = useCallback(
		(files: FileList | null) => {
			if (files) void addFiles(files);
		},
		[addFiles],
	);

	// Apply a template: REPLACES the whole composer (round-12 product pass).
	// Starters and saved templates are complete fill-in documents, not
	// snippets — merging into existing text produced stitched-together
	// messages. Rides the same setPlaintext path as typing, so it works for
	// both editor styles.
	const applyTemplate = useCallback((body: string) => {
		setPlaintext(body);
	}, []);

	// "Insert table of contents" (round-12 editor pass): parse the CURRENT
	// composer markdown for ATX headings and PREPEND a GitHub-style TOC
	// (slug anchors, one blank line after). Heading-less messages get a
	// toast and are left completely untouched.
	const insertTableOfContents = useCallback(() => {
		const toc = buildTableOfContents(plaintext);
		if (!toc) {
			toast({ title: "No headings found — add some `#` headings first" });
			return;
		}
		setPlaintext(`${toc}\n\n${plaintext}`);
	}, [plaintext, toast]);

	// Copy the composer's markdown SOURCE (what the recipient will see
	// rendered). Works without sealing — for pasting the message anywhere
	// else, archiving it, or moving it to another tool.
	const handleCopyMarkdown = useCallback(() => {
		if (!plaintext.trim()) {
			toast({ title: "Nothing to copy — the composer is empty" });
			return;
		}
		void navigator.clipboard
			.writeText(plaintext)
			.then(() => toast({ title: "Markdown copied" }))
			.catch(() =>
				toast({
					title: "Copy failed",
					description: "The clipboard rejected the write — select the text and copy manually.",
					variant: "destructive",
				}),
			);
	}, [plaintext, toast]);

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
			// Seal-time provenance (round 15): the signing key's display label
			// (only meaningful when the output is actually signed) + the
			// attachment count — recorded on the strip AND in the vault entry.
			const signerLabel = signing ? privateKey?.label : undefined;
			// Round 16: the signing key's fingerprint, captured at seal time from
			// the configured key's info (optional-chained — a key configured
			// without metadata simply records no fingerprint). Same signing gate
			// as the label: a non-signed seal records no provenance.
			const signerFp = signing ? privateKey?.info.fingerprint : undefined;
			setOutputMeta({
				keys: recipientKeys.length,
				signed: signing,
				labels: recipientLabels,
				signer: signerLabel,
				signerFp,
				files: attachments.length,
			});
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
				signer: signerLabel,
				signerFp,
				files: attachments.length,
			});
			setSealedHistory(recorded.entries);
			setHistoryOpen(true);

			// The user can always decrypt their own copy (Include me) — so the
			// plaintext is deleted from the composer as soon as the ciphertext
			// exists. Only the output remains in memory. The draft goes with it
			// (immediately, not on the debounced effect — closing the tab inside
			// the debounce window must not resurrect a sealed message).
			clearDraft("encrypt");
			setDraftRestored(false);
			setPlaintext("");
			setAttachments([]);
			setHintDismissedFor(null);

			// Post-encrypt success toast (round 15). When "Include me" is on the
			// user can actually complete the flow, so it carries an "Open in
			// Decrypt" action that deep-links to the Decrypt tab — the PQ copy
			// when one exists (device-key unwrap, no passphrase prompt), else
			// the classical armor. Without include-me there is no copy of theirs
			// to open, so the action is omitted.
			toast({
				title: "Message sealed — plaintext cleared",
				description: "The ciphertext is in the output box below.",
				action: includeSelf ? (
					<ToastAction
						altText="Open your sealed copy in the Decrypt tab"
						onClick={() =>
							onOpenInDecrypt?.({
								armor: pqCopy ?? armored,
								seq: Date.now(),
							})
						}
					>
						Open in Decrypt
					</ToastAction>
				) : undefined,
			});
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
		onOpenInDecrypt,
		settings.autoSign,
		settings.compression,
		settings.pqSealedCopy,
	]);

	// Vault health check (round 17): "do my sealed outputs still decrypt?"
	// ONE requestDecryptedKey() up front — silent for passphrase-less keys
	// (device-key unwrap), the standard single prompt otherwise — then every
	// entry is tried with that SAME decrypted key. A PKESK-header pre-check
	// (describeEncryptedMessage — packet headers only, no secret material)
	// first separates "not yours" (sealed to other recipients only, expected
	// non-decryptable) from a real failure BEFORE any decryption. The
	// quantum-sealed copy is preferred (deep-link parity with Open in
	// Decrypt) with one classical fallback attempt.
	const runVaultHealthCheck = useCallback(async () => {
		if (!privateKey || healthRunning) return;
		setHealthRunning(true);
		try {
			// One unlock up front; the key exists only in this local variable.
			const { key: decryptedKey, passphrase } = await requestDecryptedKey();

			// Own key IDs (primary + subkeys) for the PKESK pre-check — read
			// WITHOUT decrypting anything (no passphrase, no secret material).
			const ownKeyIds = (await listPrivateKeyIds(privateKey.encryptedArmored ?? "")) ?? [];

			let okCount = 0;
			let notMineCount = 0;
			let failedCount = 0;

			for (const entry of sealedHistory) {
				setHealthMap((prev) => ({ ...prev, [entry.id]: "running" }));
				// Small await point: the amber per-row spinner must render
				// before the (potentially heavy) decrypt work starts.
				await new Promise((resolve) => setTimeout(resolve, 30));

				// (a) PKESK pre-check on the CLASSICAL armor: when the packet
				// headers list recipient keys and NONE of them is ours, the
				// message was sealed to other recipients only — not decryptable
				// by design, so "not yours" without a decryption attempt.
				const meta = await describeEncryptedMessage(entry.armor);
				if (
					meta &&
					ownKeyIds.length > 0 &&
					!meta.recipientKeyIDs.some((id) => ownKeyIds.includes(id))
				) {
					setHealthMap((prev) => ({ ...prev, [entry.id]: "not-mine" }));
					notMineCount += 1;
					continue;
				}

				// (b) Decrypt trial: quantum-sealed copy first (same path as
				// Open in Decrypt), one classical fallback attempt.
				const tryDecrypt = async (armored: string): Promise<string> => {
					let classicalInput = armored;
					if (isQuantumSealed(armored)) {
						if (!privateKey.pq) throw new Error("No quantum-seal key configured for this key.");
						const sealSecret = await unwrapSealSecretAuto(privateKey.pq, passphrase);
						classicalInput = await unsealWithSecretKey(parseSealedArmor(armored), sealSecret);
					}
					const result = await decryptAndAutoVerify(
						{
							armoredMessage: classicalInput,
							decryptionPrivateKey: decryptedKey,
							verificationPublicKeys: [],
						},
						(keyIDs) =>
							fetchKeysFromAllSourcesWithLocal(
								keyIDs,
								PROXIES.fetchkeyProxy,
								PROXIES.fetchkeyOpgProxy,
								{
									encryptedArmored: privateKey.encryptedArmored ?? "",
									label: privateKey.label,
								},
							),
					);
					return result.plaintext;
				};

				let verdict: VaultHealthVerdict = "failed";
				if (entry.sealedArmor) {
					try {
						await tryDecrypt(entry.sealedArmor);
						verdict = "ok";
					} catch {
						// Sealed copy did not open — one classical fallback below.
					}
				}
				if (verdict !== "ok") {
					try {
						await tryDecrypt(entry.armor);
						verdict = "ok";
					} catch {
						verdict = "failed";
					}
				}
				setHealthMap((prev) => ({ ...prev, [entry.id]: verdict }));
				if (verdict === "ok") okCount += 1;
				else failedCount += 1;
			}

			// Closing tally, worded honestly: only entries that actually
			// opened count as decryptable; not-mine entries are the expected
			// non-decryptables and get their own mention.
			const total = sealedHistory.length;
			const notes: string[] = [];
			if (notMineCount > 0)
				notes.push(
					`${notMineCount} ${notMineCount === 1 ? "entry is" : "entries are"} sealed to other recipients only`,
				);
			if (failedCount > 0) notes.push(`${failedCount} failed to decrypt`);
			toast({
				title: `Health check: ${okCount}/${total} decryptable`,
				description:
					notes.length > 0
						? `${notes.join(" \u00b7 ")}. Verdicts are runtime-only and clear on the next vault change.`
						: "Every sealed output opened with your key.",
			});
		} catch (e) {
			// requestDecryptedKey rejected (the prompt was cancelled) — no
			// verdicts were produced, nothing to report per row.
			toast({
				title: "Health check cancelled",
				description:
					e instanceof Error && e.message
						? e.message
						: "Your key was not unlocked, so nothing was checked.",
			});
		} finally {
			setHealthRunning(false);
		}
	}, [privateKey, healthRunning, sealedHistory, requestDecryptedKey, toast]);

	// Vault manifest export (round 17): the whole vault as one portable JSON
	// file — kind/version/exportedAt/count/entries with the classical armor,
	// the quantum-sealed copy and every scrap of seal-time provenance.
	// Ciphertext-only BY CONSTRUCTION: vault entries never hold plaintext,
	// so the manifest cannot leak it.
	const handleExportManifest = useCallback(() => {
		if (sealedHistory.length === 0) return;
		const manifest = {
			kind: "encryptor-vault-manifest",
			version: 1,
			exportedAt: new Date().toISOString(),
			count: sealedHistory.length,
			entries: sealedHistory.map((entry) => ({
				id: entry.id,
				createdAt: new Date(entry.at).toISOString(),
				keys: entry.keys,
				signed: entry.signed,
				pqSealed: entry.pqSealed,
				labels: entry.labels ?? [],
				signer: entry.signer,
				signerFp: entry.signerFp,
				files: entry.files,
				note: entry.note,
				armor: entry.armor,
				sealedArmor: entry.sealedArmor,
			})),
		};
		const blob = new Blob([JSON.stringify(manifest, null, 2)], { type: "application/json" });
		downloadBlob(blob, vaultManifestFilename());
		toast({
			title: `Vault manifest exported — ${sealedHistory.length} ${
				sealedHistory.length === 1 ? "entry" : "entries"
			}`,
			description: "Ciphertext only: the manifest carries armor + provenance, never plaintext.",
		});
	}, [sealedHistory, toast]);

	// Save (or clear) a per-entry note: persisted through updateSealedEntryNote
	// (which re-sanitizes on write) and mirrored into local state. An empty
	// draft is a first-class clear — the toast says which.
	const handleSaveNote = useCallback(
		(id: string) => {
			const updated = updateSealedEntryNote(id, noteDraft);
			setSealedHistory(updated);
			setNoteEditingId(null);
			setNoteDraft("");
			toast(
				noteDraft.trim() === ""
					? { title: "Note removed" }
					: { title: "Note saved — it travels with exported vault manifests" },
			);
		},
		[noteDraft, toast],
	);

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

	// The whole composer — utility row (TOC, Expand, template menu) + editor
	// + counter + smart-input hint — as one value, rendered EITHER inline OR
	// inside the full-screen portal overlay further down. Moving it in and
	// out of the overlay is therefore a pure re-mount: no state lives in the
	// subtree.
	//
	// # Mr. AI Acting on s183173's Behalf
	const composerBody = (
		<>
			{/* Composer utility row: copy-markdown, table-of-contents insert,
                            full-screen toggle and the template menu, right-aligned. */}
			<div className="mb-1.5 flex items-center justify-end gap-2">
				<button
					type="button"
					aria-label="Copy message as markdown"
					title="Copy message as markdown"
					onClick={handleCopyMarkdown}
					className="flex size-7 shrink-0 items-center justify-center rounded-lg text-muted-foreground transition-colors hover:bg-black/5 hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#0055dc]/40 dark:hover:bg-white/10 dark:focus-visible:ring-[#5e94ff]/40"
				>
					<CopyMarkdownIcon aria-hidden="true" className="size-3.5" />
				</button>
				<button
					type="button"
					aria-label="Insert table of contents"
					title="Insert table of contents"
					onClick={insertTableOfContents}
					className="flex size-7 shrink-0 items-center justify-center rounded-lg text-muted-foreground transition-colors hover:bg-black/5 hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#0055dc]/40 dark:hover:bg-white/10 dark:focus-visible:ring-[#5e94ff]/40"
				>
					<List aria-hidden="true" className="size-3.5" />
				</button>
				<button
					type="button"
					aria-label={composerExpanded ? "Collapse editor" : "Expand editor to full screen"}
					title={composerExpanded ? "Collapse editor" : "Expand editor to full screen"}
					onClick={() => setComposerExpanded((v) => !v)}
					className="flex size-7 shrink-0 items-center justify-center rounded-lg text-muted-foreground transition-colors hover:bg-black/5 hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#0055dc]/40 dark:hover:bg-white/10 dark:focus-visible:ring-[#5e94ff]/40"
				>
					{composerExpanded ? (
						<Minimize2 aria-hidden="true" className="size-3.5" />
					) : (
						<Maximize2 aria-hidden="true" className="size-3.5" />
					)}
				</button>
				<TemplateMenu onApply={applyTemplate} currentMessage={plaintext} />
			</div>
			{/* flex-1 min-h-0 in the overlay lets the active editor engine fill
                            the viewport; plain block inline. */}
			<div className={composerExpanded ? "min-h-0 flex-1" : undefined}>
				<MessageEditor
					value={plaintext}
					onChange={setPlaintext}
					files={attachments}
					onNewImageDataUrl={handleNewImageDataUrl}
					onFilesDropped={handleComposerFilesDropped}
					editorKind={settings.markdownEditor}
					placeholder="Type the message you want to encrypt + sign…"
					expanded={composerExpanded}
				/>
			</div>
			{/* Draft-resilience note — only after an actual restore, and gone
                        once the user discards or seals the message. */}
			{draftRestored && (
				<DraftRestoredNote
					filesDropped={initialDraft?.filesDropped}
					onDiscard={() => {
						clearDraft("encrypt");
						setDraftRestored(false);
						setPlaintext("");
						setAttachments([]);
						setHintDismissedFor(null);
					}}
				/>
			)}
			{/* Char/word/size counter (visual feedback only) + the transient
                            "Draft saved" tick from the debounced autosave. */}
			<InputSizeCounter text={plaintext} note={draftSaved ? "Draft saved" : undefined} />
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
		</>
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
				// Ctrl/Cmd+Shift+E toggles the full-screen composer from anywhere in
				// the tab. Dialog-safe: keys aimed at an open Radix dialog/popover/
				// menu belong to that surface, never to us — and an already-handled
				// (defaultPrevented) event is left alone. The composer overlay
				// itself opts back in via the :not, just like its Escape guard.
				if (
					(e.ctrlKey || e.metaKey) &&
					e.shiftKey &&
					!e.altKey &&
					(e.key === "E" || e.key === "e") &&
					!e.defaultPrevented
				) {
					const target = e.target as HTMLElement | null;
					if (
						target?.closest(
							'[role="dialog"]:not([data-composer-overlay]), [data-radix-popper-content-wrapper], [role="menu"], [role="listbox"]',
						)
					) {
						return;
					}
					e.preventDefault();
					setComposerExpanded((v) => !v);
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
			{dragDepth > 0 && vaultDragDepth === 0 && (
				<div
					aria-hidden
					className="pointer-events-none absolute inset-0 z-10 flex items-center justify-center rounded-xl border-2 border-dashed border-[#0055dc] bg-[#0055dc]/5 dark:border-[#5e94ff] dark:bg-[#5e94ff]/10 animate-fade-up"
				>
					<span className="rounded-lg bg-background/95 px-4 py-2 text-sm font-medium text-[#0055dc] shadow-sm dark:text-[#5e94ff]">
						Drop files to attach
					</span>
				</div>
			)}
			{/* Guided-tour anchor: the recipient search lives here. */}
			<div data-tour="recipients">
				<RecipientPicker
					recipients={recipients}
					setRecipients={setRecipients}
					selfRecipient={selfRecipient}
					includeSelf={includeSelf}
					onIncludeSelfChange={onIncludeSelfChange}
				/>
			</div>

			{!composerExpanded && (
				<div className="rounded-xl" data-tour="composer">
					{composerBody}
				</div>
			)}
			{/* Full-screen composer overlay ("blow up the editor"): a portal
                            dialog filling the viewport. Escape collapses it — EXCEPT when a
                            Radix surface opened FROM the composer is on stage (template
                            dropdown, save-template dialog, …): those consume Escape
                            themselves and must never come back to a collapsed composer.
                            Most Radix layers portal OUTSIDE this overlay, so their Escapes
                            never even bubble through it; the target checks + the
                            defaultPrevented guard cover the paths that still do. */}
			{composerExpanded &&
				createPortal(
					<div
						data-composer-overlay
						role="dialog"
						aria-modal="true"
						aria-label="Composer, full screen"
						onPointerDown={(e) => {
							// Click-off close: a press on the overlay itself (the backdrop
							// around the editor card) collapses — presses inside the
							// composer content target deeper nodes and are ignored.
							if (e.target === e.currentTarget) {
								e.preventDefault();
								setComposerExpanded(false);
							}
						}}
						onKeyDownCapture={(e) => {
							if (e.key !== "Escape" || e.defaultPrevented) return;
							if (isNestedDialogTarget(e.target)) return;
							e.preventDefault();
							setComposerExpanded(false);
						}}
						onKeyDown={(e) => {
							// Mirror the tab's Ctrl/Cmd+Enter primary action — the
							// portal sits outside the <section> keydown handler.
							if ((e.ctrlKey || e.metaKey) && !e.altKey && !e.shiftKey && e.key === "Enter") {
								e.preventDefault();
								if (!busy) void handleEncrypt();
							}
							// Ctrl/Cmd+Shift+E collapses the overlay — mirrored here for
							// the same reason as Ctrl/Cmd+Enter (the portal never bubbles
							// through the section handler). Same dialog-safe guard as the
							// section: nested dialogs/popovers opened FROM the composer
							// keep the keys for themselves.
							if (
								(e.ctrlKey || e.metaKey) &&
								e.shiftKey &&
								!e.altKey &&
								(e.key === "E" || e.key === "e") &&
								!e.defaultPrevented
							) {
								const target = e.target as HTMLElement | null;
								if (
									target?.closest(
										'[role="dialog"]:not([data-composer-overlay]), [data-radix-popper-content-wrapper], [role="menu"], [role="listbox"]',
									)
								) {
									return;
								}
								e.preventDefault();
								setComposerExpanded(false);
							}
						}}
						className="fixed inset-0 z-50 overflow-y-auto bg-background p-4 sm:p-6"
					>
						<div className="mx-auto flex h-full min-h-0 w-full flex-col">{composerBody}</div>
					</div>,
					document.body,
				)}

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
					{outputMeta.signed &&
						(outputMeta.signer ? (
							// Emerald "signed by <label>" chip (round 15): replaces the bare
							// chip when the seal captured a signer label. The label is
							// recorded at seal time — displayed, not verified here.
							<span
								title={
									outputMeta.signerFp
										? `Signed by ${outputMeta.signer} at seal time · key id ${formatFingerprint(outputMeta.signerFp.slice(-16))}`
										: `Signed by ${outputMeta.signer} — display label captured at seal time (not verified here).`
								}
								className="cursor-help rounded-full border border-emerald-500/30 bg-emerald-500/10 px-2 py-0.5 text-[11px] font-medium text-emerald-600 dark:text-emerald-500"
							>
								signed by {outputMeta.signer}
							</span>
						) : (
							<span className="rounded-full bg-emerald-100 px-2 py-0.5 text-[11px] font-medium text-emerald-700 dark:bg-emerald-900/40 dark:text-emerald-300">
								signed
							</span>
						))}
					{/* Paperclip icon (round 16): files chips read as attachments at
                                            a glance — strip + vault rows + summary strip share the motif. */}
					{outputMeta.files !== undefined && outputMeta.files > 0 && (
						<span className="inline-flex items-center gap-1 rounded-full bg-zinc-500/10 px-2 py-0.5 text-[11px] font-medium text-zinc-600 dark:text-zinc-400">
							<Paperclip aria-hidden="true" className="size-3" />
							{outputMeta.files} {outputMeta.files === 1 ? "file" : "files"}
						</span>
					)}
					{sealedCopy && (
						// Violet PQ-sealed chip — mirrors the output box's violet PQ
						// badge (OutputBlock in shared.tsx): the strip reports the
						// ML-KEM-768 outer layer just like the box header does.
						<span className="rounded-full border border-violet-500/30 bg-violet-500/10 px-2 py-0.5 text-[11px] font-medium text-violet-600 dark:text-violet-500">
							PQ-sealed
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

			{/* Round 18 UX: the vault shell ALWAYS renders (collapsed default) —
                            after a Clear (or on a fresh browser) Import used to be unreachable
                            when the whole section unmounted at 0 entries. */}
			<section
				className="relative animate-fade-up overflow-hidden rounded-xl border border-border bg-card shadow-sm"
				aria-label="Recent sealed outputs"
				onDragEnter={(e) => {
					// Vault-manifest dropzone (round 19): guarded on Files so
					// text/element drags never trigger it, and stopPropagation'd
					// in EVERY handler so the tab-level attachment dropzone can
					// never claim a manifest - a hostile drop toasts "Not a
					// vault manifest" instead of becoming attachments.
					if (!e.dataTransfer.types.includes("Files")) return;
					e.preventDefault();
					e.stopPropagation();
					setVaultDragDepth((d) => d + 1);
				}}
				onDragOver={(e) => {
					if (!e.dataTransfer.types.includes("Files")) return;
					e.preventDefault();
					e.stopPropagation();
				}}
				onDragLeave={(e) => {
					if (!e.dataTransfer.types.includes("Files")) return;
					e.stopPropagation();
					setVaultDragDepth((d) => Math.max(0, d - 1));
				}}
				onDrop={(e) => {
					if (!e.dataTransfer.types.includes("Files")) return;
					e.preventDefault();
					e.stopPropagation();
					setVaultDragDepth(0);
					// Same reviewed merge/replace flow as the Import button.
					void handleVaultImportFile(e.dataTransfer.files?.[0]);
				}}
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
						{/* Round 18: Clear only makes sense with entries — hides at 0 so
                                                            the empty state stays the single focus. */}
						{sealedHistory.length > 0 && (
							<Button
								variant="ghost"
								size="sm"
								onClick={() => {
									if (!confirmClear) {
										setConfirmClear(true);
										return;
									}
									setConfirmClear(false);
									setSealedHistory(clearSealedHistory());
									toast({ title: "Sealed-output history cleared" });
								}}
								onBlur={() => setConfirmClear(false)}
								className={
									confirmClear
										? "shrink-0 text-destructive hover:text-destructive"
										: "shrink-0 text-muted-foreground hover:text-foreground"
								}
							>
								<Trash2 aria-hidden="true" className="size-4" />
								{confirmClear ? "Really clear?" : "Clear"}
							</Button>
						)}
					</div>
					<CollapsibleContent>
						{sealedHistory.length === 0 ? (
							<div className="px-4 py-5">
								{/* Round 18 UX discovery: the old shell only rendered when
                                                                            entries existed, so after a Clear (or on a fresh browser)
                                                                            Import was UNREACHABLE. The empty state gets its own dashed
                                                                            card + import button instead. */}
								<div className="flex flex-col items-center gap-2 rounded-xl border border-dashed border-border px-4 py-6 text-center">
									<History aria-hidden="true" className="size-5 text-muted-foreground" />
									<p className="text-sm font-medium">Nothing sealed yet</p>
									<p className="max-w-sm text-xs leading-relaxed text-muted-foreground">
										Every sealed message lands here as a ciphertext-only copy — restore it, open it
										in Decrypt, or export the vault to move it to another device. You can also drag
										an exported manifest onto this card to import it.
									</p>
									<Button
										type="button"
										variant="outline"
										size="sm"
										onClick={() => vaultImportInputRef.current?.click()}
										className="mt-1 gap-1.5"
									>
										<FileUp aria-hidden="true" className="size-3.5" />
										Import manifest
									</Button>
								</div>
							</div>
						) : (
							<>
								{/* Vault summary strip (round 16): a thin muted at-a-glance bar —
                                                            "N entries · ~X KB sealed · N signed · N quantum-sealed · N
                                                            attached". Only the segments that apply render; the size
                                                            combines classical + PQ armor bytes. */}
								<div className="flex flex-wrap items-center gap-x-1 px-4 pb-1 pt-2 text-[11px] text-muted-foreground">
									<span>
										{sealedHistory.length} {sealedHistory.length === 1 ? "entry" : "entries"}
									</span>
									<span aria-hidden="true">·</span>
									<span>~{(sealedTotals.bytes / 1024).toFixed(1)} KB sealed</span>
									{sealedTotals.signed > 0 && (
										<>
											<span aria-hidden="true">·</span>
											<span>{sealedTotals.signed} signed</span>
										</>
									)}
									{sealedTotals.pq > 0 && (
										<>
											<span aria-hidden="true">·</span>
											<span className="text-violet-600 dark:text-violet-400">
												{sealedTotals.pq} quantum-sealed
											</span>
										</>
									)}
									{sealedTotals.files > 0 && (
										<>
											<span aria-hidden="true">·</span>
											<span className="inline-flex items-center gap-1">
												<Paperclip aria-hidden="true" className="size-3" />
												{sealedTotals.files} attached
											</span>
										</>
									)}
									{healthTotals.checked > 0 && (
										<>
											<span aria-hidden="true">·</span>
											<span
												className="text-emerald-600 dark:text-emerald-400"
												title={`Opened with your key during the last health check — ${healthTotals.ok} of ${sealedHistory.length} decryptable${
													healthTotals.notMine > 0
														? `, ${healthTotals.notMine} not addressed to your key`
														: ""
												}${healthTotals.failed > 0 ? `, ${healthTotals.failed} failed` : ""}.`}
											>
												{healthTotals.ok}/{sealedHistory.length} decryptable
											</span>
										</>
									)}
									<span className="ml-auto flex items-center gap-1">
										<Button
											type="button"
											variant="ghost"
											size="sm"
											onClick={runVaultHealthCheck}
											disabled={!privateKey || healthRunning}
											title={
												!privateKey
													? "Configure your private key first — the health check decrypts with your key."
													: "Try every sealed output with your key — verdicts appear on each row."
											}
											className="h-7 gap-1.5 px-2 text-[11px] text-muted-foreground hover:text-foreground"
										>
											{healthRunning ? (
												<Loader2 aria-hidden="true" className="size-3.5 animate-spin" />
											) : (
												<ShieldCheck aria-hidden="true" className="size-3.5" />
											)}
											Health check
										</Button>
										<Button
											type="button"
											variant="ghost"
											size="sm"
											onClick={handleExportManifest}
											disabled={sealedHistory.length === 0}
											title={
												sealedHistory.length === 0
													? "Nothing to export yet — the vault is empty."
													: "Download the whole vault as a ciphertext-only JSON manifest."
											}
											className="h-7 gap-1.5 px-2 text-[11px] text-muted-foreground hover:text-foreground"
										>
											<Download aria-hidden="true" className="size-3.5" />
											Export
										</Button>
										<Button
											type="button"
											variant="ghost"
											size="sm"
											onClick={() => vaultImportInputRef.current?.click()}
											title="Merge or replace your vault from an exported manifest JSON."
											className="h-7 gap-1.5 px-2 text-[11px] text-muted-foreground hover:text-foreground"
										>
											<FileUp aria-hidden="true" className="size-3.5" />
											Import
										</Button>
									</span>
								</div>
								{/* Vault search row (round 23): renders with entries, under the
                                                                    summary strip. Filters by recipient labels / note / signer;
                                                                    shows an N-of-M tally while active. */}
								<div className="flex items-center gap-2 px-4 pb-2">
									<div className="relative min-w-0 flex-1">
										<Search
											aria-hidden="true"
											className="pointer-events-none absolute top-1/2 left-2.5 size-3.5 -translate-y-1/2 text-muted-foreground"
										/>
										<Input
											value={vaultQuery}
											onChange={(e) => setVaultQuery(e.target.value)}
											onKeyDown={(e) => {
												if (e.key === "Escape") {
													e.preventDefault();
													setVaultQuery("");
												}
											}}
											placeholder="Filter by recipient, note, or signer"
											aria-label="Filter vault entries"
											className="h-8 bg-background pl-8 text-xs dark:bg-input/20"
										/>
									</div>
									{vaultQuery.trim() !== "" && (
										<span
											className="shrink-0 text-[11px] tabular-nums text-muted-foreground"
											aria-live="polite"
										>
											{filteredHistory.length} of {sealedHistory.length}
										</span>
									)}
								</div>
								<ul className="divide-y divide-border border-t border-border">
									{filteredHistory.length === 0 && vaultQuery.trim() !== "" ? (
										<li className="px-4 py-5 text-center">
											<p className="text-xs text-muted-foreground">
												No vault entries match “{vaultQuery.trim()}”. The filter covers recipient
												labels, notes, and the signer — not the ciphertext.
											</p>
										</li>
									) : (
										filteredHistory.map((entry) => (
											<li
												key={entry.id}
												className="relative flex flex-wrap items-center gap-x-3 gap-y-2 px-4 py-2.5 transition-colors odd:bg-muted/25 hover:bg-muted/40"
											>
												{/* PQ edge accent (round 14): a violet gradient strip on the left
                                                                                    edge mirrors the PQ chip/badge color language — rows carrying a
                                                                                    quantum-sealed copy are spottable at a glance. */}
												{entry.sealedArmor && (
													<span
														aria-hidden="true"
														className="absolute inset-y-1 left-0 w-[3px] rounded-full bg-gradient-to-b from-violet-500 to-fuchsia-500"
													/>
												)}
												<time
													dateTime={new Date(entry.at).toISOString()}
													title={formatHistoryTime(entry.at)}
													className="w-[7.5rem] shrink-0 cursor-help font-mono text-[11px] text-muted-foreground"
												>
													{formatRelativeHistoryTime(entry.at)}
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
													{entry.signed &&
														(entry.signer ? (
															<span
																title={
																	entry.signerFp
																		? `Signed by ${entry.signer} at seal time · fingerprint ${formatFingerprint(entry.signerFp)}`
																		: `Signed by ${entry.signer} — display label captured at seal time (not verified here).`
																}
																className="cursor-help rounded-full border border-emerald-500/30 bg-emerald-500/10 px-2 py-0.5 text-[10px] font-medium text-emerald-600 dark:text-emerald-500"
															>
																signed by {entry.signer}
															</span>
														) : (
															<span className="rounded-full bg-emerald-100 px-2 py-0.5 text-[10px] font-medium text-emerald-700 dark:bg-emerald-900/40 dark:text-emerald-300">
																signed
															</span>
														))}
													{entry.pqSealed && (
														<span className="rounded-full bg-violet-100 px-2 py-0.5 text-[10px] font-medium text-violet-700 dark:bg-violet-900/40 dark:text-violet-300">
															PQ
														</span>
													)}
													{entry.files !== undefined && entry.files > 0 && (
														<span className="inline-flex items-center gap-1 rounded-full bg-zinc-500/10 px-2 py-0.5 text-[10px] font-medium text-zinc-600 dark:text-zinc-400">
															<Paperclip aria-hidden="true" className="size-3" />
															{entry.files} {entry.files === 1 ? "file" : "files"}
														</span>
													)}
													<HealthVerdictChip verdict={healthMap[entry.id]} />
													<span className="font-mono text-[10px] text-muted-foreground">
														~{Math.max(1, Math.round(entry.armor.length / 1024))} KB
													</span>
												</span>
												{/* User note line (round 22): basis-full drops it onto its own
                                                                                    row under the auto chips. Annotation voice — amber accent +
                                                                                    italic — deliberately distinct from the seal-time chip family.
                                                                                    Clicking the note re-opens the editor. */}
												{noteEditingId !== entry.id && entry.note && (
													<button
														type="button"
														onClick={() => {
															setNoteEditingId(entry.id);
															setNoteDraft(entry.note ?? "");
														}}
														aria-label={`Edit the note on this entry: ${entry.note}`}
														className="flex w-full basis-full cursor-pointer items-start gap-1.5 border-l-2 border-amber-400/60 pl-2 text-left"
													>
														<StickyNote
															aria-hidden="true"
															className="mt-0.5 size-3.5 shrink-0 text-amber-500 dark:text-amber-400/80"
														/>
														<span className="text-[11px] italic leading-snug text-muted-foreground">
															{entry.note}
														</span>
													</button>
												)}
												{noteEditingId === entry.id && (
													<span className="flex w-full basis-full flex-wrap items-center gap-1.5">
														<Input
															value={noteDraft}
															onChange={(e) => setNoteDraft(e.target.value)}
															onKeyDown={(e) => {
																if (e.key === "Enter") {
																	e.preventDefault();
																	handleSaveNote(entry.id);
																} else if (e.key === "Escape") {
																	e.preventDefault();
																	setNoteEditingId(null);
																	setNoteDraft("");
																}
															}}
															maxLength={MAX_SEALED_NOTE_CHARS}
															placeholder="e.g. Contract for Alice — emailed 9/23"
															aria-label="Vault entry note"
															className="h-8 min-w-0 flex-1 bg-background text-xs dark:bg-input/20"
															autoFocus
														/>
														<Button
															variant="outline"
															size="sm"
															onClick={() => handleSaveNote(entry.id)}
															className="h-8 px-2.5 text-xs"
														>
															Save
														</Button>
														<Button
															variant="ghost"
															size="sm"
															onClick={() => {
																setNoteEditingId(null);
																setNoteDraft("");
															}}
															className="h-8 px-2.5 text-xs"
														>
															Cancel
														</Button>
													</span>
												)}
												{/* min-w-0 + flex-wrap (was shrink-0 nowrap): with two new per-row
                                                                                    actions the group must wrap at narrow widths — nowrap plus the
                                                                                    section's overflow-hidden silently clipped the trailing
                                                                                    txt/remove buttons at 390 px. */}
												<span className="flex min-w-0 flex-wrap items-center justify-end gap-1">
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
																signer: entry.signer,
																signerFp: entry.signerFp,
																files: entry.files,
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
													<Button
														variant="ghost"
														size="sm"
														onClick={() =>
															onOpenInDecrypt?.({
																armor: entry.sealedArmor ?? entry.armor,
																seq: Date.now(),
															})
														}
														title={
															healthMap[entry.id] === "ok"
																? "Verified decryptable by the last health check, so this is one click to plaintext."
																: "Opens this sealed output in the Decrypt tab — auto-decrypts with your key."
														}
														className="h-7 gap-1.5 px-2 text-xs text-[#0055dc] hover:bg-[#0055dc]/8 hover:text-[#0055dc] dark:text-[#5e94ff] dark:hover:bg-[#5e94ff]/10"
													>
														<ArrowRight aria-hidden="true" className="size-3.5" />
														{healthMap[entry.id] === "ok" && (
															// Emerald glow-dot (round 19): this entry passed the last
															// health check, so the deep-link is one click to plaintext.
															<span
																aria-hidden="true"
																className="size-1.5 rounded-full bg-emerald-500 shadow-[0_0_4px] shadow-emerald-500/60"
															/>
														)}
														<span className="whitespace-nowrap">Open in Decrypt</span>
													</Button>
													<CopyButton
														text={entry.armor}
														label="Copy"
														ariaLabel="Copy sealed output to clipboard"
													/>
													{entry.sealedArmor && (
														<SealedCopyButton sealedArmor={entry.sealedArmor} />
													)}
													<DownloadButton text={entry.armor} title="sealed output" />
													<Button
														variant="ghost"
														size="icon"
														onClick={() => {
															setNoteEditingId(noteEditingId === entry.id ? null : entry.id);
															setNoteDraft(entry.note ?? "");
														}}
														aria-label={
															entry.note
																? `Edit the note on this entry: ${entry.note}`
																: "Add a note to this vault entry"
														}
														title={entry.note ? "Edit note" : "Add note"}
														className={`size-7 ${
															noteEditingId === entry.id
																? "text-amber-600 dark:text-amber-400"
																: "text-muted-foreground hover:text-amber-600 dark:hover:text-amber-400"
														}`}
													>
														<Pencil aria-hidden="true" className="size-3.5" />
													</Button>
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
										))
									)}
								</ul>
								<p className="border-t border-border bg-muted/25 px-4 py-2 text-[11px] text-muted-foreground">
									Ciphertext only, kept in this browser (last {MAX_SEALED_ENTRIES}). Plaintext is
									never stored — Restore puts the armor back in the output box above, Open in
									Decrypt re-opens it directly, and the violet button copies the quantum-sealed copy
									when the entry has one. Health check tries every entry with your unlocked key
									(verdict chips appear per row), the pencil annotates an entry with a private local
									note that travels with exported manifests, Export downloads the whole vault as a
									ciphertext-only JSON manifest, and Import merges (or replaces) it back — reviewed
									in a dialog first. Dragging a manifest file onto the vault card opens the same
									reviewed import.
								</p>
							</>
						)}
					</CollapsibleContent>
				</Collapsible>
				{/* Round 19: violet manifest-dropzone overlay - while a Files drag
                                    hovers the vault card (vaultDragDepth > 0) the whole section
                                    lights up with the dashed violet target, carrying the same
                                    FileUp motif as the Import buttons. pointer-events-none keeps
                                    the drag itself untouched. */}
				{vaultDragDepth > 0 && (
					<div
						aria-hidden
						className="pointer-events-none absolute inset-0 z-20 flex items-center justify-center rounded-xl border-2 border-dashed border-violet-500/60 bg-violet-500/5 animate-fade-up"
					>
						<span className="inline-flex items-center gap-1.5 rounded-lg bg-background/95 px-3 py-1.5 text-xs font-medium text-violet-600 shadow-sm dark:text-violet-400">
							<FileUp aria-hidden="true" className="size-3.5" />
							Drop a vault manifest to import
						</span>
					</div>
				)}
			</section>
			{/* Hidden manifest picker (round 18): mounted at SECTION level —
                            outside the CollapsibleContent — so collapsing the vault can't
                            unmount it mid-pick. Re-armed after every read so picking the
                            same file twice re-fires onChange. */}
			<input
				ref={vaultImportInputRef}
				type="file"
				accept="application/json,.json"
				className="hidden"
				tabIndex={-1}
				aria-hidden="true"
				onChange={(e) => {
					const file = e.target.files?.[0];
					e.target.value = "";
					void handleVaultImportFile(file);
				}}
			/>

			{/* Vault manifest import review (round 18) — a pure confirm dialog;
                            Escape / outside click route through onOpenChange(false) = cancel. */}
			<VaultImportDialog
				open={pendingImport !== null}
				onOpenChange={(next) => {
					if (!next) setPendingImport(null);
				}}
				entryCount={pendingImport?.entries.length ?? 0}
				vaultCount={sealedHistory.length}
				skippedRows={pendingImport?.skipped ?? 0}
				signedCount={pendingImport?.entries.filter((en) => en.signer).length ?? 0}
				quantumCount={pendingImport?.entries.filter((en) => en.pqSealed).length ?? 0}
				filesCount={pendingImport?.entries.reduce((sum, en) => sum + (en.files ?? 0), 0) ?? 0}
				annotatedCount={pendingImport?.entries.filter((en) => en.note).length ?? 0}
				notes={
					pendingImport?.entries
						.filter((en): en is typeof en & { note: string } => typeof en.note === "string")
						.map((en) => ({ at: en.at, note: en.note })) ?? []
				}
				exportedAt={pendingImport?.exportedAt}
				onMerge={() => runVaultImport("merge")}
				onReplace={() => runVaultImport("replace")}
			/>
		</section>
	);
}

/**
 * Grouped fingerprint display for the seal provenance tooltips (round 16):
 * hex digits only (already-sanitized values pass through untouched), cut
 * into runs of `group` (default 4) joined by spaces and UPPERCASED for
 * display — exactly the grouping the key-details panel shows. Pure
 * formatting, no state.
 */
function formatFingerprint(fp: string, group = 4): string {
	const hex = (fp || "").replace(/[^0-9a-fA-F]/g, "");
	if (!hex) return "";
	const chunks: string[] = [];
	for (let i = 0; i < hex.length; i += group) {
		chunks.push(hex.slice(i, i + group));
	}
	return chunks.join(" ").toUpperCase();
}

/**
 * Exact clock time for a sealed-history row: same clock-face for today
 * ("14:32"), a day label otherwise ("Sep 12 · 14:32"). Since round 14 it
 * backs the row time element's native title tooltip while the visible
 * label is the coarse relative time (formatRelativeHistoryTime). Pure
 * formatting — no state, no effects.
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

/**
 * Relative timestamp for a sealed-history row (round 14): "just now" /
 * "N min ago" / "N h ago", falling back to the absolute locale string
 * past 24 h. The exact clock time (formatHistoryTime) moves into the
 * row's native title tooltip. Pure formatting — no state, no effects;
 * rows re-render on the next vault interaction, plenty precise for a
 * coarse "N min ago" label.
 */
function formatRelativeHistoryTime(at: number): string {
	const d = new Date(at);
	if (Number.isNaN(d.getTime())) return "";
	const elapsed = Date.now() - d.getTime();
	// Future timestamps (clock skew) read saner as absolute strings.
	if (elapsed < 0) return formatHistoryTime(at);
	const minutes = Math.floor(elapsed / 60000);
	if (minutes < 1) return "just now";
	if (minutes < 60) return `${minutes} min ago`;
	const hours = Math.floor(minutes / 60);
	if (hours < 24) return `${hours} h ago`;
	return new Intl.DateTimeFormat(undefined, {
		hour: "2-digit",
		minute: "2-digit",
		month: "short",
		day: "numeric",
		hour12: false,
	}).format(d);
}

/**
 * Per-row "Copy quantum-sealed copy" button (round 14): an icon-only
 * violet action for entries that carry an ML-KEM-768 sealed copy —
 * distinct from the classical armor the regular Copy button handles.
 * The icon swaps Copy → Check for ~1.6 s after a successful copy and
 * the toast names WHAT was copied, so the two copy actions never read
 * the same.
 */
function SealedCopyButton({ sealedArmor }: { sealedArmor: string }) {
	const [copied, setCopied] = useState(false);
	const checkTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
	const { toast } = useToast();

	// Clear the pending icon-swap timer on unmount.
	useEffect(() => {
		return () => {
			if (checkTimerRef.current) clearTimeout(checkTimerRef.current);
		};
	}, []);

	return (
		<Button
			type="button"
			variant="ghost"
			size="icon"
			onClick={async () => {
				try {
					await navigator.clipboard.writeText(sealedArmor);
					setCopied(true);
					if (checkTimerRef.current) clearTimeout(checkTimerRef.current);
					checkTimerRef.current = setTimeout(() => setCopied(false), 1600);
					toast({
						title: "Quantum-sealed copy copied to clipboard",
						description:
							"The ML-KEM-768 sealed armor is on your clipboard — it unwraps on this device without the recipient's passphrase.",
					});
				} catch (e) {
					toast({
						title: "Copy failed",
						description: (e as Error)?.message || "Clipboard unavailable",
						variant: "destructive",
					});
				}
			}}
			title="Copy quantum-sealed copy"
			aria-label="Copy quantum-sealed copy"
			className="size-7 text-violet-600 hover:bg-violet-500/10 hover:text-violet-700 dark:text-violet-400 dark:hover:bg-violet-400/10 dark:hover:text-violet-300"
		>
			{copied ? (
				<Check aria-hidden="true" className="size-3.5 text-emerald-600 dark:text-emerald-400" />
			) : (
				<Copy aria-hidden="true" className="size-3.5" />
			)}
		</Button>
	);
}

/**
 * Per-row health-check verdict chip (round 17): emerald "decrypts" when
 * the entry opened with the user's key, zinc "not yours" when the PKESK
 * headers showed it was sealed to other recipients only (expected
 * non-decryptable, no decryption attempted), red "failed" when decryption
 * genuinely failed, and an amber spinner while the entry is being tried.
 * Undefined verdict → nothing renders (not checked yet). Runtime-only
 * state — the parent wipes verdicts on every vault mutation.
 */
function HealthVerdictChip({ verdict }: { verdict: VaultHealthVerdict | undefined }) {
	if (!verdict) return null;
	if (verdict === "running") {
		return (
			<span
				role="status"
				aria-label="Checking this entry"
				className="inline-flex items-center rounded-full bg-amber-500/10 px-2 py-0.5 text-amber-600 dark:text-amber-400"
			>
				<Loader2 aria-hidden="true" className="size-3 animate-spin" />
			</span>
		);
	}
	if (verdict === "ok") {
		return (
			<span
				title="Opened with your key during the last health check."
				className="inline-flex cursor-help items-center gap-1 rounded-full border border-emerald-500/30 bg-emerald-500/10 px-2 py-0.5 text-[10px] font-medium text-emerald-600 dark:text-emerald-500"
			>
				<ShieldCheck aria-hidden="true" className="size-3" />
				decrypts
			</span>
		);
	}
	if (verdict === "not-mine") {
		return (
			<span
				title="Sealed to other recipients only — expected not to open with your key."
				className="inline-flex cursor-help items-center gap-1 rounded-full bg-zinc-500/10 px-2 py-0.5 text-[10px] font-medium text-zinc-600 dark:text-zinc-400"
			>
				<CircleSlash aria-hidden="true" className="size-3" />
				not yours
			</span>
		);
	}
	return (
		<span
			title="Failed to decrypt with your key — the ciphertext may be damaged or the key has changed."
			className="inline-flex cursor-help items-center gap-1 rounded-full border border-red-500/30 bg-red-500/10 px-2 py-0.5 text-[10px] font-medium text-red-600 dark:text-red-500"
		>
			<ShieldX aria-hidden="true" className="size-3" />
			failed
		</span>
	);
}

/**
 * Filename for the vault manifest export (round 17): LOCAL time, zero-
 * padded — encryptor-vault-manifest-YYYYMMDD-HHmm.json. Pure formatting.
 */
function vaultManifestFilename(now = new Date()): string {
	const pad2 = (n: number) => String(n).padStart(2, "0");
	return `encryptor-vault-manifest-${now.getFullYear()}${pad2(now.getMonth() + 1)}${pad2(now.getDate())}-${pad2(now.getHours())}${pad2(now.getMinutes())}.json`;
}

/**
 * Sanitized composer filename for a dropped image (round 18): the editor
 * hands over the file's REAL name. Take only the last path segment,
 * strip control characters by CODEPOINT FILTER (Array.from — a
 * control-CLASS regex is rejected by oxlint's no-control-regex), strip
 * the filesystem-hostile <>:"|?* set, cap at 64 chars, and infer the
 * extension from the data URL's mime when the name carries none. Falls
 * back to the classic pasted-image.<ext> when nothing usable survives.
 * Pure — no state.
 */
function sanitizeDroppedImageName(raw: string | undefined, ext: string): string {
	const fallback = `pasted-image.${ext}`;
	if (!raw) return fallback;
	const base = raw.split(/[\\/]/).pop() ?? "";
	const cleaned = Array.from(base)
		.filter((ch) => {
			const code = ch.codePointAt(0) ?? 0;
			return code >= 0x20 && code !== 0x7f;
		})
		.join("")
		.replace(/[<>:"|?*]/g, "")
		.trim()
		.slice(0, 64);
	if (cleaned === "") return fallback;
	return /\.[a-z0-9]{1,8}$/i.test(cleaned) ? cleaned : `${cleaned}.${ext}`;
}
