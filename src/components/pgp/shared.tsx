"use client";

/**
 * Shared PGP UI building blocks.
 *
 * Logic, strings, and defaults are ported verbatim from the original app
 * (src/components/pgp/PgpApp.tsx in the audit tree) — only the styling is
 * modernized (shadcn/ui + #0055dc accent, 150–200ms transitions, a11y).
 */
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
	BadgeCheck,
	Check,
	ChevronLeft,
	ChevronRight,
	Copy,
	FileSignature,
	FileText,
	Lock,
	X,
} from "lucide-react";
import Markdown from "react-markdown";
import remarkGfm from "remark-gfm";
import remarkBreaks from "remark-breaks";
import { toast } from "@/hooks/use-toast";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogTitle } from "@/components/ui/dialog";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import {
	envelopeFileToDataUrl,
	formatFileSize,
	isLocalImageUrl,
	isSafeImageUrl,
	SAFE_DATA_IMAGE_RE,
	type EnvelopeFile,
} from "@/lib/pgp/envelope";
import { parseInlineImageAlt } from "@/lib/pgp/inline-image";
import { formatTimestamp } from "@/lib/pgp/signer-info";
import { getKeyExpiryStatus } from "@/lib/pgp/key-details";
import {
	base64ToUint8Array,
	buildZipBundle,
	downloadBlob,
	zipFilename,
} from "@/lib/pgp/zip-bundle";
import type { KeySource, SignatureInfo, VerificationResult } from "@/components/pgp/contracts";

/* Accent helpers (design brief: #0055dc, hover #0046b8, dark text #5e94ff). */
const ACCENT_TEXT = "text-[#0055dc] dark:text-[#5e94ff]";

/* ------------------------- Key source + hash labels ------------------------- */
// # Mr. AI Acting on s183173's Behalf
// Signature cards (Verify tab + Decrypt tab's "Signed by") must say WHERE
// the signer's public key came from and what the key ID / fingerprint hex
// strings actually mean — without any format talk or filler captions.

/** Human label for each key-lookup source, keyed by contracts.KeySource. */
const KEY_SOURCE_LABELS: Readonly<Record<KeySource, string>> = {
	local: "key from your configured key",
	keybase: "key from Keybase",
	"openpgp.org": "key from keys.openpgp.org",
	encryptor: "key from the Encryptor Registry",
};

/** Small muted pill naming where the signer's public key was resolved from.
 *  Renders nothing when the source is unknown (verification didn't run). */
export function KeySourcePill({ source }: { source: KeySource | undefined }) {
	if (!source) return null;
	return (
		<span className="inline-flex shrink-0 items-center rounded-full bg-muted px-2 py-0.5 text-[10px] font-medium text-muted-foreground">
			{KEY_SOURCE_LABELS[source]}
		</span>
	);
}

/** One-line legend explaining the key ID + fingerprint hex strings shown on
 *  signature results ("what do the random hashes mean?"). Rendered once per
 *  results card, under the signature list. */
export function SignerHashLegend() {
	return (
		<p className="mt-2 border-t border-border pt-2 text-[10px] leading-snug text-muted-foreground">
			<span className="font-medium">Key ID</span> — short ID of the signing key.{" "}
			<span className="font-medium">Fingerprint</span> — the key's unique 40-character identity.
		</p>
	);
}

/* -------------------------------- ImageViewer ------------------------------- */

/** Full-size image viewer (lightbox) for attachments. Opens from the file
 *  name / thumbnail clicks in FileDownloadList — never from the download
 *  button, which keeps its plain download behavior. */
export function ImageViewer({
	images,
	index,
	onIndexChange,
	onClose,
}: {
	/** All image attachments (viewer navigates within this list). */
	images: EnvelopeFile[];
	/** Currently viewed index, or null when closed. */
	index: number | null;
	onIndexChange: (next: number) => void;
	onClose: () => void;
}) {
	const open = index !== null && images.length > 0;
	const file = open ? images[Math.min(index, images.length - 1)] : null;
	const rawViewerSrc = file && file.type.startsWith("image/") ? envelopeFileToDataUrl(file) : null;
	// Barrier guard for static analysis: the same tainted string that
	// reaches <img src> is regex-tested right here.
	const safeSrc =
		rawViewerSrc !== null &&
		SAFE_DATA_IMAGE_RE.test(rawViewerSrc) &&
		isSafeImageUrl(rawViewerSrc) !== null
			? rawViewerSrc
			: null;
	const many = images.length > 1;
	const go = useCallback(
		(delta: number) => {
			if (index === null || images.length === 0) return;
			onIndexChange((index + delta + images.length) % images.length);
		},
		[index, images.length, onIndexChange],
	);

	// Arrow-key navigation while the viewer is open (dialog keeps focus, so a
	// window listener scoped to `open` is enough).
	useEffect(() => {
		if (!open || !many) return;
		const onKey = (e: KeyboardEvent) => {
			if (e.key === "ArrowLeft") {
				e.preventDefault();
				go(-1);
			} else if (e.key === "ArrowRight") {
				e.preventDefault();
				go(1);
			}
		};
		window.addEventListener("keydown", onKey);
		return () => window.removeEventListener("keydown", onKey);
	}, [open, many, go]);

	return (
		<Dialog open={open} onOpenChange={(o) => !o && onClose()}>
			<DialogContent className="max-w-3xl p-0 overflow-hidden" aria-describedby={undefined}>
				<DialogTitle className="sr-only">
					{file ? `Viewing ${file.name}` : "Image viewer"}
				</DialogTitle>
				{file && safeSrc && (
					<figure className="relative space-y-0">
						<div className="flex max-h-[70vh] items-center justify-center overflow-auto bg-muted/40 p-2">
							{}
							<img
								src={safeSrc}
								alt={file.name}
								className="max-h-[68vh] w-auto max-w-full rounded object-contain"
							/>
						</div>
						{many && (
							<>
								<button
									type="button"
									onClick={() => go(-1)}
									aria-label="Previous image"
									title="Previous (←)"
									className="absolute left-2 top-1/2 grid size-9 -translate-y-1/2 place-items-center rounded-full border bg-background/90 text-foreground shadow-sm backdrop-blur transition-colors hover:bg-muted"
								>
									<ChevronLeft className="size-4" aria-hidden />
								</button>
								<button
									type="button"
									onClick={() => go(1)}
									aria-label="Next image"
									title="Next (→)"
									className="absolute right-2 top-1/2 grid size-9 -translate-y-1/2 place-items-center rounded-full border bg-background/90 text-foreground shadow-sm backdrop-blur transition-colors hover:bg-muted"
								>
									<ChevronRight className="size-4" aria-hidden />
								</button>
							</>
						)}
						<figcaption className="flex items-center gap-2 border-t border-border bg-background px-3 py-2">
							<span className="truncate text-xs font-medium">{file.name}</span>
							<span className="shrink-0 text-[11px] text-muted-foreground">
								{formatFileSize(file.size)}
							</span>
							{many && (
								<span className="shrink-0 text-[11px] tabular-nums text-muted-foreground">
									{Math.min(index ?? 0, images.length - 1) + 1} / {images.length}
								</span>
							)}
							<Button
								type="button"
								variant="ghost"
								size="icon"
								onClick={onClose}
								className="ml-auto size-7 text-muted-foreground"
								aria-label="Close image viewer"
							>
								<X className="size-4" aria-hidden />
							</Button>
						</figcaption>
					</figure>
				)}
			</DialogContent>
		</Dialog>
	);
}

/* -------------------------------- ErrorBanner ------------------------------- */

/** Destructive-tinted error panel. Renders nothing when there is no message. */
export function ErrorBanner({ message }: { message: string | null | undefined }) {
	if (!message) return null;
	return (
		<div
			role="alert"
			className="rounded-lg border border-destructive/30 bg-destructive/10 px-3 py-2 text-xs text-red-700 dark:text-red-400"
		>
			{message}
		</div>
	);
}

/* -------------------------------- CopyButton -------------------------------- */

/** Clipboard write with "Copy" → "Copied!" feedback for 1500ms. The leading
 *  icon swaps Copy → Check (emerald tint) for ~1.6s after a successful copy
 *  (timer cleared on unmount / re-copy). Success and failure are additionally
 *  surfaced as toasts (additive; the button label and timing behavior are
 *  unchanged from the original). */
export function CopyButton({
	text,
	label = "Copy",
	ariaLabel = "Copy output to clipboard",
}: {
	/** The string to copy. */
	text: string;
	/** Visible button label (defaults to "Copy", as in the original). */
	label?: string;
	/** Accessible name (defaults to the original "Copy output to clipboard"). */
	ariaLabel?: string;
}) {
	const [copied, setCopied] = useState(false);
	const [showCheck, setShowCheck] = useState(false);
	const checkTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

	// Clear the pending icon-swap timer on unmount.
	useEffect(() => {
		return () => {
			if (checkTimerRef.current) clearTimeout(checkTimerRef.current);
		};
	}, []);

	return (
		<Button
			type="button"
			variant="outline"
			size="sm"
			onClick={async () => {
				try {
					await navigator.clipboard.writeText(text);
					setCopied(true);
					setTimeout(() => setCopied(false), 1500);
					setShowCheck(true);
					if (checkTimerRef.current) clearTimeout(checkTimerRef.current);
					checkTimerRef.current = setTimeout(() => setShowCheck(false), 1600);
					toast({ title: "Copied to clipboard" });
				} catch (e) {
					toast({
						title: "Copy failed",
						description: (e as Error)?.message || "Clipboard unavailable",
						variant: "destructive",
					});
				}
			}}
			className="h-11 gap-1.5 px-3 text-xs transition-colors sm:h-8"
			title="Copy to clipboard"
			aria-label={ariaLabel}
		>
			{showCheck ? (
				<Check aria-hidden="true" className="size-3.5 text-emerald-600 dark:text-emerald-400" />
			) : (
				<Copy aria-hidden="true" className="size-3.5" />
			)}
			{copied ? "Copied!" : label}
		</Button>
	);
}

/* ----------------------------- ZipDownloadButton ---------------------------- */

/** Button that bundles the output + files + metadata into a ZIP download.
 *  jszip is loaded dynamically by buildZipBundle so it doesn't bloat the
 *  initial client bundle. */
export function ZipDownloadButton({
	files,
	operation,
	output,
	signers,
	verificationResult,
	fileCount,
}: {
	files: EnvelopeFile[];
	operation: string;
	output?: string;
	signers?: SignatureInfo[];
	/** Accepts the structured VerificationResult or a plain status string;
	 *  metadata.json always stores the string form (same shape as the original). */
	verificationResult?: VerificationResult | string;
	fileCount?: number;
}) {
	const [busy, setBusy] = useState(false);
	const [error, setError] = useState<string | null>(null);

	const handleDownload = useCallback(async () => {
		setError(null);
		setBusy(true);
		try {
			// Convert EnvelopeFile[] (base64 data) to ZipFileEntry[] (Uint8Array).
			const entries = files.map((f) => ({
				name: f.name,
				data: base64ToUint8Array(f.data),
			}));
			const blob = await buildZipBundle(entries, {
				operation,
				generatedAt: new Date().toISOString(),
				output,
				signers,
				verificationResult:
					typeof verificationResult === "string"
						? verificationResult
						: verificationResult?.verified,
				fileCount: fileCount ?? entries.length,
			});
			const filename = zipFilename(operation);
			downloadBlob(blob, filename);
			toast({
				title: "ZIP downloaded",
				description: `${filename}${entries.length > 0 ? ` · ${entries.length} file${entries.length === 1 ? "" : "s"}` : ""}`,
			});
		} catch (e) {
			setError((e as Error).message);
		} finally {
			setBusy(false);
		}
	}, [files, operation, output, signers, verificationResult, fileCount]);

	return (
		<div className="flex items-center gap-2">
			{error && <span className="text-[10px] text-red-600 dark:text-red-400">{error}</span>}
			<Button
				type="button"
				variant="outline"
				size="sm"
				onClick={handleDownload}
				disabled={busy}
				className="h-11 gap-1 px-3 text-xs transition-colors sm:h-8"
				title="Download the output + attachments + metadata as a ZIP file"
				aria-label="Download output as a ZIP file"
			>
				{busy ? "Zipping…" : "⬇ ZIP"}
			</Button>
		</div>
	);
}

/* --------------------------- Output title status icon ----------------------- */

/** Small status icon for an output block, derived purely from the title
 *  string (pure function, no props API): Lock for encrypted outputs,
 *  FileSignature for signature/signed outputs, FileText for decrypted text,
 *  BadgeCheck as fallback. "decrypted" is checked first so a decrypted-
 *  message title always maps to FileText. Returns a ready-to-render
 *  aria-hidden element (NOT a component) so callers can inline it without
 *  creating a component during render (react-hooks/static-components). */
function outputStatusIcon(title: string) {
	const cls = "size-3.5 shrink-0 text-[#0055dc] dark:text-[#5e94ff]";
	const t = title.toLowerCase();
	if (t.includes("decrypted")) return <FileText className={cls} aria-hidden="true" />;
	if (t.includes("encrypted")) return <Lock className={cls} aria-hidden="true" />;
	if (t.includes("signature") || t.includes("signed"))
		return <FileSignature className={cls} aria-hidden="true" />;
	return <BadgeCheck className={cls} aria-hidden="true" />;
}

/* ------------------------------ DownloadButton ------------------------------ */

/** Derive a text-file filename from an output title: lowercase,
 *  non-alphanumeric runs → "-", trimmed, + ".txt"
 *  (e.g. "Encrypted + signed message" → "encrypted-signed-message.txt"). */
function outputTitleToFilename(title: string): string {
	const slug = title
		.toLowerCase()
		.replace(/[^a-z0-9]+/g, "-")
		.replace(/^-+|-+$/g, "");
	return `${slug || "output"}.txt`;
}

/** Small ghost button that downloads the output text as a .txt file.
 *  Additive next to Copy/ZIP in the output actions row; builds a
 *  text/plain Blob client-side and reuses downloadBlob from zip-bundle.
 *  Exported for secondary-output rows (e.g. the quantum-sealed copy). */
export function DownloadButton({ text, title }: { text: string; title: string }) {
	const handleDownload = useCallback(() => {
		try {
			const blob = new Blob([text], { type: "text/plain;charset=utf-8" });
			downloadBlob(blob, outputTitleToFilename(title));
			toast({ title: "Text file downloaded" });
		} catch (e) {
			toast({
				title: "Download failed",
				description: (e as Error)?.message || "Download unavailable",
				variant: "destructive",
			});
		}
	}, [text, title]);

	return (
		<Button
			type="button"
			variant="outline"
			size="sm"
			onClick={handleDownload}
			className="h-11 gap-1 px-3 text-xs transition-colors sm:h-8"
			title="Download output as a text file"
			aria-label="Download output as a text file"
		>
			⬇ .txt
		</Button>
	);
}

/* -------------------------------- OutputBlock ------------------------------- */

/** Output section: rendered preview / raw text toggle, ZIP + copy actions,
 *  nuke-input panel, and a "Start over" reset. */
export function OutputBlock({
	title,
	output,
	files,
	preview,
	onNuke,
	nukeLabel,
	onReset,
	signers,
	verificationResult,
	operation,
	inputBytes,
}: {
	title: string;
	output: string;
	/** When provided, renders a ZIP download button bundling output + files +
	 *  metadata (pass [] for a metadata-only bundle). */
	files?: EnvelopeFile[];
	/** When provided, shows a rendered preview of the message (with inline
	 *  images) as the primary view. A small toggle switches to the raw
	 *  `output` text. Copy/ZIP always act on `output`.
	 *  Accepts either a plain string (the envelope plaintext — inline images
	 *  are resolved against the top-level `files`) or an object of the shape
	 *  `{ text?/plaintext?, files? }`. */
	preview?: string | { text?: string; plaintext?: string; files?: EnvelopeFile[] };
	onNuke?: () => void;
	nukeLabel?: string;
	onReset: () => void;
	signers?: SignatureInfo[];
	verificationResult?: VerificationResult | string;
	/** Operation tag used for the ZIP filename + metadata (e.g. "encrypt",
	 *  "decrypt", "sign-cleartext"). Defaults to "output". */
	operation?: string;
	/** Approximate INPUT byte size (message + attachments). When the armored
	 *  output is smaller, the stats line gains a quiet "N% smaller" savings
	 *  marker — an honest at-a-glance signal that compression did work. */
	inputBytes?: number;
}) {
	const [showRaw, setShowRaw] = useState(false);
	const [nuked, setNuked] = useState(false);

	// Re-arm the nuke panel whenever a new output is produced — done via the
	// render-time state adjustment pattern (no effect needed).
	const [prevOutput, setPrevOutput] = useState(output);
	if (prevOutput !== output) {
		setPrevOutput(output);
		setNuked(false);
	}

	const previewText =
		typeof preview === "string" ? preview : (preview?.text ?? preview?.plaintext ?? "");
	const previewFiles =
		typeof preview === "string" ? (files ?? []) : (preview?.files ?? files ?? []);

	// Small status icon in the title row, derived from the title string only.
	const statusIcon = outputStatusIcon(title);

	return (
		<div className={output ? "animate-scale-in glow-accent space-y-3" : "space-y-3"}>
			{/* result-enter: one-time success ring when the output block first
            appears (mounts once per operation — the tabs clear output before
            each run, so re-runs replay it; showRaw toggles do not remount
            this wrapper). Reduced-motion gated in globals.css. */}
			<div className="result-enter">
				{/* R10: screen-reader announcement when the output first appears —
            the visual section header is aria-hidden, so live-region text is
            the only reliable cue that the operation finished. */}
				{output && (
					<span role="status" className="sr-only">
						{title} ready
					</span>
				)}
				<div className="mb-1 flex items-center justify-between gap-2">
					<span className="flex items-center gap-2">
						{statusIcon}
						<span
							aria-hidden
							className="h-3.5 w-[3px] shrink-0 rounded-full bg-[#0055dc] dark:bg-[#5e94ff]"
						/>
						{/* Section-label family (R11-b): the tab input cards and the
		Decrypt-tab result rows both render their Label as
		text-xs uppercase tracking-wide muted — the OutputBlock title
		is the same kind of section label, so it joins the family. */}
						<Label className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
							{title}
						</Label>
						{/* R8: armor stats — quiet mono detail next to the section label.
		Armor is ASCII so string length ≈ byte length; lines from the
		raw split. Hidden on the smallest screens to keep the row
		uncluttered. */}
						{output && (
							<span
								aria-hidden="true"
								className="ml-0.5 hidden font-mono text-[10px] font-normal normal-case tracking-normal text-muted-foreground sm:inline"
							>
								{output.split("\n").length.toLocaleString()} lines ·{" "}
								{(output.length / 1024).toFixed(1)} KB
								{/* Savings marker (R10): only when the caller reports the
                    input size and the armored output actually came out
                    smaller (small messages with per-recipient overhead stay
                    silent instead of showing a confusing negative). */}
								{inputBytes !== undefined && output.length < inputBytes && (
									<span
										className="font-medium text-emerald-600 dark:text-emerald-400"
										title="Armored output is smaller than the input — compression did the work"
									>
										{" "}
										· {Math.max(1, Math.round((1 - output.length / inputBytes) * 100))}% smaller
									</span>
								)}
							</span>
						)}
					</span>
					{preview && (
						<button
							type="button"
							onClick={() => setShowRaw((v) => !v)}
							className="inline-flex min-h-11 items-center text-[10px] text-muted-foreground underline-offset-2 transition-colors hover:text-foreground hover:underline sm:min-h-0"
							title="Toggle between rendered preview and raw text (advanced)"
						>
							{showRaw ? "Show preview" : "Show raw text"}
						</button>
					)}
				</div>
				{preview && !showRaw ? (
					// bg-card (R11-b): this pane floats directly on the page background
					// (tabs render OutputBlock outside any card), so in dark mode it must
					// use the elevated card token like every sibling preview pane
					// (Decrypt-tab preview, SignerBadges) — light mode is unchanged
					// (#ffffff == #ffffff).
					<div className="min-h-[100px] rounded-xl border bg-card px-3.5 py-3 shadow-sm">
						<DecryptedMessageView text={previewText} files={previewFiles} />
					</div>
				) : (
					<Textarea
						value={output}
						readOnly
						rows={12}
						className="field-sizing-fixed bg-muted/40 font-mono"
						aria-label={title}
					/>
				)}
				<div className="mt-2 flex justify-end gap-2">
					{operation && (
						<ZipDownloadButton
							files={files ?? []}
							operation={operation}
							output={output}
							signers={signers}
							verificationResult={verificationResult}
						/>
					)}
					<DownloadButton text={output} title={title} />
					<CopyButton text={output} />
				</div>
			</div>

			{onNuke && (
				<div className="rounded-xl border border-amber-200 bg-amber-50 px-3 py-2.5 shadow-sm dark:border-amber-900/60 dark:bg-amber-950/30">
					{!nuked ? (
						<div className="flex flex-col justify-between gap-2.5 sm:flex-row sm:items-center">
							<p className="text-xs text-amber-800 dark:text-amber-300">
								Your input is still in memory. Nuke it now to make sure only the output remains.
							</p>
							<Button
								type="button"
								onClick={() => {
									onNuke();
									setNuked(true);
								}}
								className="h-11 shrink-0 bg-amber-700 px-3 text-xs font-medium text-white transition-colors hover:bg-amber-800 sm:h-8 dark:bg-amber-500 dark:text-amber-950 dark:hover:bg-amber-400"
							>
								{nukeLabel ?? "Nuke input"}
							</Button>
						</div>
					) : (
						<p className="text-xs text-emerald-700 dark:text-emerald-400">
							✓ Input nuked. Only the output remains in memory.
						</p>
					)}
				</div>
			)}

			<div className="flex gap-2">
				<Button type="button" variant="ghost" onClick={onReset} className="h-11 text-sm sm:h-9">
					Start over
				</Button>
			</div>
		</div>
	);
}

/* ------------------------------ InputSizeCounter ---------------------------- */

/** Right-aligned char/word/KB counter under composer inputs (Encrypt + Sign
 *  tabs share it). aria-live off on purpose — announcing every keystroke
 *  would be noisy for screen readers. */
export function InputSizeCounter({ text }: { text: string }) {
	const trimmed = text.trim();
	const words = trimmed ? trimmed.split(/\s+/).length : 0;
	return (
		<div aria-live="off" className="mt-1 text-right text-[10px] text-muted-foreground">
			{text.length.toLocaleString()} chars
			{words > 0 && ` · ${words.toLocaleString()} ${words === 1 ? "word" : "words"}`}
			{text.length > 0 && ` · ~${(text.length / 1024).toFixed(1)} KB`}
		</div>
	);
}

/* ------------------------------ AttachmentList ------------------------------ */

/** Render the list of files attached to an outgoing encrypted message.
 *  Owns the hidden multi-file input; its value is reset after each change so
 *  selecting the same file again still fires onChange. */
export function AttachmentList({
	attachments,
	onAddFiles,
	onRemove,
}: {
	attachments: EnvelopeFile[];
	onAddFiles: (files: FileList | null) => void;
	onRemove: (index: number) => void;
}) {
	const fileInputRef = useRef<HTMLInputElement>(null);

	return (
		<div className="space-y-2">
			<div className="flex flex-wrap items-center gap-2">
				<Button
					type="button"
					variant="outline"
					onClick={() => fileInputRef.current?.click()}
					className="h-11 text-sm sm:h-9"
				>
					+ Add files
				</Button>
				{attachments.length > 0 && (
					<span className="text-[11px] text-muted-foreground">
						{attachments.length} file{attachments.length === 1 ? "" : "s"} ·{" "}
						{formatFileSize(attachments.reduce((sum, f) => sum + f.size, 0))}
					</span>
				)}
			</div>
			{attachments.length > 0 && (
				<ul className="flex flex-wrap gap-2">
					{attachments.map((f, idx) => {
						const isImage = f.type.startsWith("image/");
						const rawPreview = isImage ? envelopeFileToDataUrl(f) : null;
						const previewUrl =
							rawPreview !== null &&
							SAFE_DATA_IMAGE_RE.test(rawPreview) &&
							isSafeImageUrl(rawPreview) !== null
								? rawPreview
								: null;
						return (
							<li
								key={`${f.name}-${idx}`}
								className="relative flex items-center gap-2 rounded-lg border bg-background py-1.5 pl-2 pr-7 text-xs shadow-xs transition-shadow hover:shadow-sm"
								title={f.name}
							>
								{previewUrl ? (
									<img src={previewUrl} alt="" className="size-6 rounded-md object-cover" />
								) : (
									<div className="grid size-6 place-items-center rounded-md bg-muted text-[10px] font-medium text-muted-foreground">
										{f.name.split(".").pop()?.toUpperCase().slice(0, 4) || "FILE"}
									</div>
								)}
								<div className="min-w-0 max-w-[180px]">
									<div className="truncate font-medium">{f.name}</div>
									<div className="text-[10px] text-muted-foreground">{formatFileSize(f.size)}</div>
								</div>
								<button
									type="button"
									onClick={() => onRemove(idx)}
									className="absolute right-1 top-1/2 grid size-6 -translate-y-1/2 place-items-center rounded-full text-base leading-none text-muted-foreground transition-colors hover:bg-destructive/10 hover:text-destructive focus-visible:outline-2 focus-visible:outline-offset-1 focus-visible:outline-[#0055dc] dark:focus-visible:outline-[#5e94ff]"
									aria-label={`Remove ${f.name}`}
								>
									×
								</button>
							</li>
						);
					})}
				</ul>
			)}
			<input
				ref={fileInputRef}
				type="file"
				multiple
				className="hidden"
				aria-hidden="true"
				tabIndex={-1}
				onChange={(e) => {
					onAddFiles(e.target.files);
					// reset so selecting the same file again still fires onChange
					e.target.value = "";
				}}
			/>
		</div>
	);
}

/* --------------------------- DecryptedMessageView --------------------------- */

/** Render a decrypted message as markdown (GitHub-flavored), with inline
 *  envelope images.
 *
 *  Message text is composed in a markdown editor, so it renders as markdown
 *  here (GFM tables/lists/strikethrough; remark-breaks keeps single
 *  newlines as line breaks so plain-text messages still read exactly as
 *  typed). HTML in the message is never executed — react-markdown escapes
 *  raw HTML and only allows safe URL schemes.
 *
 *  Envelope image markers (`![alt|NN%[@dx,dy]](envelope://filename)`) are
 *  ordinary markdown images whose `envelope://` src is resolved to the
 *  attachment's data URL via the `img` component override below; scale and
 *  pixel offsets are carried in the alt text and re-applied here. Every
 *  URL that reaches an <img src> passes through isSafeImageUrl (CodeQL
 *  js/xss-through-dom guard) exactly as before.
 */
export function DecryptedMessageView({ text, files }: { text: string; files: EnvelopeFile[] }) {
	// Build a filename → data URL map. First match wins (matching the
	// Encrypt-side behavior where deduplicated names are unique).
	const fileMap = useMemo(() => {
		const m = new Map<string, string>();
		for (const f of files) {
			if (!m.has(f.name)) {
				m.set(f.name, envelopeFileToDataUrl(f));
			}
		}
		return m;
	}, [files]);

	return (
		<div className="break-words text-sm leading-relaxed text-foreground [&>*:first-child]:mt-0 [&>*:last-child]:mb-0 [&_a]:underline-offset-2 [&_a:hover]:underline [&_blockquote]:border-l-2 [&_blockquote]:border-border [&_blockquote]:pl-3 [&_blockquote]:text-muted-foreground [&_code]:rounded [&_code]:bg-muted [&_code]:px-1 [&_code]:py-0.5 [&_code]:text-[0.85em] [&_h1]:mt-4 [&_h1]:mb-2 [&_h1]:border-b [&_h1]:border-border/60 [&_h1]:pb-1 [&_h1]:text-xl [&_h1]:font-semibold [&_h1]:leading-tight [&_h1:first-child]:mt-0 [&_h2]:mt-4 [&_h2]:mb-2 [&_h2]:text-lg [&_h2]:font-semibold [&_h2]:leading-tight [&_h2:first-child]:mt-0 [&_h3]:mt-3 [&_h3]:mb-1.5 [&_h3]:text-base [&_h3]:font-semibold [&_h3:first-child]:mt-0 [&_h4]:mt-3 [&_h4]:mb-1.5 [&_h4]:text-sm [&_h4]:font-semibold [&_h4:first-child]:mt-0 [&_h5]:mt-3 [&_h5]:mb-1 [&_h5]:text-sm [&_h5]:font-medium [&_h5:first-child]:mt-0 [&_h6]:mt-3 [&_h6]:mb-1 [&_h6]:text-xs [&_h6]:font-medium [&_h6]:uppercase [&_h6]:tracking-wide [&_h6:first-child]:mt-0 [&_hr]:my-4 [&_hr]:border-border [&_img]:my-1 [&_li]:my-0.5 [&_ol]:my-2 [&_ol]:list-decimal [&_ol]:pl-6 [&_p]:my-2 [&_p:first-child]:mt-0 [&_p:last-child]:mb-0 [&_pre]:overflow-x-auto [&_pre]:rounded-md [&_pre]:bg-muted [&_pre]:p-2 [&_table]:my-2 [&_table]:w-full [&_td]:border [&_td]:border-border [&_td]:px-2 [&_td]:py-1 [&_th]:border [&_th]:border-border [&_th]:px-2 [&_th]:py-1 [&_ul]:my-2 [&_ul]:list-disc [&_ul]:pl-6">
			<Markdown
				remarkPlugins={[remarkGfm, remarkBreaks]}
				components={{
					a: ({ node: _node, children, ...props }) => (
						<a {...props} target="_blank" rel="noreferrer noopener" className={ACCENT_TEXT}>
							{children}
						</a>
					),
					img: ({ node: _node, src, alt, title }) => {
						const meta = parseInlineImageAlt(alt ?? "");
						// Resolve envelope:// handles against the attachment list. Every
						// other URL (markdown written by the sender) must pass the strict
						// LOCAL-ONLY allow-list (isLocalImageUrl) before reaching the DOM:
						// unlike the encrypt-side previews, remote https: images are NOT
						// rendered here — they would auto-load while reading a decrypted
						// message and leak the recipient's IP to a tracking pixel.
						const raw = typeof src === "string" ? src : null;
						const candidate =
							raw !== null && raw.startsWith("envelope://")
								? (fileMap.get(decodeURIComponent(raw.slice("envelope://".length))) ?? null)
								: raw;
						// Barrier guard for static analysis: regex-test the exact
						// tainted string before it reaches <img src>.
						const safeSrc =
							candidate !== null &&
							SAFE_DATA_IMAGE_RE.test(candidate) &&
							isLocalImageUrl(candidate) !== null
								? candidate
								: null;
						const remoteBlocked = safeSrc === null && raw !== null && /^https?:/i.test(raw);
						if (!safeSrc) {
							return (
								<span
									title={
										remoteBlocked
											? "Remote images are blocked in decrypted messages (tracking-pixel privacy guard)."
											: undefined
									}
									className="mx-1 inline-block rounded border border-red-200 bg-red-50 px-2 py-0.5 text-[11px] italic text-red-700 dark:border-red-900 dark:bg-red-950/40 dark:text-red-400"
								>
									{remoteBlocked
										? `[remote image blocked: ${meta.displayName}]`
										: `[missing image: ${meta.displayName}]`}
								</span>
							);
						}
						// NOTE: sender-controlled markdown attributes are NOT spread onto
						// the <img> — a crafted srcset/sizes attribute would bypass the
						// src allow-list above. Only alt/src/style/className/title (ours)
						// reach the DOM. loading=lazy also defers offscreen inline images.
						return (
							<img
								title={title}
								src={safeSrc}
								alt={meta.displayName}
								loading="lazy"
								decoding="async"
								style={{
									width: `${meta.scale}%`,
									maxWidth: "100%",
									minHeight: "20px",
									transform: `translate(${meta.dx}px, ${meta.dy}px)`,
								}}
								className="inline-block rounded border border-border align-middle"
							/>
						);
					},
				}}
			>
				{text}
			</Markdown>
		</div>
	);
}

/* ------------------------------- SignerBadges ------------------------------- */

/** "Signed by" panel describing each signature found on a message. Same
 *  contract as the Verify tab's result card: it names the signer, says where
 *  the verification key came from, and labels the key ID / fingerprint hex
 *  strings — no format talk, no filler captions. */
export function SignerBadges({ signatures }: { signatures: SignatureInfo[] }) {
	return (
		<div className="rounded-xl border bg-muted/40 p-4 shadow-sm">
			<div className="mb-1.5 text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
				Signed by
			</div>
			<ul className="space-y-2">
				{signatures.map((s, i) => {
					const color =
						s.verified === "valid"
							? "border-emerald-200 bg-emerald-100 text-emerald-800 dark:border-emerald-900 dark:bg-emerald-950/40 dark:text-emerald-300"
							: s.verified === "invalid"
								? "border-red-200 bg-red-100 text-red-800 dark:border-red-900 dark:bg-red-950/40 dark:text-red-300"
								: "border-border bg-muted text-muted-foreground";
					const label =
						s.verified === "valid"
							? "verified"
							: s.verified === "invalid"
								? "invalid signature"
								: "unknown signer";
					// Build the display name: prefer Keybase username, then full name,
					// then email, then raw userID, then fall back to "Unknown key".
					const displayName = s.username
						? `@${s.username}`
						: s.name
							? s.name
							: s.email
								? s.email
								: s.userID
									? s.userID
									: "Unknown key";
					// Signer-key expiry (R9): only when the verification record carried
					// real expiration data (currently the local-match path). Same DRY
					// helper + pill classes as the RecipientPicker chips.
					const expiry =
						typeof s.expiresAt === "number" ? getKeyExpiryStatus(new Date(s.expiresAt)) : null;
					return (
						<li key={i} className="text-sm">
							<div className="flex flex-wrap items-center gap-2">
								<span className={`font-medium ${ACCENT_TEXT}`}>{displayName}</span>
								<span
									className={`inline-flex items-center rounded-full border px-2 py-0.5 text-[10px] font-medium tracking-wide ${color}`}
								>
									{label}
								</span>
								{/* Where the signer's public key was resolved from. */}
								<KeySourcePill source={s.resolvedFrom} />
								{/* Self-signer marker: the signature verified against the
                    user's own locally-configured key (never published to
                    keyservers, hence resolved locally — R7). */}
								{s.self && (
									<span className="inline-flex items-center rounded-full border border-[#0055dc]/30 bg-[#0055dc]/5 px-2 py-0.5 text-[10px] font-medium tracking-wide text-[#0055dc] dark:border-[#5e94ff]/40 dark:bg-[#5e94ff]/10 dark:text-[#5e94ff]">
										you
									</span>
								)}
								{/* Signer-key expiry (R9): rendered only when the verification
                    record carried real expiration data (currently the local-
                    match path). Same red/amber pills as the RecipientPicker
                    chips. "none"/unknown → no pill. */}
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
							{/* Secondary info line: name + email + comment (if available and
                  not already used as the display name). */}
							{(s.name || s.email || s.comment) && !s.username && (
								// Wrap rhythm (R9-b): horizontal separation unchanged (8px);
								// wrapped rows tighten to the 2px inter-row rhythm (mt-0.5)
								// instead of the looser all-axis 8px gap on narrow widths.
								<div className="mt-0.5 flex flex-wrap gap-x-2 gap-y-0.5 text-[11px] text-muted-foreground">
									{s.name && <span>Name: {s.name}</span>}
									{s.email && (
										<span>
											Email:{" "}
											<a href={`mailto:${s.email}`} className={`${ACCENT_TEXT} hover:underline`}>
												{s.email}
											</a>
										</span>
									)}
									{s.comment && <span>Comment: {s.comment}</span>}
								</div>
							)}
							{/* All user IDs (if the key has more than one). */}
							{s.allUserIDs && s.allUserIDs.length > 1 && (
								<details className="mt-1">
									<summary className="cursor-pointer text-[10px] text-muted-foreground transition-colors hover:text-foreground">
										All user IDs ({s.allUserIDs.length})
									</summary>
									<ul className="mt-1 space-y-0.5 font-mono text-[11px] text-muted-foreground">
										{s.allUserIDs.map((uid, j) => (
											<li key={j} className="break-all">
												{uid}
											</li>
										))}
									</ul>
								</details>
							)}
							{/* High-precision signing timestamp from the signature notation. */}
							{s.timestampIso && (
								<div className="mt-0.5 text-[11px] text-muted-foreground">
									Signed at: <span className="font-mono">{formatTimestamp(s.timestampIso)}</span>
								</div>
							)}
							{/* Fingerprint (if available) — labeled so the hex string is
                  self-explanatory. */}
							{s.fingerprint && (
								<div className="mt-0.5 break-all font-mono text-[10px] text-muted-foreground">
									<span className="mr-1 font-sans text-[10px] tracking-wide">Fingerprint</span>
									{s.fingerprint}
								</div>
							)}
						</li>
					);
				})}
			</ul>
			{/* One-line explainer for the key ID / fingerprint hex strings. */}
			<SignerHashLegend />
		</div>
	);
}

/* ----------------------------- FileDownloadList ----------------------------- */

/** Render the list of files extracted from a decrypted envelope.
 *
 *  Image attachments open a full-size viewer when clicking the file name or
 *  the thumbnail (anything except the Download button, which keeps its
 *  plain download behavior — the viewer never intercepts it). Non-image
 *  files keep a static chip + download. */
export function FileDownloadList({ files }: { files: EnvelopeFile[] }) {
	// Viewer state: index into the IMAGES subset (non-images aren't viewable).
	const [viewingIndex, setViewingIndex] = useState<number | null>(null);
	const images = useMemo(() => files.filter((f) => f.type.startsWith("image/")), [files]);

	return (
		<div className="rounded-xl border bg-muted/40 p-4 shadow-sm">
			<div className="mb-1.5 flex items-center gap-2">
				<span
					aria-hidden="true"
					className="h-3.5 w-[3px] shrink-0 rounded-full bg-[#0055dc] dark:bg-[#5e94ff]"
				/>
				<div className="text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
					Attached files ({files.length})
				</div>
			</div>
			<ul className="space-y-1.5">
				{files.map((f, i) => {
					const url = envelopeFileToDataUrl(f);
					const safeImgSrc =
						SAFE_DATA_IMAGE_RE.test(url) && isSafeImageUrl(url) !== null ? url : null;
					return (
						<li key={i} className="flex items-center gap-2.5 text-sm">
							{safeImgSrc ? (
								// Thumbnail + file name open the image viewer (not a download).
								<button
									type="button"
									onClick={() => setViewingIndex(images.indexOf(f))}
									className="flex items-center gap-2.5 text-left transition-opacity hover:opacity-80"
									aria-label={`View ${f.name}`}
									title="View image"
								>
									{}
									<img
										src={safeImgSrc}
										alt={f.name}
										className="size-8 rounded border border-border object-cover"
									/>
									<span className={`font-medium ${ACCENT_TEXT} hover:underline`}>{f.name}</span>
								</button>
							) : (
								<div className="flex items-center gap-2.5">
									<div className="grid size-8 place-items-center rounded border border-border bg-background text-[9px] font-medium text-muted-foreground">
										{f.name.split(".").pop()?.toUpperCase().slice(0, 4) || "FILE"}
									</div>
									<span className="font-medium">{f.name}</span>
								</div>
							)}
							<span className="text-[11px] text-muted-foreground">{formatFileSize(f.size)}</span>
							<a
								href={url}
								download={f.name}
								className="ml-auto inline-flex min-h-11 items-center rounded-md border bg-background px-3 text-[11px] font-medium text-foreground shadow-xs transition-colors hover:bg-muted sm:min-h-0 sm:py-1"
								aria-label={`Download ${f.name}`}
							>
								Download
							</a>
						</li>
					);
				})}
			</ul>
			<ImageViewer
				images={images}
				index={viewingIndex}
				onIndexChange={setViewingIndex}
				onClose={() => setViewingIndex(null)}
			/>
		</div>
	);
}
