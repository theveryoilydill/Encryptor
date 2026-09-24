"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";

import { FileSignature, FileUp, Maximize2, Minimize2, ShieldCheck, X } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group";
import { CopyButton, ErrorBanner, InputSizeCounter, OutputBlock } from "@/components/pgp/shared";
import { MessageEditor } from "@/components/pgp/MessageEditor";
import { formatFileSize } from "@/lib/pgp/envelope";
import { downloadBlob } from "@/lib/pgp/zip-bundle";
import type { MarkdownEditorKind } from "@/lib/pgp/settings";
import type { PrivateKeyConfig } from "@/components/pgp/contracts";
import {
	composerOverlayOwner,
	isComposerToggleChord,
	isNestedDialogTarget,
	isPrimaryActionChord,
} from "@/lib/pgp/composer-overlay";
import { signFileDetached, signMessage } from "@/lib/pgp/pgp";
import { toast } from "@/hooks/use-toast";

export function SignTab({
	privateKey,
	requestDecryptedKey,
	markdownEditor,
	globalComposerChord = false,
}: {
	privateKey: PrivateKeyConfig | null;
	requestDecryptedKey: () => Promise<{ key: OpenPGP.PrivateKey; passphrase: string | null }>;
	/** Which composer engine to use (same setting as the Encrypt tab). */
	markdownEditor: MarkdownEditorKind;
	/** True while the Sign tab is active — PgpApp routes the global
	 *  Ctrl/Cmd+Shift+E expand chord to whichever tab owns the composer
	 *  (see EncryptTab.globalComposerChord for the other side of the
	 *  routing). */
	globalComposerChord?: boolean;
}) {
	// Composer content. Plaintext is held in React state ONLY — nothing is
	// persisted to storage (user request: "Don't save drafts, that is
	// insecure"). Signing intentionally does NOT clear the composer on
	// success, but a refresh still loses unsent text by design.
	const [plaintext, setPlaintext] = useState("");
	const [detached, setDetached] = useState(false);
	const [output, setOutput] = useState("");
	const [busy, setBusy] = useState(false);
	const [error, setError] = useState<string | null>(null);
	// Full-screen composer overlay (parity with the Encrypt tab): when
	// expanded, the whole "Text to sign" composer — header row, editor,
	// counter — moves into a portal dialog filling the viewport. The state
	// lives HERE in the tab; the editor engine simply re-mounts with the
	// same value props, so text survives expand AND collapse untouched.
	//
	// # Mr. AI Acting on s183173's Behalf
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
	// Escape collapses the overlay from ANYWHERE (window-level capture —
	// opening it can drop focus on <body>, and an aria-modal dialog that
	// ignores Escape is an a11y bug). Nested Radix surfaces keep their
	// Escape via the shared guard, and a focus inside ANOTHER tab's overlay
	// (both composers can stack) makes this handler stand down.
	useEffect(() => {
		if (!composerExpanded) return;
		const onWindowEscape = (e: KeyboardEvent) => {
			if (e.key !== "Escape" || e.defaultPrevented) return;
			if (isNestedDialogTarget(e.target)) return;
			const owner = composerOverlayOwner(e.target);
			if (owner !== null && owner !== "sign") return;
			e.preventDefault();
			setComposerExpanded(false);
		};
		window.addEventListener("keydown", onWindowEscape, true);
		return () => window.removeEventListener("keydown", onWindowEscape, true);
	}, [composerExpanded]);
	// Global Ctrl/Cmd+Shift+E — routes to THIS tab's composer only while the
	// Sign tab is active (PgpApp owns the routing; see globalComposerChord).
	useEffect(() => {
		if (!globalComposerChord) return;
		const onKey = (e: KeyboardEvent) => {
			if (!isComposerToggleChord(e) || e.defaultPrevented) return;
			if (isNestedDialogTarget(e.target)) return;
			e.preventDefault();
			setComposerExpanded((v) => !v);
		};
		window.addEventListener("keydown", onKey, true);
		return () => window.removeEventListener("keydown", onKey, true);
	}, [globalComposerChord]);

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
			const { key: decryptedKey } = await requestDecryptedKey();

			// Pass the PrivateKey object directly to avoid re-armoring +
			// re-parsing, which can lose key material for Keybase P3SKB keys.
			const signed = await signMessage({
				plaintext,
				privateKey: decryptedKey,
				detached,
			});
			setOutput(signed);
			// Signed from the full-screen overlay: collapse it so the result
			// (which renders in the inline layout BELOW the composer) is
			// actually visible — the overlay would otherwise cover it.
			setComposerExpanded(false);
		} catch (e) {
			setError((e as Error).message);
		} finally {
			setBusy(false);
		}
	}, [plaintext, privateKey, detached, requestDecryptedKey]);

	// ------------------------- File signing (round 20) -------------------------
	// A self-contained second flow at the bottom of the tab: pick ANY file,
	// get an armored detached signature over its exact bytes. The file never
	// leaves the browser and is deliberately NOT persisted anywhere — no
	// draft, no storage: File handles die with the page by design.
	const [signFile, setSignFile] = useState<File | null>(null);
	const [fileSig, setFileSig] = useState<{ name: string; size: number; armor: string } | null>(
		null,
	);
	const [fileBusy, setFileBusy] = useState(false);
	const [fileDragDepth, setFileDragDepth] = useState(0);
	const fileInputRef = useRef<HTMLInputElement>(null);

	/** 100 MB guard: openpgp.js buffers the whole message in memory, and a
	 *  multi-GB read would hang the tab without ever being a supported
	 *  use-case (sha256sum-style flows belong on disk, not in a browser). */
	const MAX_FILE_SIGN_BYTES = 100 * 1024 * 1024;

	const acceptChosenFile = (file: File | undefined | null) => {
		if (!file) return;
		setFileSig(null);
		setError(null);
		if (file.size > MAX_FILE_SIGN_BYTES) {
			setError(
				`"${file.name}" is ${formatFileSize(file.size)} — the limit for file signing is 100 MB.`,
			);
			return;
		}
		setSignFile(file);
	};

	const handleSignFile = useCallback(async () => {
		if (!signFile || fileBusy) return;
		setError(null);
		setFileSig(null);
		if (!privateKey) {
			setError("Configure your private key first (top-right button).");
			return;
		}
		setFileBusy(true);
		try {
			const { key: decryptedKey } = await requestDecryptedKey();
			const bytes = new Uint8Array(await signFile.arrayBuffer());
			const armor = await signFileDetached({ file: bytes, privateKey: decryptedKey });
			setFileSig({ name: signFile.name, size: signFile.size, armor });
			toast({
				title: "Detached signature created",
				description: `${signFile.name} — download the .sig and send it alongside the file.`,
			});
		} catch (e) {
			setError((e as Error).message);
		} finally {
			setFileBusy(false);
		}
	}, [signFile, fileBusy, privateKey, requestDecryptedKey, toast]);

	const handleDownloadSig = useCallback(() => {
		if (!fileSig) return;
		try {
			const blob = new Blob([fileSig.armor], { type: "text/plain;charset=utf-8" });
			downloadBlob(blob, `${fileSig.name}.sig`);
			toast({ title: "Signature file downloaded" });
		} catch (e) {
			toast({
				title: "Download failed",
				description: (e as Error)?.message || "Download unavailable",
				variant: "destructive",
			});
		}
	}, [fileSig, toast]);

	// The whole "Text to sign" composer — header row (label + utility
	// buttons), empty-state, editor, draft note and counter — as one value,
	// rendered EITHER inside the inline card OR inside the full-screen
	// portal overlay below. Pure re-mount either way: no state lives in the
	// subtree, so text survives expand AND collapse.
	//
	// # Mr. AI Acting on s183173's Behalf
	const composerBody = (
		<>
			<div className="mb-1.5 flex items-center justify-between gap-2">
				<div className="flex items-center gap-2">
					<span
						aria-hidden="true"
						className="h-3.5 w-[3px] shrink-0 rounded-full bg-[#0055dc] dark:bg-[#5e94ff]"
					/>
					<Label className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
						Text to sign
					</Label>
				</div>
				<div className="flex items-center gap-2">
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
				</div>
			</div>
			{/* Hidden while the full-screen overlay is up — the editor's own
                            placeholder already covers "empty" in zen mode (Encrypt parity). */}
			{!composerExpanded && !plaintext.trim() && !output && (
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
			{/* Markdown editor for signing ("markdown for signing too") — same
                                    two engines as the Encrypt composer. Signing has no attachment
                                    pipeline, so image registration intentionally fails closed:
                                    pasted images stay inline as data URLs inside the signed text.
                                    flex-1 min-h-0 in the overlay lets the engine fill the viewport. */}
			<div className={composerExpanded ? "min-h-0 flex-1" : undefined}>
				<MessageEditor
					value={plaintext}
					onChange={setPlaintext}
					files={[]}
					onNewImageDataUrl={() => {
						throw new Error("Signing has no attachment pipeline.");
					}}
					editorKind={markdownEditor}
					placeholder="Paste or write the text you want to sign."
					expanded={composerExpanded}
				/>
			</div>
			{/* Char/word/size counter — parity with the Encrypt tab counter. */}
			<InputSizeCounter text={plaintext} />
		</>
	);

	return (
		<section
			className="space-y-6"
			onKeyDown={(e) => {
				// Ctrl/Cmd+Enter runs the primary action from anywhere in the tab.
				// Skips while a run is in flight — same guard as the disabled button.
				if (isPrimaryActionChord(e)) {
					e.preventDefault();
					if (!busy) void handleSign();
				}
				// Ctrl/Cmd+Shift+E toggles the full-screen composer — same dialog-safe
				// wiring as the Encrypt tab (shared predicates live in
				// lib/pgp/composer-overlay.ts).
				if (isComposerToggleChord(e) && !e.defaultPrevented && !isNestedDialogTarget(e.target)) {
					e.preventDefault();
					setComposerExpanded((v) => !v);
				}
			}}
		>
			{!composerExpanded && (
				<div className="rounded-xl border border-border bg-card p-4 shadow-sm sm:p-6">
					{composerBody}
				</div>
			)}
			{/* Full-screen composer overlay — same pattern as the Encrypt tab:
                                    a portal dialog filling the viewport. Click-off + Escape collapse
                                    (both dialog-safe), Ctrl/Cmd+Enter signs from inside, Ctrl/Cmd+Shift+E
                                    collapses. The passphrase prompt opened by requestDecryptedKey
                                    portals OUTSIDE this overlay and keeps its own Escape via the
                                    nested-dialog guard. */}
			{composerExpanded &&
				createPortal(
					<div
						data-composer-overlay="sign"
						role="dialog"
						aria-modal="true"
						aria-label="Composer, full screen"
						onPointerDown={(e) => {
							// Click-off close: a press on the overlay itself (the backdrop
							// around the composer) collapses — presses inside the composer
							// content target deeper nodes and are ignored.
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
							if (isPrimaryActionChord(e)) {
								e.preventDefault();
								if (!busy) void handleSign();
							}
							// Ctrl/Cmd+Shift+E collapses the overlay — same dialog-safe
							// guard as the section handler.
							if (
								isComposerToggleChord(e) &&
								!e.defaultPrevented &&
								!isNestedDialogTarget(e.target)
							) {
								e.preventDefault();
								setComposerExpanded(false);
							}
						}}
						className="fixed inset-0 z-50 overflow-y-auto bg-background p-4 sm:p-6"
					>
						{/* max-w-4xl + status bar — same pattern as the Encrypt overlay
                            (Notion-style reading column; mt-auto pins the bar). */}
						<div className="mx-auto flex h-full min-h-0 w-full max-w-4xl flex-col">
							{composerBody}
							<div className="mt-auto flex flex-wrap items-center justify-between gap-x-4 gap-y-2 pt-3">
								<div className="flex min-w-0 flex-wrap items-center gap-1.5 text-[11px] text-muted-foreground">
									<span className="rounded-full bg-muted/60 px-2 py-0.5">
										{detached ? "Detached signature" : "Cleartext signed"}
									</span>
									{privateKey ? (
										<span className="rounded-full bg-muted/60 px-2 py-0.5">
											Key: {privateKey.label}
										</span>
									) : (
										<span className="rounded-full border border-amber-300/70 bg-amber-50 px-2 py-0.5 font-medium text-amber-700 dark:border-amber-900/50 dark:bg-amber-950/30 dark:text-amber-300">
											No key selected
										</span>
									)}
								</div>
								<div className="hidden shrink-0 items-center gap-1.5 text-[11px] text-muted-foreground sm:flex">
									<kbd className="rounded border bg-muted px-1.5 py-0.5 text-[10px] font-mono">
										Ctrl+↵
									</kbd>
									<span>Sign</span>
									<span aria-hidden="true" className="text-border">
										·
									</span>
									<kbd className="rounded border bg-muted px-1.5 py-0.5 text-[10px] font-mono">
										Esc
									</kbd>
									<span>Collapse</span>
								</div>
							</div>
						</div>
					</div>,
					document.body,
				)}

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
				/>
			)}

			{/* ------------------------- Sign a file (round 20) -------------------------
                            A second, self-contained flow: detached signature over a FILE's
                            exact bytes (the classic gpg --detach-sig workflow). Session-only
                            by design — the file is never stored, uploaded, or drafted. */}
			<div className="rounded-xl border border-border bg-card p-4 shadow-sm sm:p-6">
				<div className="mb-1.5 flex items-center gap-2">
					<span
						aria-hidden="true"
						className="h-3.5 w-[3px] shrink-0 rounded-full bg-violet-500 dark:bg-violet-400"
					/>
					<Label className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
						Sign a file instead
					</Label>
				</div>
				<p className="mb-3 text-xs leading-relaxed text-muted-foreground">
					Detached signature for any document — send the file and the .sig together. The file never
					leaves this browser; the signature covers its exact bytes.
				</p>

				{!signFile && !fileSig && (
					<div
						role="button"
						tabIndex={0}
						aria-label="Choose a file to sign — or drop it here"
						onClick={() => fileInputRef.current?.click()}
						onKeyDown={(e) => {
							if (e.key === "Enter" || e.key === " ") {
								e.preventDefault();
								fileInputRef.current?.click();
							}
						}}
						onDragEnter={(e) => {
							e.preventDefault();
							if (e.dataTransfer.types.includes("Files")) setFileDragDepth((d) => d + 1);
						}}
						onDragOver={(e) => e.preventDefault()}
						onDragLeave={() => setFileDragDepth((d) => Math.max(0, d - 1))}
						onDrop={(e) => {
							e.preventDefault();
							setFileDragDepth(0);
							acceptChosenFile(e.dataTransfer.files?.[0]);
						}}
						className={`animate-fade-up flex cursor-pointer flex-col items-center justify-center rounded-xl border-2 border-dashed p-6 text-center transition-colors duration-150 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#0055dc]/40 dark:focus-visible:ring-[#5e94ff]/40 sm:p-8 ${
							fileDragDepth > 0
								? "border-violet-500/70 bg-violet-500/5"
								: "border-border bg-muted/30 hover:border-violet-500/40 hover:bg-violet-500/5"
						}`}
					>
						<div className="grid size-12 place-items-center rounded-full bg-violet-500/10">
							<FileUp aria-hidden="true" className="size-7 text-violet-600 dark:text-violet-400" />
						</div>
						<p className="mt-3 text-sm font-medium">
							{fileDragDepth > 0
								? "Drop to choose the file"
								: "Choose a file to sign — or drop it here"}
						</p>
						<p className="mt-1 text-xs text-muted-foreground">
							Any format, up to 100 MB · signed locally, never uploaded
						</p>
					</div>
				)}

				{signFile && !fileSig && (
					<div className="animate-fade-up flex flex-wrap items-center gap-x-3 gap-y-2 rounded-xl border border-border bg-muted/30 px-3 py-2.5">
						<FileSignature
							aria-hidden="true"
							className="size-4 shrink-0 text-violet-600 dark:text-violet-400"
						/>
						<span className="min-w-0 flex-1 truncate text-sm font-medium" title={signFile.name}>
							{signFile.name}
						</span>
						<span className="font-mono text-[11px] text-muted-foreground">
							{formatFileSize(signFile.size)}
						</span>
						<Button
							onClick={() => void handleSignFile()}
							disabled={fileBusy}
							size="sm"
							className="bg-violet-600 text-white hover:bg-violet-700 transition-colors duration-150 press-effect"
						>
							{fileBusy ? "Signing…" : "Sign file"}
						</Button>
						<Button
							variant="ghost"
							size="icon"
							aria-label="Remove this file"
							onClick={() => {
								setSignFile(null);
								setError(null);
							}}
							className="size-7 shrink-0 text-muted-foreground hover:text-red-600 dark:hover:text-red-400"
						>
							<X aria-hidden="true" className="size-3.5" />
						</Button>
					</div>
				)}

				{fileSig && (
					<div className="animate-fade-up space-y-3">
						<div className="flex flex-wrap items-center gap-x-3 gap-y-2 rounded-xl border border-emerald-300/70 bg-emerald-500/5 px-3 py-2.5 dark:border-emerald-900/50">
							<ShieldCheck
								aria-hidden="true"
								className="size-4 shrink-0 text-emerald-600 dark:text-emerald-400"
							/>
							<span className="min-w-0 flex-1 truncate text-sm font-medium" title={fileSig.name}>
								{fileSig.name}
							</span>
							<span className="font-mono text-[11px] text-muted-foreground">
								{formatFileSize(fileSig.size)}
							</span>
							<span className="rounded-full border border-emerald-500/30 bg-emerald-500/10 px-2 py-0.5 text-[10px] font-medium text-emerald-600 dark:text-emerald-500">
								signed · binary
							</span>
						</div>
						<OutputBlock
							title={`Detached signature for ${fileSig.name}`}
							output={fileSig.armor}
							operation="sign-file"
						/>
						<div className="flex flex-wrap gap-2">
							<Button
								onClick={handleDownloadSig}
								size="sm"
								className="bg-[#0055dc] text-white hover:bg-[#0046b8] transition-colors duration-150 press-effect"
							>
								Download {fileSig.name}.sig
							</Button>
							<CopyButton
								text={fileSig.armor}
								label="Copy signature"
								ariaLabel="Copy the detached signature armor to the clipboard"
							/>
							<Button
								variant="ghost"
								size="sm"
								onClick={() => {
									setFileSig(null);
									setSignFile(null);
									setError(null);
								}}
								className="transition-colors duration-150"
							>
								Sign another file
							</Button>
						</div>
					</div>
				)}

				{/* Hidden picker — re-armed after every read so picking the same
                                    file twice re-fires onChange. */}
				<input
					ref={fileInputRef}
					type="file"
					className="hidden"
					tabIndex={-1}
					aria-hidden="true"
					onChange={(e) => {
						acceptChosenFile(e.target.files?.[0]);
						e.target.value = "";
					}}
				/>
			</div>
		</section>
	);
}
