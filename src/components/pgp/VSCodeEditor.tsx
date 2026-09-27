"use client";

/**
 * VS Code-style markdown composer (source + live preview).
 *
 * # Mr. AI Acting on s183173's Behalf
 *
 * Rebuilt from the feedback round's screenshot: a real editor tab strip
 * ("Message.md" + "Preview Message.md" with a close box), a panel toggle
 * in the strip's top-right, line numbers, markdown syntax highlighting
 * (CodeMirror 6 — the old @uiw textarea had neither), a draggable split
 * divider, and the same read-side renderer the recipient sees in the
 * preview pane.
 *
 * The source shows the wire text (envelope:// markers stay short); only
 * the preview resolves markers to image data URLs. Pasted images register
 * through the attachment pipeline exactly like the other engines — and
 * when there IS no pipeline (Sign tab) the paste degrades to an inline
 * data URL instead of exploding.
 *
 * Loaded dynamically (client-only) from MessageEditor.
 */
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import CodeMirror, { type ReactCodeMirrorRef } from "@uiw/react-codemirror";
import { EditorView, keymap } from "@codemirror/view";
import { EditorSelection } from "@codemirror/state";
import { HighlightStyle, syntaxHighlighting } from "@codemirror/language";
import { markdown } from "@codemirror/lang-markdown";
import { tags } from "@lezer/highlight";
import { PanelRightClose, PanelRightOpen, X, FileCode2 } from "lucide-react";
import { useTheme } from "next-themes";
import { DEFAULT_INLINE_IMAGE_SCALE, buildInlineImageMarker } from "@/lib/pgp/inline-image";
import type { EnvelopeFile } from "@/lib/pgp/envelope";
import { DecryptedMessageView } from "@/components/pgp/shared";
import { markersToDataUrls } from "./MessageEditor";

/** Split bounds (percent of the row width the source pane takes). */
const SPLIT_DEFAULT = 50;
const SPLIT_MIN = 20;
const SPLIT_MAX = 85;

/** Fixed inline (non-overlay) editor height — parity with the old engine. */
const INLINE_HEIGHT = 480;

/** VS Code-authentic chrome + token palette, one per app theme. Kept as a
 *  function (not a constant) because EditorView.theme bakes the `dark`
 *  flag into the generated styles. */
function vscodeExtensions(dark: boolean) {
	const chrome = EditorView.theme(
		{
			"&": {
				fontSize: "13px",
				backgroundColor: dark ? "#1e1e1e" : "#ffffff",
				color: dark ? "#d4d4d4" : "#1f2328",
			},
			".cm-content": {
				fontFamily: "ui-monospace, SFMono-Regular, Menlo, Consolas, 'Liberation Mono', monospace",
				caretColor: dark ? "#aeafad" : "#0055dc",
				padding: "8px 0",
			},
			"&.cm-focused": { outline: "none" },
			".cm-scroller": { overflow: "auto", lineHeight: "1.6" },
			".cm-gutters": {
				backgroundColor: dark ? "#1e1e1e" : "#ffffff",
				color: dark ? "#6e7681" : "#a1a1a1",
				border: "none",
				borderRight: dark ? "1px solid #2b2b2b" : "1px solid #ebebeb",
			},
			".cm-activeLine": { backgroundColor: dark ? "#282828" : "#f6f8fa" },
			".cm-activeLineGutter": {
				backgroundColor: dark ? "#282828" : "#f6f8fa",
				color: dark ? "#d4d4d4" : "#1f2328",
			},
			"&.cm-focused .cm-selectionBackground, .cm-selectionBackground, .cm-content ::selection": {
				backgroundColor: dark ? "#264f78" : "#add6ff",
			},
			".cm-selectionMatch": { backgroundColor: dark ? "#405d7d66" : "#c9e0ff88" },
			".cm-cursor": { borderLeftWidth: "2px" },
		},
		{ dark },
	);
	// Markdown tokens — VS Code Dark+ in dark, Light+ hues in light.
	const highlight = HighlightStyle.define([
		{ tag: tags.heading1, color: dark ? "#569cd6" : "#0451a5", fontWeight: "700" },
		{ tag: tags.heading2, color: dark ? "#569cd6" : "#0451a5", fontWeight: "700" },
		{ tag: tags.heading3, color: dark ? "#569cd6" : "#0451a5", fontWeight: "600" },
		{ tag: tags.heading4, color: dark ? "#569cd6" : "#0451a5", fontWeight: "600" },
		{ tag: tags.heading5, color: dark ? "#569cd6" : "#0451a5" },
		{ tag: tags.heading6, color: dark ? "#569cd6" : "#0451a5" },
		{ tag: tags.strong, color: dark ? "#d7ba7d" : "#795e26" },
		{ tag: tags.emphasis, fontStyle: "italic" },
		{
			tag: tags.strikethrough,
			textDecoration: "line-through",
			color: dark ? "#808080" : "#6e7781",
		},
		{ tag: tags.link, color: dark ? "#4daafc" : "#0055dc", textDecoration: "underline" },
		{ tag: tags.url, color: dark ? "#4daafc" : "#0055dc" },
		{ tag: tags.monospace, backgroundColor: dark ? "#2b2b2b" : "#f0f0f0", borderRadius: "3px" },
		{ tag: tags.quote, color: dark ? "#6a9955" : "#267f99", fontStyle: "italic" },
		{ tag: [tags.processingInstruction], color: dark ? "#c586c0" : "#af00db" },
		{ tag: [tags.contentSeparator], color: dark ? "#c586c0" : "#af00db" },
		{ tag: [tags.keyword, tags.atom], color: dark ? "#569cd6" : "#0000ff" },
		{ tag: [tags.meta], color: dark ? "#808080" : "#6e7781" },
	]);
	return [chrome, syntaxHighlighting(highlight), EditorView.lineWrapping];
}

/** Insert markdown at the cursor (paste pipeline shared by the image path). */
function insertAtCursor(view: EditorView, text: string): void {
	const sel = view.state.selection.main;
	const before = view.state.sliceDoc(0, sel.from);
	const after = view.state.sliceDoc(sel.to);
	const pad1 = before.length > 0 && !before.endsWith("\n") ? "\n\n" : "";
	const pad2 = after.length > 0 && !after.startsWith("\n") ? "\n\n" : "";
	const insert = pad1 + text + pad2;
	const pos = sel.from + insert.length;
	view.dispatch({
		changes: { from: sel.from, to: sel.to, insert },
		selection: EditorSelection.cursor(pos),
		scrollIntoView: true,
	});
	view.focus();
}

/** Read image blobs as data URLs (FileReader, same as the other engines). */
function readAsDataUrl(file: File): Promise<string> {
	return new Promise((resolve, reject) => {
		const reader = new FileReader();
		reader.onload = () => resolve(typeof reader.result === "string" ? reader.result : "");
		reader.onerror = () => reject(reader.error ?? new Error("FileReader error"));
		reader.readAsDataURL(file);
	});
}

export default function VSCodeEditor({
	value,
	onChange,
	files,
	onNewImageDataUrl,
	placeholder,
	expanded = false,
}: {
	value: string;
	onChange: (text: string) => void;
	files: EnvelopeFile[];
	onNewImageDataUrl: (dataUrl: string, suggestedName?: string) => EnvelopeFile;
	placeholder?: string;
	/** Full-screen overlay mode: fill the overlay instead of a fixed height. */
	expanded?: boolean;
}) {
	const { resolvedTheme } = useTheme();
	const dark = resolvedTheme === "dark";
	const [previewOpen, setPreviewOpen] = useState(true);
	const [split, setSplit] = useState(SPLIT_DEFAULT);
	const wrapRef = useRef<HTMLDivElement>(null);
	const dragging = useRef(false);
	const cmRef = useRef<ReactCodeMirrorRef>(null);

	// The SOURCE shows the wire text (envelope:// markers — short lines);
	// the PREVIEW resolves markers to data URLs. The old engine piped
	// resolved data URLs into the textarea too, which printed megabyte-long
	// base64 lines into the source.
	const previewText = useMemo(() => markersToDataUrls(value, files), [value, files]);

	// Paste: images register through the attachment pipeline; when the
	// caller has no pipeline (Sign tab) the image degrades to an inline
	// data URL — the signed text carries it, nothing throws.
	const pasteExtensions = useMemo(
		() => [
			EditorView.domEventHandlers({
				paste: (event, view) => {
					const items = event.clipboardData?.items;
					if (!items) return false;
					const imageFiles: File[] = [];
					for (const item of Array.from(items)) {
						if (item.kind === "file" && item.type.startsWith("image/")) {
							const f = item.getAsFile();
							if (f) imageFiles.push(f);
						}
					}
					if (imageFiles.length === 0) return false;
					event.preventDefault();
					void (async () => {
						const markers: string[] = [];
						for (const f of imageFiles) {
							const dataUrl = await readAsDataUrl(f);
							try {
								const stored = onNewImageDataUrl(dataUrl);
								markers.push(
									buildInlineImageMarker(
										stored.name,
										DEFAULT_INLINE_IMAGE_SCALE,
										0,
										0,
										stored.name,
									),
								);
							} catch {
								markers.push(`![image](${dataUrl})`);
							}
						}
						insertAtCursor(view, markers.join("\n\n"));
					})();
					return true;
				},
			}),
			// Ctrl/Cmd+Enter belongs to the overlay's primary action; keep CM
			// from treating Enter-variants as its own commands.
			keymap.of([
				{
					key: "Mod-Enter",
					run: () => false,
					preventDefault: false,
				},
			]),
		],
		[onNewImageDataUrl],
	);

	// ONE stable extension array: CodeMirror reconfigures itself whenever
	// the array identity changes, and a fresh array every render fed a
	// reconfigure storm into the controlled-value loop (React logged
	// "Maximum update depth exceeded" on every keystroke).
	const allExtensions = useMemo(
		() => [markdown(), vscodeExtensions(dark), pasteExtensions],
		[dark, pasteExtensions],
	);

	// Focus the source when the overlay opens (keyboard users must land in
	// the editor, not behind the aria-modal surface).
	useEffect(() => {
		if (!expanded) return;
		const id = requestAnimationFrame(() => cmRef.current?.view?.focus());
		return () => cancelAnimationFrame(id);
	}, [expanded]);

	// Divider drag: pointer capture keeps the drag alive outside the strip;
	// double-click resets to an even split. Keyboard: arrows nudge by 2%.
	const applySplit = useCallback((clientX: number) => {
		const box = wrapRef.current?.getBoundingClientRect();
		if (!box) return;
		const pct = ((clientX - box.left) / box.width) * 100;
		setSplit(Math.min(SPLIT_MAX, Math.max(SPLIT_MIN, pct)));
	}, []);

	const onDividerPointerDown = (e: React.PointerEvent<HTMLDivElement>) => {
		e.preventDefault();
		dragging.current = true;
		e.currentTarget.setPointerCapture(e.pointerId);
	};

	const onDividerPointerMove = (e: React.PointerEvent<HTMLDivElement>) => {
		if (!dragging.current) return;
		applySplit(e.clientX);
	};

	const stopDrag = (e: React.PointerEvent<HTMLDivElement>) => {
		dragging.current = false;
		e.currentTarget.releasePointerCapture(e.pointerId);
	};

	const preview = (
		<div className="min-h-0 min-w-0 flex-1 overflow-y-auto p-4">
			{previewText.trim() ? (
				<DecryptedMessageView text={previewText} files={files} />
			) : (
				<p className="text-xs text-muted-foreground">{placeholder ?? "Nothing to preview yet."}</p>
			)}
		</div>
	);

	return (
		<div
			ref={wrapRef}
			className={
				"flex select-none flex-col overflow-hidden rounded-xl border border-border bg-card shadow-sm focus-within:border-[#0055dc]/50 focus-within:ring-2 focus-within:ring-[#0055dc]/20 dark:focus-within:border-[#5e94ff]/50 dark:focus-within:ring-[#5e94ff]/20 " +
				(expanded ? "h-full min-h-0" : "h-[480px]")
			}
		>
			{/* Tab strip — chrome bar with the source tab, the preview tab (when
                            open) and the preview toggle, VS Code title-bar style. */}
			<div className="flex h-9 shrink-0 items-stretch border-b border-border bg-muted/50 dark:bg-[#252526]">
				<div
					aria-current="true"
					className="flex items-center gap-1.5 border-r border-border bg-background px-3 text-xs font-medium dark:bg-[#1e1e1e]"
				>
					<FileCode2 aria-hidden="true" className="size-3.5 text-[#0055dc] dark:text-[#5e94ff]" />
					Message.md
				</div>
				{previewOpen && (
					<div className="hidden items-center gap-1.5 border-r border-border px-3 text-xs text-muted-foreground sm:flex">
						<PanelRightOpen aria-hidden="true" className="size-3.5" />
						Preview
						<button
							type="button"
							aria-label="Close preview panel"
							onClick={() => setPreviewOpen(false)}
							className="ml-0.5 rounded p-0.5 transition-colors hover:bg-black/10 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#0055dc]/40 dark:hover:bg-white/10 dark:focus-visible:ring-[#5e94ff]/40"
						>
							<X aria-hidden="true" className="size-3" />
						</button>
					</div>
				)}
				<div className="ml-auto flex items-center gap-1 px-2">
					<button
						type="button"
						aria-label={previewOpen ? "Hide preview panel" : "Show preview panel"}
						aria-pressed={previewOpen}
						title="Toggle preview panel"
						onClick={() => setPreviewOpen((v) => !v)}
						className="flex size-7 items-center justify-center rounded-md text-muted-foreground transition-colors hover:bg-black/10 hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#0055dc]/40 dark:hover:bg-white/10 dark:focus-visible:ring-[#5e94ff]/40"
					>
						{previewOpen ? (
							<PanelRightClose aria-hidden="true" className="size-4" />
						) : (
							<PanelRightOpen aria-hidden="true" className="size-4" />
						)}
					</button>
				</div>
			</div>

			{/* Split panes. */}
			<div className="flex min-h-0 flex-1 flex-col lg:flex-row">
				<div
					className="min-h-0 min-w-0 overflow-hidden border-b border-border lg:border-b-0"
					style={{ flexBasis: previewOpen ? `${split}%` : "100%", flexGrow: 0, flexShrink: 0 }}
				>
					<CodeMirror
						ref={cmRef}
						value={value}
						onChange={onChange}
						height={expanded ? "100%" : `${INLINE_HEIGHT - 36}px`}
						extensions={allExtensions}
						basicSetup={{
							lineNumbers: true,
							highlightActiveLine: true,
							highlightActiveLineGutter: true,
							foldGutter: false,
							autocompletion: false,
							bracketMatching: false,
							closeBrackets: false,
							allowMultipleSelections: false,
							highlightSelectionMatches: false,
							searchKeymap: false,
						}}
						theme={dark ? "dark" : "light"}
						placeholder={placeholder ?? "Type the message…"}
						aria-label="Message (markdown source)"
					/>
				</div>
				{previewOpen && (
					<>
						{/* Draggable divider (lg+); on small screens the border above
                                                    and stacked layout take over. */}
						<div
							role="separator"
							aria-orientation="vertical"
							aria-label="Resize source and preview panes"
							tabIndex={0}
							onPointerDown={onDividerPointerDown}
							onPointerMove={onDividerPointerMove}
							onPointerUp={stopDrag}
							onPointerCancel={stopDrag}
							onDoubleClick={() => setSplit(SPLIT_DEFAULT)}
							onKeyDown={(e) => {
								if (e.key === "ArrowLeft") setSplit((s) => Math.max(SPLIT_MIN, s - 2));
								else if (e.key === "ArrowRight") setSplit((s) => Math.min(SPLIT_MAX, s + 2));
								else return;
								e.preventDefault();
							}}
							className="group relative hidden w-px shrink-0 cursor-col-resize bg-border lg:block"
						>
							<span className="absolute inset-y-0 -left-1 -right-1 block transition-colors group-hover:bg-[#0055dc]/25 dark:group-hover:bg-[#5e94ff]/25" />
						</div>
						{preview}
					</>
				)}
			</div>
		</div>
	);
}
