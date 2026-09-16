"use client";

/**
 * Message composer for the Encrypt tab — a real markdown editor.
 *
 * # Mr. AI Acting on s183173's Behalf
 *
 * Two styles, switched in settings (default: Notion-style):
 *   - "notion": BlockNote block editor (Notion/Affine-like). Inline images
 *     render right in the document; a reconcile step converts every image
 *     data URL the editor produces into the envelope's `envelope://` marker
 *     format (and registers new pastes as attachments), so the encrypted
 *     wire format is unchanged.
 *   - "vscode": @uiw/react-md-editor source editor with a live preview pane
 *     side-by-side (VS Code style). The preview reuses the same
 *     DecryptedMessageView renderer the recipient sees.
 *
 * The parent owns the plaintext (markdown + envelope markers) and the
 * attachment list; this component only edits text through onChange and
 * registers pasted images through the provided callback.
 */
import { useCallback, useEffect, useMemo, useRef } from "react";
import { useTheme } from "next-themes";
import dynamic from "next/dynamic";
import MDEditor, { commands as mdCommands } from "@uiw/react-md-editor";
import { DEFAULT_INLINE_IMAGE_SCALE, buildInlineImageMarker } from "@/lib/pgp/inline-image";
import { envelopeFileToDataUrl, type EnvelopeFile } from "@/lib/pgp/envelope";
import { DecryptedMessageView } from "@/components/pgp/shared";
import type { MarkdownEditorKind } from "@/lib/pgp/settings";

/** Register a freshly pasted image (given as a data: URL) as a new
 *  attachment. Returns the stored EnvelopeFile (with its unique name) so
 *  the editor can reference it. */
export type OnNewImageDataUrl = (dataUrl: string, suggestedName?: string) => EnvelopeFile;

const BlockNoteEditor = dynamic(() => import("./BlockNoteEditor"), {
	ssr: false,
	loading: () => <div className="min-h-32 animate-pulse rounded-md bg-muted/40" />,
});

/** Slim, grouped source-mode toolbar — the @uiw default ships ~20 commands
 *  (comment, image, fullscreen, help, live-preview triad …) that are
 *  noise for this composer: images belong to the attachment pipeline, and
 *  the split preview is always visible. Eleven essentials, three groups —
 *  table added for parity with the Notion engine's table block. */
const VSCODE_COMMANDS = [
	mdCommands.bold,
	mdCommands.italic,
	mdCommands.strikethrough,
	mdCommands.divider,
	mdCommands.title,
	mdCommands.quote,
	mdCommands.code,
	mdCommands.divider,
	mdCommands.unorderedListCommand,
	mdCommands.orderedListCommand,
	mdCommands.checkedListCommand,
	mdCommands.table,
	mdCommands.divider,
	mdCommands.link,
];

/** Replace every `envelope://filename` image URL in the markdown with the
 *  matching attachment's data URL (resolved against `files`). Used when
 *  feeding message text INTO an editor that renders images. */
export function markersToDataUrls(text: string, files: EnvelopeFile[]): string {
	if (!text.includes("envelope://")) return text;
	const byName = new Map(files.map((f) => [f.name, envelopeFileToDataUrl(f)]));
	return text.replace(/!\[([^\]]*)\]\(envelope:\/\/([^)\s]+)\)/g, (whole, alt, encodedName) => {
		const name = decodeURIComponent(encodedName);
		const dataUrl = byName.get(name);
		return dataUrl ? `![${alt}](${dataUrl})` : whole;
	});
}

/** Replace every image data URL in the markdown with an envelope marker,
 *  registering unknown data URLs as new attachments via `onNewImage`. Used
 *  when taking markdown OUT of an editor that stored pastes inline. */
export function dataUrlsToMarkers(
	text: string,
	files: EnvelopeFile[],
	onNewImage: OnNewImageDataUrl,
): string {
	if (!text.includes("data:image/")) return text;
	const byData = new Map(files.map((f) => [f.data, f.name]));
	return text.replace(
		/!\[([^\]]*)\]\(data:(image\/[a-z0-9.+-]+);base64,([A-Za-z0-9+/=]+)\)/g,
		(whole, alt, mime, data) => {
			let name = byData.get(data);
			if (!name) {
				let stored: EnvelopeFile | null = null;
				try {
					stored = onNewImage(`data:${mime};base64,${data}`);
				} catch {
					stored = null;
				}
				if (!stored) return whole;
				name = stored.name;
				byData.set(data, name);
			}
			// Keep whatever scale/position metadata the alt text carried; default
			// newly-pasted images (no scale suffix) to the app-wide default.
			const altWithScale =
				alt.includes("|") || alt.includes("@") ? alt : `${alt}|${DEFAULT_INLINE_IMAGE_SCALE}%`;
			return `![${altWithScale}](envelope://${encodeURIComponent(name)})`;
		},
	);
}

export function MessageEditor({
	value,
	onChange,
	files,
	onNewImageDataUrl,
	editorKind,
	placeholder,
	onFilesDropped: _onFilesDropped,
	expanded = false,
}: {
	value: string;
	onChange: (text: string) => void;
	files: EnvelopeFile[];
	onNewImageDataUrl: OnNewImageDataUrl;
	editorKind: MarkdownEditorKind;
	/** Non-image files pasted/dropped in the editor — forwarded to the
	 *  composer's attachment flow (qol layer wires this up). */
	onFilesDropped?: (files: File[]) => void;
	placeholder?: string;
	/** Full-screen composer overlay mode (round-12 editor pass):
	 *  # Mr. AI Acting on s183173's Behalf
	 *  drop the fixed composer heights so the active editor engine fills
	 *  the overlay through 100%-height chains. */
	expanded?: boolean;
}) {
	// Decorative toolbar icons (VS Code mode): MDEditor renders its toolbar
	// glyphs as role="img" SVGs without alternative text — axe's svg-img-alt
	// rule flags them (serious). Each toolbar button already carries its own
	// accessible name, so the icons are hidden from the accessibility tree.
	// Re-runs on editor switches; a no-op in Notion mode (ref not attached).
	const vsWrapRef = useRef<HTMLDivElement>(null);
	useEffect(() => {
		if (editorKind !== "vscode") return;
		const id = requestAnimationFrame(() => {
			vsWrapRef.current
				?.querySelectorAll('svg[role="img"]')
				.forEach((svg) => svg.setAttribute("aria-hidden", "true"));
		});
		return () => cancelAnimationFrame(id);
	}, [editorKind]);

	// VS Code mode -------------------------------------------------------------
	const handleMDEditorChange = useCallback(
		(next?: string) => {
			onChange(dataUrlsToMarkers(next ?? "", files, onNewImageDataUrl));
		},
		[onChange, files, onNewImageDataUrl],
	);

	// Paste images directly into the source editor: register them as
	// attachments and insert envelope markers at the cursor.
	const handleVSPaste = useCallback(
		(e: React.ClipboardEvent<HTMLTextAreaElement>) => {
			const items = e.clipboardData?.items;
			if (!items) return;
			const imageFiles: File[] = [];
			for (let i = 0; i < items.length; i++) {
				const it = items[i];
				if (it.kind === "file" && it.type.startsWith("image/")) {
					const f = it.getAsFile();
					if (f) imageFiles.push(f);
				}
			}
			if (imageFiles.length === 0) return;
			e.preventDefault();
			const textarea = e.currentTarget;
			const start = textarea.selectionStart ?? value.length;
			const end = textarea.selectionEnd ?? start;

			void (async () => {
				const markers: string[] = [];
				for (const f of imageFiles) {
					const dataUrl = await new Promise<string>((resolve, reject) => {
						const reader = new FileReader();
						reader.onload = () => resolve(typeof reader.result === "string" ? reader.result : "");
						reader.onerror = () => reject(reader.error ?? new Error("FileReader error"));
						reader.readAsDataURL(f);
					});
					const stored = onNewImageDataUrl(dataUrl);
					markers.push(
						buildInlineImageMarker(stored.name, DEFAULT_INLINE_IMAGE_SCALE, 0, 0, stored.name),
					);
				}
				const insert = markers.join("\n\n");
				const before = value.slice(0, start);
				const after = value.slice(end);
				const pad1 = before.length > 0 && !before.endsWith("\n") ? "\n\n" : "";
				const pad2 = after.length > 0 && !after.startsWith("\n") ? "\n\n" : "";
				onChange(before + pad1 + insert + pad2 + after);
				queueMicrotask(() => {
					textarea.focus();
					const pos = (before + pad1 + insert).length;
					textarea.setSelectionRange(pos, pos);
				});
			})();
		},
		[value, onChange, onNewImageDataUrl],
	);

	void _onFilesDropped;
	const { resolvedTheme } = useTheme();
	const editorMd = useMemo(() => markersToDataUrls(value, files), [value, files]);
	const previewMd = editorMd;

	// @uiw/react-md-editor reads its chrome theme from data-color-mode on
	// the document root (not from a wrapper attribute) — sync it for the
	// lifetime of the split view, restore the previous value on unmount.
	useEffect(() => {
		if (editorKind !== "vscode") return;
		const root = document.documentElement;
		const prev = root.getAttribute("data-color-mode");
		root.setAttribute("data-color-mode", resolvedTheme === "dark" ? "dark" : "light");
		return () => {
			if (prev === null) root.removeAttribute("data-color-mode");
			else root.setAttribute("data-color-mode", prev);
		};
	}, [editorKind, resolvedTheme]);

	if (editorKind === "vscode") {
		return (
			<div
				ref={vsWrapRef}
				className={`md-editor-wrap overflow-hidden rounded-xl border border-border bg-card shadow-sm focus-within:border-[#0055dc]/50 focus-within:ring-2 focus-within:ring-[#0055dc]/20 dark:focus-within:border-[#5e94ff]/50 dark:focus-within:ring-[#5e94ff]/20 ${expanded ? "flex h-full min-h-0 flex-col" : ""}`}
			>
				<div
					className={`grid lg:grid-cols-2 ${expanded ? "min-h-0 flex-1 grid-rows-2 lg:grid-rows-1" : ""}`}
				>
					<div
						className={`min-w-0 border-b border-border lg:border-b-0 lg:border-r ${expanded ? "min-h-0" : ""}`}
					>
						<MDEditor
							value={editorMd}
							onChange={handleMDEditorChange}
							preview="edit"
							commands={VSCODE_COMMANDS}
							extraCommands={[]}
							textareaProps={{
								onPaste: handleVSPaste,
								placeholder,
								"aria-label": "Message (markdown)",
							}}
							height={expanded ? "100%" : 480}
							style={{ background: "transparent" }}
							className="min-w-0"
						/>
					</div>
					<div
						className={
							expanded
								? "min-h-0 overflow-y-auto bg-background/40 p-4"
								: "h-80 overflow-y-auto bg-background/40 p-4 lg:h-[480px]"
						}
					>
						{previewMd.trim() ? (
							<DecryptedMessageView text={previewMd} files={files} />
						) : (
							<p className="text-xs text-muted-foreground">
								{placeholder ?? "Nothing to preview yet."}
							</p>
						)}
					</div>
				</div>
			</div>
		);
	}

	// Notion/Affine-style mode (default) --------------------------------------
	return (
		<BlockNoteEditor
			value={value}
			onChange={onChange}
			files={files}
			onNewImageDataUrl={onNewImageDataUrl}
			placeholder={placeholder}
			expanded={expanded}
		/>
	);
}
