"use client";

/**
 * Message composer for the Encrypt/Sign tabs — a real markdown editor.
 *
 * # Mr. AI Acting on s183173's Behalf
 *
 * Two styles, switched in settings (default: Notion-style):
 *   - "notion": BlockNote block editor (Notion/Affine-like). Inline images
 *     render right in the document; a reconcile step converts every image
 *     data URL the editor produces into the envelope's `envelope://` marker
 *     format (and registers new pastes as attachments), so the encrypted
 *     wire format is unchanged.
 *   - "vscode": CodeMirror 6 source editor with line numbers + markdown
 *     syntax highlighting, a tab strip, a draggable split and a toggleable
 *     live preview pane (VS Code style). The preview reuses the same
 *     DecryptedMessageView renderer the recipient sees.
 *
 * The parent owns the plaintext (markdown + envelope markers) and the
 * attachment list; this component only edits text through onChange and
 * registers pasted images through the provided callback. The marker
 * bridge below is shared by both engines.
 */
import dynamic from "next/dynamic";
import { DEFAULT_INLINE_IMAGE_SCALE } from "@/lib/pgp/inline-image";
import { envelopeFileToDataUrl, type EnvelopeFile } from "@/lib/pgp/envelope";
import type { MarkdownEditorKind } from "@/lib/pgp/settings";

/** Register a freshly pasted image (given as a data: URL) as a new
 *  attachment. Returns the stored EnvelopeFile (with its unique name) so
 *  the editor can reference it. */
export type OnNewImageDataUrl = (dataUrl: string, suggestedName?: string) => EnvelopeFile;

const BlockNoteEditor = dynamic(() => import("./BlockNoteEditor"), {
	ssr: false,
	loading: () => (
		<div className="min-h-32 animate-in fade-in rounded-md bg-muted/40 duration-200" />
	),
});

const VSCodeEditor = dynamic(() => import("./VSCodeEditor"), {
	ssr: false,
	loading: () => (
		<div className="min-h-32 animate-in fade-in rounded-md bg-muted/40 duration-200" />
	),
});

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
	onFilesDropped: _onFilesDropped,
	placeholder,
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
	void _onFilesDropped;

	if (editorKind === "vscode") {
		return (
			<VSCodeEditor
				value={value}
				onChange={onChange}
				files={files}
				onNewImageDataUrl={onNewImageDataUrl}
				placeholder={placeholder}
				expanded={expanded}
			/>
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
