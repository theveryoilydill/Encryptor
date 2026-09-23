"use client";

/**
 * Notion/Affine-style block editor for the message composer (BlockNote).
 *
 * # Mr. AI Acting on s183173's Behalf
 *
 * Loaded dynamically (client-only) from MessageEditor. Sync with the
 * parent's plaintext runs through a lossy-markdown bridge:
 *
 *   parent value ──markers→data URLs──▶ tryParseMarkdownToBlocks ─▶ editor
 *   editor.document ──blocksToMarkdownLossy──data URLs→markers──▶ parent
 *
 * Images pasted natively into BlockNote arrive as data URLs; the reconcile
 * step registers each new one as an attachment and rewrites it to the
 * envelope marker, so the encrypted wire format carries attachments exactly
 * as before. Scale metadata travels in the marker's alt text (the image's
 * caption in the editor).
 */
import {
	BlockNoteSchema,
	defaultBlockSpecs,
	filterSuggestionItems,
	type BlockNoteEditor as BlockNoteEditorType,
} from "@blocknote/core";
import { BlockNoteView } from "@blocknote/mantine";
import {
	SuggestionMenuController,
	getDefaultReactSlashMenuItems,
	useCreateBlockNote,
	type DefaultReactSuggestionItem,
} from "@blocknote/react";
import "@blocknote/core/fonts/inter.css";
import "@blocknote/mantine/style.css";
import {
	useCallback,
	useEffect,
	useRef,
	useState,
	type PointerEvent as ReactPointerEvent,
} from "react";
import { useTheme } from "next-themes";
import { ListTree } from "lucide-react";
import { useToast } from "@/hooks/use-toast";
import type { EnvelopeFile } from "@/lib/pgp/envelope";
import { dataUrlsToMarkers, markersToDataUrls, type OnNewImageDataUrl } from "./MessageEditor";

// Drop the media blocks the composer never needs — the envelope wire format
// carries text + IMAGE attachments only. (audio/video/file blocks would
// inline payloads as non-image data URLs that the reconcile step can't
// carry into the envelope.)
const { audio, video, file, ...keptBlockSpecs } = defaultBlockSpecs;

void audio;
void video;
void file;

const schema = BlockNoteSchema.create({
	blockSpecs: keptBlockSpecs,
});

/** "Insert table of contents" as a / command — TOC insertion lives in the
 *  slash menu, not only in the composer utility row. Builds a GitHub-style
 *  TOC from the document's headings and prepends it.
 *
 *  # Mr. AI Acting on s183173's Behalf */
const insertTableOfContentsSlashItem = (editor: Editor): DefaultReactSuggestionItem => ({
	title: "Table of contents",
	subtext: "Insert a TOC from the document headings",
	onItemClick: () => {
		void (async () => {
			const md = await editor.blocksToMarkdownLossy();
			const rows: string[] = [];
			for (const line of md.split("\n")) {
				const match = /^(#{1,6})\s+(.*)$/.exec(line);
				if (!match) continue;
				const title = match[2].trim().replace(/\[([^\]]*)\]\([^)]*\)/g, "$1");
				const slug = title
					.toLowerCase()
					.replace(/[^\p{L}\p{N}\s-]/gu, "")
					.replace(/\s+/g, "-");
				rows.push(`${"  ".repeat(match[1].length - 1)}- [${title}](#${slug})`);
			}
			if (rows.length === 0) return;
			const tocBlocks = await editor.tryParseMarkdownToBlocks(`${rows.join("\n")}\n`);
			if (tocBlocks && tocBlocks.length > 0) {
				editor.insertBlocks(tocBlocks, editor.document[0], "before");
			}
		})();
	},
	aliases: ["toc", "table of contents", "outline"],
	group: "Advanced",
	icon: <ListTree size={18} />,
});

/** Slash menu = the defaults + the TOC item. */
function getSlashMenuItems(editor: Editor, query: string) {
	return filterSuggestionItems(
		[...getDefaultReactSlashMenuItems(editor), insertTableOfContentsSlashItem(editor)],
		query,
	);
}

type Editor = BlockNoteEditorType<
	typeof schema.blockSchema,
	typeof schema.inlineContentSchema,
	typeof schema.styleSchema
>;

export default function BlockNoteEditor({
	value,
	onChange,
	files,
	onNewImageDataUrl,
	onFilesDropped,
	expanded = false,
}: {
	value: string;
	onChange: (text: string) => void;
	files: EnvelopeFile[];
	onNewImageDataUrl: OnNewImageDataUrl;
	/** Round 18: non-image files the editor can't carry — PASTED or
	 *  DROPPED — forwarded to the composer's attachment flow. Absent →
	 *  the editor keeps its old guidance-toast fallback instead. */
	onFilesDropped?: (files: File[]) => void;
	placeholder?: string;
	/** Full-screen composer overlay mode (round-12 editor pass):
	 *  # Mr. AI Acting on s183173's Behalf
	 *  the wrapper fills the overlay through an h-full + flex chain and
	 *  the fixed composer min-heights are dropped so BlockNote grows with
	 *  the viewport (.bn-container owns the scrolling). */
	expanded?: boolean;
}) {
	const { resolvedTheme } = useTheme();
	// Fallback guidance for non-image pastes/drops when the parent didn't
	// thread the onFilesDropped bridge (round 18).
	const { toast } = useToast();

	// Latest props, read inside callbacks without re-creating the editor.
	// (Assigned in an effect — refs must not be updated during render.)
	const latest = useRef({ onChange, files, onNewImageDataUrl, onFilesDropped });
	useEffect(() => {
		latest.current = { onChange, files, onNewImageDataUrl, onFilesDropped };
	});

	// Accessible name + textbox semantics for the inner ProseMirror
	// contenteditable (.tiptap). BlockNoteView does not forward aria-label to
	// it, and axe flags a bare contenteditable div twice over: no accessible
	// name (aria-input-field-name) and a label on a role-prohibited element
	// (aria-prohibited-attr). Mount-only — the element is created once.
	const viewRef = useRef<HTMLDivElement>(null);
	useEffect(() => {
		const el = viewRef.current?.querySelector<HTMLElement>(".tiptap");
		if (el) {
			el.setAttribute("role", "textbox");
			el.setAttribute("aria-multiline", "true");
			el.setAttribute("aria-label", "Message (markdown)");
		}
	}, []);

	const editor: Editor = useCreateBlockNote({
		schema,
		pasteHandler: ({ event, defaultPasteHandler }) => {
			const items = event.clipboardData?.items;
			if (!items) return defaultPasteHandler();
			const imageFiles: File[] = [];
			const otherFiles: File[] = [];
			for (let i = 0; i < items.length; i++) {
				const it = items[i];
				if (it.kind !== "file") continue;
				const f = it.getAsFile();
				if (!f) continue;
				if (f.type.startsWith("image/")) imageFiles.push(f);
				else otherFiles.push(f);
			}
			if (imageFiles.length === 0 && otherFiles.length === 0) return defaultPasteHandler();

			// Round 18: non-image pastes FORWARD to the composer's attachment
			// flow (onFilesDropped) instead of dying in BlockNote's default
			// handler — which logs "uploadFile is not set" and does nothing.
			// The toast is only the fallback when the parent didn't thread
			// the bridge.
			if (otherFiles.length > 0) {
				const forward = latest.current.onFilesDropped;
				if (forward) {
					forward(otherFiles);
				} else {
					toast({
						title: "Files can't be pasted into the message",
						description: "Attach them with the Add files control below the composer instead.",
					});
					return defaultPasteHandler();
				}
			}
			if (imageFiles.length === 0) return true; // consumed: forwarded only

			// Own the image paste: register each image as an attachment, then
			// insert it as a block rendering the stored data URL. The onChange
			// reconcile below rewrites the data URL to an envelope marker.
			void (async () => {
				for (const f of imageFiles) {
					const dataUrl = await new Promise<string>((resolve, reject) => {
						const reader = new FileReader();
						reader.onload = () => resolve(typeof reader.result === "string" ? reader.result : "");
						reader.onerror = () => reject(reader.error ?? new Error("FileReader error"));
						reader.readAsDataURL(f);
					});
					let stored: EnvelopeFile;
					try {
						stored = latest.current.onNewImageDataUrl(dataUrl);
					} catch {
						continue;
					}
					const cursor = editor.getTextCursorPosition().block;
					editor.insertBlocks(
						[{ type: "image", props: { url: dataUrl, caption: stored.name } }],
						cursor,
						"after",
					);
				}
			})();
			return true;
		},
	});

	// Value the editor currently reflects — guards the sync effect against
	// feedback loops with our own onChange output.
	const syncedValue = useRef<string | null>(null);

	// Push outside changes (reset / tab remount / paste-inserted markers from
	// the parent) into the editor.
	useEffect(() => {
		if (syncedValue.current === value) return;
		syncedValue.current = value;
		const md = markersToDataUrls(value, latest.current.files);
		let blocks: Editor["document"] | undefined;
		try {
			blocks = editor.tryParseMarkdownToBlocks(md);
		} catch {
			blocks = undefined;
		}
		const next =
			blocks && blocks.length > 0
				? blocks
				: [{ type: "paragraph" as const, content: value ? md : "" }];
		editor.replaceBlocks(editor.document, next);
	}, [value, editor]);

	// Editor → parent: serialize, reconcile images, push.
	useEffect(() => {
		const unsub = editor.onChange(() => {
			const { onChange: push, files: currentFiles, onNewImageDataUrl: register } = latest.current;
			try {
				const md = editor.blocksToMarkdownLossy();
				const reconciled = dataUrlsToMarkers(md, currentFiles, register);
				// An empty document (one bare paragraph) serializes to "\n" —
				// pushing that back left the parent holding a phantom 1-char
				// message after every seal-and-clear (the size counter showed
				// "1 chars" on an empty composer). Image-only documents carry
				// envelope:// markers, so they still count as content.
				const clean = reconciled.trim() === "" ? "" : reconciled;
				syncedValue.current = clean;
				if (clean !== value) push(clean);
			} catch {
				// Never let a serialization hiccup break typing.
			}
		});
		return unsub;
	}, [editor]);

	// Round 18: file drops are consumed BY THE EDITOR — images insert
	// inline blocks (paste parity) keeping their REAL filename via
	// onNewImageDataUrl's suggestedName; non-images forward through
	// onFilesDropped. Capture phase + stopPropagation so a consumed drop
	// never ALSO reaches the tab-level attachment dropzone (double
	// attachments) — which is exactly why EncryptTab resets its drag
	// overlay from handleComposerFilesDropped instead of onDrop.
	const handleEditorDropCapture = (e: React.DragEvent<HTMLDivElement>) => {
		const files = Array.from(e.dataTransfer?.files ?? []);
		if (files.length === 0) return; // text / internal drags: normal drop
		const images = files.filter((f) => f.type.startsWith("image/"));
		const others = files.filter((f) => !f.type.startsWith("image/"));
		// Without the parent bridge we can only handle pure-image drops
		// here; anything carrying non-image files keeps the old behavior
		// (bubbles to the tab-level dropzone → addFiles).
		if (others.length > 0 && !latest.current.onFilesDropped) return;
		e.preventDefault();
		e.stopPropagation();
		void (async () => {
			for (const f of images) {
				const dataUrl = await new Promise<string>((resolve, reject) => {
					const reader = new FileReader();
					reader.onload = () => resolve(typeof reader.result === "string" ? reader.result : "");
					reader.onerror = () => reject(reader.error ?? new Error("FileReader error"));
					reader.readAsDataURL(f);
				});
				let stored: EnvelopeFile;
				try {
					stored = latest.current.onNewImageDataUrl(dataUrl, f.name);
				} catch {
					continue;
				}
				const cursor = editor.getTextCursorPosition().block;
				editor.insertBlocks(
					[{ type: "image", props: { url: dataUrl, caption: stored.name } }],
					cursor,
					"after",
				);
			}
			// ALWAYS notify when the bridge exists — even with an EMPTY list
			// (image-only drop): the parent resets its drag overlay on the
			// call itself, forwarded or not.
			latest.current.onFilesDropped?.(others);
		})();
	};

	// Drag-select in the editor's left sidebar/margin ("drag in sidebars of
	// the markdown editor to make a drag select box"): pressing in the
	// gutter starts a selection rectangle; every block whose box intersects
	// is selected by extending the browser's native selection from the
	// first to the last intersecting block — copy/delete keep working.
	//
	// # Mr. AI Acting on s183173's Behalf
	const [dragBox, setDragBox] = useState<{ x: number; y: number; w: number; h: number } | null>(
		null,
	);
	const gutterDrag = useRef<{ startY: number; startX: number } | null>(null);

	const blockElements = useCallback((): HTMLElement[] => {
		const root = viewRef.current;
		if (!root) return [];
		return Array.from(root.querySelectorAll<HTMLElement>(".bn-block-content"));
	}, []);

	const selectRange = useCallback(
		(startY: number, endY: number, startX: number, endX: number) => {
			const blocks = blockElements();
			if (blocks.length === 0) return;
			const top = Math.min(startY, endY);
			const bottom = Math.max(startY, endY);
			const left = Math.min(startX, endX);
			const right = Math.max(startX, endX);
			const hit = blocks.filter((el) => {
				const r = el.getBoundingClientRect();
				return r.bottom >= top && r.top <= bottom && r.right >= left && r.left <= right;
			});
			if (hit.length === 0) return;
			const first = hit[0];
			const last = hit[hit.length - 1];
			const range = document.createRange();
			range.setStartBefore(first);
			range.setEndAfter(last);
			const sel = window.getSelection();
			sel?.removeAllRanges();
			sel?.addRange(range);
		},
		[blockElements],
	);

	const onGutterPointerDown = useCallback(
		(e: ReactPointerEvent<HTMLDivElement>) => {
			if (e.button !== 0) return;
			e.preventDefault();
			gutterDrag.current = { startY: e.clientY, startX: e.clientX };
			const move = (ev: PointerEvent) => {
				const d = gutterDrag.current;
				if (!d) return;
				setDragBox({
					x: Math.min(d.startX, ev.clientX),
					y: Math.min(d.startY, ev.clientY),
					w: Math.abs(ev.clientX - d.startX),
					h: Math.abs(ev.clientY - d.startY),
				});
				selectRange(d.startY, ev.clientY, d.startX, ev.clientX);
			};
			const up = () => {
				gutterDrag.current = null;
				setDragBox(null);
				window.removeEventListener("pointermove", move);
				window.removeEventListener("pointerup", up);
			};
			window.addEventListener("pointermove", move);
			window.addEventListener("pointerup", up);
		},
		[selectRange],
	);
	const editorShell =
		"overflow-hidden rounded-xl border border-border bg-card shadow-sm transition-colors focus-within:border-[#0055dc]/50 focus-within:ring-2 focus-within:ring-[#0055dc]/20 dark:focus-within:border-[#5e94ff]/50 dark:focus-within:ring-[#5e94ff]/20";
	return (
		<div
			ref={viewRef}
			onDropCapture={handleEditorDropCapture}
			// Full-screen overlay: fill the viewport through an h-full + flex
			// chain and drop the fixed composer min-heights (.bn-container owns
			// the scrolling); the inline composer keeps them.
			className={
				expanded
					? `${editorShell} flex h-full min-h-0 flex-col [&_.bn-container]:bg-transparent [&>.bn-container]:min-h-0 [&>.bn-container]:flex [&>.bn-container]:flex-1 [&>.bn-container]:flex-col [&>.bn-container]:overflow-y-auto [&_.bn-editor]:min-h-0 [&_.bn-editor]:px-8 [&_.bn-editor]:py-4 [&_.bn-editor]:leading-relaxed`
					: `${editorShell} min-h-[320px] [&_.bn-container]:bg-transparent [&_.bn-editor]:min-h-[300px] [&_.bn-editor]:px-8 [&_.bn-editor]:py-4 [&_.bn-editor]:leading-relaxed`
			}
		>
			{/* Left-margin drag-select surface: sits beside the blocks, never on
                            top of them (pointer-events only on the 24px strip). */}
			<div
				aria-hidden="true"
				onPointerDown={onGutterPointerDown}
				className="absolute inset-y-0 left-0 z-10 w-6 cursor-default select-none"
			/>
			{dragBox && (
				<div
					aria-hidden="true"
					className="pointer-events-none fixed z-40 rounded border border-[#0055dc]/60 bg-[#0055dc]/10 dark:border-[#5e94ff]/60 dark:bg-[#5e94ff]/10"
					style={{ left: dragBox.x, top: dragBox.y, width: dragBox.w, height: dragBox.h }}
				/>
			)}
			<BlockNoteView
				editor={editor}
				theme={resolvedTheme === "dark" ? "dark" : "light"}
				slashMenu={false}
				aria-label="Message (markdown)"
			>
				<SuggestionMenuController
					triggerCharacter="/"
					getItems={async (query) => getSlashMenuItems(editor, query)}
				/>
			</BlockNoteView>
		</div>
	);
}
