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
 *
 * Notion-grade touches (this pass):
 *   - The custom `placeholder` prop reaches the editor via the dictionary
 *     (the per-tab copy shows on the empty, unfocused composer).
 *   - Table header rows are enabled (`tables.headers`) — they export as GFM
 *     `th` and survive the markdown bridge.
 *   - Code blocks carry a language <select> (exports as the fence info
 *     string) and a hover "Copy" chip.
 *   - The slash menu's image entry is device-upload only: the URL-embed
 *     panel let remote https images into the wire, which every recipient
 *     silently blocks (tracking-pixel posture) — a dead end for the sender.
 *   - The formatting toolbar drops the color picker: colors never survive
 *     the markdown bridge, so the button advertised something the
 *     recipient would never see.
 *   - A callout block (amber card) exports as `> 💡 …`, so it degrades to
 *     an honest quoted line for recipients and the sanitize schema stays
 *     untouched.
 */
import {
	BlockNoteSchema,
	createCodeBlockSpec,
	defaultBlockSpecs,
	filterSuggestionItems,
	insertOrUpdateBlockForSlashMenu,
	type BlockNoteEditor as BlockNoteEditorType,
} from "@blocknote/core";
import { en } from "@blocknote/core/locales";
import { BlockNoteView } from "@blocknote/mantine";
import {
	BasicTextStyleButton,
	BlockTypeSelect,
	CreateLinkButton,
	ExperimentalMobileFormattingToolbarController,
	FormattingToolbar,
	FormattingToolbarController,
	NestBlockButton,
	SuggestionMenuController,
	TextAlignButton,
	UnnestBlockButton,
	createReactBlockSpec,
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
import { Check, Copy, ImagePlus, Lightbulb } from "lucide-react";
import { useToast } from "@/hooks/use-toast";
import type { EnvelopeFile } from "@/lib/pgp/envelope";
import { dataUrlsToMarkers, markersToDataUrls, type OnNewImageDataUrl } from "./MessageEditor";

// Drop the media blocks the composer never needs — the envelope wire format
// carries text + IMAGE attachments only. (audio/video/file blocks would
// inline payloads as non-image data URLs that the reconcile step can't
// carry into the envelope.) The default codeBlock is replaced further down
// with a language-aware spec.
const { audio, video, file, codeBlock: _defaultCodeBlock, ...keptBlockSpecs } = defaultBlockSpecs;

void audio;
void video;
void file;
void _defaultCodeBlock;

/** Languages offered by the code block's language select. The key is the
 *  fence info string on the wire (```python …), the name is the <option>
 *  label. Text first = the default. Aliases cover the common short forms
 *  people type after three backticks (```py …). */
const CODE_LANGUAGES = {
	text: { name: "Text", aliases: ["plain", "txt"] },
	javascript: { name: "JavaScript", aliases: ["js", "jsx", "node"] },
	typescript: { name: "TypeScript", aliases: ["ts", "tsx"] },
	python: { name: "Python", aliases: ["py"] },
	bash: { name: "Bash", aliases: ["sh", "shell", "zsh"] },
	json: { name: "JSON" },
	html: { name: "HTML" },
	css: { name: "CSS" },
	markdown: { name: "Markdown", aliases: ["md"] },
};

/** Language-aware code block. BlockNote's built-in spec THROWS when a block
 *  carries a language outside supportedLanguages — and the fence input rule
 *  happily sets any language the user typed (```ruby). The render override
 *  downgrades unknown languages to the plain text look instead of crashing
 *  the editor; the markdown keeps the original fence untouched. */
const codeBlockSpec = createCodeBlockSpec({
	defaultLanguage: "text",
	supportedLanguages: CODE_LANGUAGES,
});

// (cast) The render is a method that reads `this`-provided context, so the
// wrapper must forward it — extracting it as a free function crashes.
type CodeBlockRenderFn = (
	this: unknown,
	block: { id: string; props: { language: string } },
	controller: unknown,
) => unknown;
const originalRender = codeBlockSpec.implementation.render as unknown as CodeBlockRenderFn;
(codeBlockSpec.implementation as unknown as { render: CodeBlockRenderFn }).render = function (
	this: unknown,
	block,
	controller,
) {
	if (block.props.language in CODE_LANGUAGES) {
		return originalRender.call(this, block, controller);
	}
	return originalRender.call(
		this,
		{ ...block, props: { ...block.props, language: "text" } },
		controller,
	);
};

/** Callout block: an amber "note" card with a Notion-style icon chip.
 *  Exports as `> <emoji> …` — a GFM quote every recipient renders — and
 *  parses back from ANY emoji-prefixed quote so editor round-trips keep
 *  the chosen icon. Zero sanitizer changes by design.
 *
 *  # Mr. AI Acting on s183173's Behalf */

/** Notion-style icon palette — clicking the chip on a callout card cycles
 *  through it. The emoji rides the wire inside the quote text, so the
 *  recipient's plain-markdown renderer shows exactly this character. */
const CALLOUT_ICONS = ["💡", "ℹ️", "⚠️", "✅", "🔥", "❌", "📌", "🎯"];

/** Leading-emoji matcher for parsing quotes back into callouts. Accepts a
 *  pictographic head (with optional FE0F/ZWJ sequences) followed by
 *  whitespace — plain quotes never become callouts. */
const CALLOUT_EMOJI_PREFIX_RE =
	/^(\p{Extended_Pictographic}(?:\uFE0F|\u200D\p{Extended_Pictographic})*)[\s\u00A0]+/u;

/** Strip a leading emoji (plus trailing whitespace) out of the parsed
 *  blockquote's DOM so the icon becomes the block's `emoji` PROP instead of
 *  literal inline content — otherwise the card would render the icon twice
 *  after every markdown round-trip. */
function stripCalloutEmoji(element: Element, emoji: string): void {
	for (const node of Array.from(element.childNodes)) {
		if (node.nodeType !== Node.TEXT_NODE) continue;
		const text = node.textContent ?? "";
		const idx = text.indexOf(emoji);
		if (idx === -1) continue;
		const rest = text.slice(idx + emoji.length).replace(/^[\s\u00A0]+/, "");
		if (rest) node.textContent = rest;
		else element.removeChild(node);
		return;
	}
}

const calloutBlockSpec = createReactBlockSpec(
	{
		type: "callout",
		propSchema: { emoji: { default: "💡" } },
		content: "inline",
	},
	{
		render: ({ block, editor, contentRef }) => {
			const emoji = block.props.emoji || "💡";
			return (
				<div
					data-callout
					className="my-1 flex gap-2.5 rounded-lg border border-amber-300/60 bg-amber-50 px-3 py-2 dark:border-amber-500/30 dark:bg-amber-950/30"
				>
					<button
						type="button"
						contentEditable={false}
						aria-label="Change callout icon"
						title="Click to change the callout icon"
						onMouseDown={(e) => e.preventDefault()}
						onClick={() => {
							const idx = CALLOUT_ICONS.indexOf(emoji);
							const next = CALLOUT_ICONS[(idx + 1) % CALLOUT_ICONS.length] ?? CALLOUT_ICONS[0];
							editor.updateBlock(block, { props: { emoji: next } });
						}}
						className="mt-0.5 flex size-6 shrink-0 items-center justify-center rounded-md text-base leading-none transition-colors hover:bg-black/5 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#0055dc]/40 dark:hover:bg-white/10 dark:focus-visible:ring-[#5e94ff]/40"
					>
						{emoji}
					</button>
					<div ref={contentRef} className="flex-1 text-sm leading-relaxed" />
				</div>
			);
		},
		toExternalHTML: ({ block, contentRef }) => (
			<blockquote>
				{block.props.emoji || "💡"}&nbsp;
				<div ref={contentRef} />
			</blockquote>
		),
		parse: (element) => {
			if (element.tagName !== "BLOCKQUOTE") return undefined;
			const match = CALLOUT_EMOJI_PREFIX_RE.exec(element.textContent?.trimStart() ?? "");
			if (!match) return undefined;
			stripCalloutEmoji(element, match[1]);
			return { emoji: match[1] };
		},
	},
)();

const schema = BlockNoteSchema.create({
	blockSpecs: {
		...keptBlockSpecs,
		codeBlock: codeBlockSpec,
		callout: calloutBlockSpec,
	},
});

type Editor = BlockNoteEditorType<
	typeof schema.blockSchema,
	typeof schema.inlineContentSchema,
	typeof schema.styleSchema
>;

/** FileReader as a promise — shared by the paste, drop and slash-insert
 *  image paths (DRY). */
function fileToDataUrl(file: File): Promise<string> {
	return new Promise((resolve, reject) => {
		const reader = new FileReader();
		reader.onload = () => resolve(typeof reader.result === "string" ? reader.result : "");
		reader.onerror = () => reject(reader.error ?? new Error("FileReader error"));
		reader.readAsDataURL(file);
	});
}

/** Register a local image as an attachment and insert it at the cursor.
 *  One code path for paste, drop and the slash-menu insert. */
async function insertLocalImage(
	editor: Editor,
	file: File,
	register: OnNewImageDataUrl,
): Promise<void> {
	const dataUrl = await fileToDataUrl(file);
	const stored = register(dataUrl, file.name);
	const cursor = editor.getTextCursorPosition().block;
	editor.insertBlocks(
		[{ type: "image", props: { url: dataUrl, caption: stored.name } }],
		cursor,
		"after",
	);
}

/** Device-upload "Insert image" — replaces the default Image item whose
 *  URL-embed panel could put remote https images on the wire that
 *  recipients then refuse to render. */
const insertImageSlashItem = (pickImage: () => void): DefaultReactSuggestionItem => ({
	title: "Insert image",
	subtext: "Upload an image from this device",
	aliases: ["image", "picture", "photo", "upload"],
	group: "Media",
	icon: <ImagePlus size={18} />,
	onItemClick: pickImage,
});

/** Callout slash item — turns the current block into the amber note card.
 *  The icon chip on the card cycles the emoji (Notion's change-icon
 *  affordance), so a single menu item covers all callout flavors. */
const calloutSlashItem = (editor: Editor): DefaultReactSuggestionItem => ({
	title: "Callout",
	subtext: "Highlighted note — click the icon on the card to change it",
	aliases: ["callout", "note", "highlight", "info", "warning"],
	group: "Basic blocks",
	icon: <Lightbulb size={18} />,
	onItemClick: () => insertOrUpdateBlockForSlashMenu(editor, { type: "callout" }),
});

/** Slash menu = defaults (minus the URL-embed image trap) + insert-image +
 *  callout. The title check matches the shipped English dictionary. Items
 *  are stable-sorted by group so each group renders exactly one header
 *  (custom items appended blindly produce duplicate "Basic blocks"/
 *  "Advanced" sections — and React duplicate-key errors). */
const GROUP_ORDER = ["Headings", "Subheadings", "Basic blocks", "Advanced", "Media", "Others"];

/** Group rank for the stable sort; unknown groups sort last (before only
 *  undefined ones). */
const rank = (group: string | undefined): number => {
	const idx = group ? GROUP_ORDER.indexOf(group) : -1;
	return idx === -1 ? GROUP_ORDER.length : idx;
};

function getSlashMenuItems(editor: Editor, query: string, pickImage: () => void) {
	const defaults = getDefaultReactSlashMenuItems(editor).filter((item) => item.title !== "Image");
	const items = [...defaults, insertImageSlashItem(pickImage), calloutSlashItem(editor)].sort(
		(a, b) => rank(a.group) - rank(b.group),
	);
	return filterSuggestionItems(items, query);
}

/** Formatting toolbar minus ColorStyleButton: text/background colors die in
 *  the markdown bridge, so the picker advertised styling recipients would
 *  never see. Inline code style is kept — it round-trips as backticks. */
function ComposerFormattingToolbar() {
	return (
		<FormattingToolbar>
			<BlockTypeSelect key={"blockTypeSelect"} />
			<BasicTextStyleButton basicTextStyle="bold" key="boldStyleButton" />
			<BasicTextStyleButton basicTextStyle="italic" key="italicStyleButton" />
			<BasicTextStyleButton basicTextStyle="underline" key="underlineStyleButton" />
			<BasicTextStyleButton basicTextStyle="strike" key="strikeStyleButton" />
			<BasicTextStyleButton basicTextStyle="code" key="codeStyleButton" />
			<TextAlignButton textAlignment="left" key="textAlignLeftButton" />
			<TextAlignButton textAlignment="center" key="textAlignCenterButton" />
			<NestBlockButton key="nestBlockButton" />
			<UnnestBlockButton key="unnestBlockButton" />
			<CreateLinkButton key="createLinkButton" />
		</FormattingToolbar>
	);
}

/** Compact toolbar for the mobile bottom bar. The desktop floating toolbar
 *  clips off-viewport at phone widths (the link button falls off at 390px),
 *  so below the sm breakpoint we dock the same actions to the bottom of the
 *  screen instead — horizontally scrollable, above the virtual keyboard.
 *  Alignment buttons are the cut: they need a visual anchor mobile users
 *  don't have mid-typing, and the slash menu covers the rest. */
function ComposerMobileFormattingToolbar() {
	return (
		<FormattingToolbar>
			<BlockTypeSelect key={"blockTypeSelect"} />
			<BasicTextStyleButton basicTextStyle="bold" key="boldStyleButton" />
			<BasicTextStyleButton basicTextStyle="italic" key="italicStyleButton" />
			<BasicTextStyleButton basicTextStyle="underline" key="underlineStyleButton" />
			<BasicTextStyleButton basicTextStyle="code" key="codeStyleButton" />
			<NestBlockButton key="nestBlockButton" />
			<UnnestBlockButton key="unnestBlockButton" />
			<CreateLinkButton key="createLinkButton" />
		</FormattingToolbar>
	);
}

/** Match the Tailwind sm breakpoint — the point where the floating toolbar's
 *  widest row stops fitting the viewport. Listens live, so a window drag
 *  across the threshold swaps the controllers without a reload. */
function usePrefersMobileToolbar(): boolean {
	const [mobile, setMobile] = useState(
		() => typeof window !== "undefined" && window.matchMedia("(max-width: 640px)").matches,
	);
	useEffect(() => {
		const mq = window.matchMedia("(max-width: 640px)");
		const onChange = (e: MediaQueryListEvent) => setMobile(e.matches);
		mq.addEventListener("change", onChange);
		return () => mq.removeEventListener("change", onChange);
	}, []);
	return mobile;
}

/** Hover "Copy" chip for code blocks. Fixed-positioned from the block's
 *  bounding rect; hidden on scroll (cheap, always correct). */
function useCodeCopyChip(viewRef: React.RefObject<HTMLDivElement | null>) {
	const [chip, setChip] = useState<{ top: number; left: number; text: string } | null>(null);
	const [copied, setCopied] = useState(false);

	useEffect(() => {
		const root = viewRef.current;
		if (!root) return;
		const findBlock = (target: EventTarget | null) =>
			target instanceof HTMLElement
				? target.closest<HTMLElement>('[data-content-type="codeBlock"]')
				: null;
		const onOver = (e: MouseEvent) => {
			const block = findBlock(e.target);
			if (!block) {
				setChip(null);
				return;
			}
			const rect = block.getBoundingClientRect();
			setChip({ top: rect.top + 6, left: rect.right - 34, text: block.textContent ?? "" });
		};
		const hide = () => setChip(null);
		root.addEventListener("mouseover", onOver);
		window.addEventListener("scroll", hide, true);
		return () => {
			root.removeEventListener("mouseover", onOver);
			window.removeEventListener("scroll", hide, true);
		};
	}, [viewRef]);

	const copy = useCallback(() => {
		if (!chip) return;
		void navigator.clipboard.writeText(chip.text).then(() => {
			setCopied(true);
			setTimeout(() => setCopied(false), 1200);
		});
	}, [chip]);

	const chipElement = chip ? (
		<button
			type="button"
			onClick={copy}
			aria-label="Copy code"
			title="Copy code"
			className="fixed z-30 flex size-7 items-center justify-center rounded-md border border-border bg-background/95 text-muted-foreground shadow-sm backdrop-blur transition-colors hover:text-foreground"
			style={{ top: chip.top, left: chip.left }}
		>
			{copied ? (
				<Check aria-hidden className="size-3.5 text-emerald-600" />
			) : (
				<Copy aria-hidden className="size-3.5" />
			)}
		</button>
	) : null;

	return chipElement;
}

/** Quote blocks that carry an emoji prefix must become callout blocks.
 *
 *  WHY: ProseMirror tries parse rules in schema order, and the built-in
 *  `quote` block (registered before our custom `callout`) claims every
 *  <blockquote> first — the callout's own `parse` never runs on the
 *  markdown→blocks path. Without this pass, every remount of the editor
 *  (expand/collapse the composer, switch engines, template apply) silently
 *  degraded callouts to plain quotes — the "callouts look different big
 *  mode vs small mode" report: the block literally changed TYPE.
 *
 *  The pass walks the parsed tree (recursing into children) and rewrites
 *  emoji-prefixed quotes into callouts, moving the emoji into the `emoji`
 *  prop so the card doesn't render the icon twice. Plain quotes pass
 *  through untouched. */
function promoteCalloutQuotes(blocks: Editor["document"]): Editor["document"] {
	return blocks.map((block) => {
		const withChildren =
			"children" in block && Array.isArray(block.children)
				? { ...block, children: promoteCalloutQuotes(block.children as Editor["document"]) }
				: block;
		if (withChildren.type !== "quote") return withChildren;
		const content = withChildren.content;
		if (!Array.isArray(content) || content.length === 0) return withChildren;
		const first = content[0];
		if (first.type !== "text") return withChildren;
		const match = CALLOUT_EMOJI_PREFIX_RE.exec(first.text);
		if (!match) return withChildren;
		const restText = first.text.slice(match[0].length);
		const restContent = [...(restText ? [{ ...first, text: restText }] : []), ...content.slice(1)];
		return {
			id: withChildren.id,
			type: "callout" as const,
			props: { emoji: match[1] },
			content: restContent,
		} as Editor["document"][number];
	});
}

export default function BlockNoteEditor({
	value,
	onChange,
	files,
	onNewImageDataUrl,
	onFilesDropped,
	placeholder,
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
	// Full-screen overlay just opened: move focus into the editor so
	// keyboard users are not left behind the aria-modal surface (the
	// portal renders outside the tab panel, so focus must be explicit).
	// Re-runs on every expand; a collapse keeps focus where the user
	// clicked (the overlay unmounts entirely).
	useEffect(() => {
		if (!expanded) return;
		const id = requestAnimationFrame(() => {
			viewRef.current?.querySelector<HTMLElement>(".bn-editor")?.focus();
		});
		return () => cancelAnimationFrame(id);
	}, [expanded]);
	useEffect(() => {
		const el = viewRef.current?.querySelector<HTMLElement>(".tiptap");
		if (el) {
			el.setAttribute("role", "textbox");
			el.setAttribute("aria-multiline", "true");
			el.setAttribute("aria-label", "Message (markdown)");
		}
	}, []);

	// Hidden image picker for the slash-menu "Insert image" item. The
	// change handler lives below the editor creation (it needs the editor).
	const imageInputRef = useRef<HTMLInputElement>(null);
	const pickImage = useCallback(() => imageInputRef.current?.click(), []);

	const editor: Editor = useCreateBlockNote({
		schema,
		tables: { headers: true },
		dictionary: {
			...en,
			placeholders: {
				...en.placeholders,
				// Empty + unfocused composer hint (the per-tab copy).
				emptyDocument: placeholder ?? en.placeholders.default,
			},
		},
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
					try {
						await insertLocalImage(editor, f, (dataUrl, suggestedName) =>
							latest.current.onNewImageDataUrl(dataUrl, suggestedName),
						);
					} catch {
						continue;
					}
				}
			})();
			return true;
		},
	});

	// Image picker change handler — after the editor exists.
	const handleImagePick = useCallback(
		(e: React.ChangeEvent<HTMLInputElement>) => {
			const picked = Array.from(e.target.files ?? []).filter((f) => f.type.startsWith("image/"));
			e.target.value = ""; // re-picking the same file must re-fire change
			for (const f of picked) {
				void insertLocalImage(editor, f, (dataUrl, suggestedName) =>
					latest.current.onNewImageDataUrl(dataUrl, suggestedName),
				).catch(() => {
					// A skipped image is better than a broken composer.
				});
			}
		},
		[editor],
	);

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
			if (blocks && blocks.length > 0) blocks = promoteCalloutQuotes(blocks);
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
	}, [editor, value]);

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
				try {
					await insertLocalImage(editor, f, (dataUrl, suggestedName) =>
						latest.current.onNewImageDataUrl(dataUrl, suggestedName),
					);
				} catch {
					continue;
				}
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
	const codeCopyChip = useCodeCopyChip(viewRef);
	const mobileToolbar = usePrefersMobileToolbar();
	// Keyboard offset: BlockNote's experimental controller tracks the
	// virtual keyboard itself (VirtualKeyboard API + visualViewport
	// fallback → --bn-mobile-keyboard-offset) — no custom listener needed.
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
					? `${editorShell} flex h-full min-h-0 flex-col [&_.bn-container]:bg-transparent [&>.bn-container]:min-h-0 [&>.bn-container]:flex [&>.bn-container]:flex-1 [&>.bn-container]:flex-col [&>.bn-container]:overflow-y-auto [&_.bn-editor]:min-h-0 [&_.bn-editor]:flex-1 [&_.bn-editor]:px-8 [&_.bn-editor]:py-4 [&_.bn-editor]:leading-relaxed`
					: `${editorShell} min-h-[320px] [&_.bn-container]:bg-transparent [&_.bn-editor]:min-h-[300px] [&_.bn-editor]:px-8 [&_.bn-editor]:py-4 [&_.bn-editor]:leading-relaxed`
			}
		>
			<input
				ref={imageInputRef}
				type="file"
				accept="image/*"
				multiple
				onChange={handleImagePick}
				className="sr-only"
				aria-hidden="true"
				tabIndex={-1}
			/>
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
			{codeCopyChip}
			<BlockNoteView
				editor={editor}
				theme={resolvedTheme === "dark" ? "dark" : "light"}
				slashMenu={false}
				// The child controllers own the toolbar; the built-in would
				// otherwise ALSO render its default floating toolbar next to the
				// experimental mobile controller (which doesn't register as an
				// override and suppress it).
				formattingToolbar={false}
				aria-label="Message (markdown)"
			>
				<SuggestionMenuController
					triggerCharacter="/"
					getItems={async (query) => getSlashMenuItems(editor, query, pickImage)}
				/>
				{mobileToolbar ? (
					<ExperimentalMobileFormattingToolbarController
						formattingToolbar={ComposerMobileFormattingToolbar}
					/>
				) : (
					<FormattingToolbarController formattingToolbar={ComposerFormattingToolbar} />
				)}
			</BlockNoteView>
		</div>
	);
}
