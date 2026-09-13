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
  type BlockNoteEditor as BlockNoteEditorType,
} from "@blocknote/core";
import { BlockNoteView } from "@blocknote/mantine";
import { useCreateBlockNote } from "@blocknote/react";
import "@blocknote/core/fonts/inter.css";
import "@blocknote/mantine/style.css";
import { useEffect, useRef } from "react";
import { useTheme } from "next-themes";
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
}: {
  value: string;
  onChange: (text: string) => void;
  files: EnvelopeFile[];
  onNewImageDataUrl: OnNewImageDataUrl;
  placeholder?: string;
}) {
  const { resolvedTheme } = useTheme();

  // Latest props, read inside callbacks without re-creating the editor.
  // (Assigned in an effect — refs must not be updated during render.)
  const latest = useRef({ onChange, files, onNewImageDataUrl });
  useEffect(() => {
    latest.current = { onChange, files, onNewImageDataUrl };
  });

  const editor: Editor = useCreateBlockNote({
    schema,
    pasteHandler: ({ event, defaultPasteHandler }) => {
      const items = event.clipboardData?.items;
      if (!items) return defaultPasteHandler();
      const imageFiles: File[] = [];
      for (let i = 0; i < items.length; i++) {
        const it = items[i];
        if (it.kind === "file" && it.type.startsWith("image/")) {
          const f = it.getAsFile();
          if (f) imageFiles.push(f);
        }
      }
      if (imageFiles.length === 0) return defaultPasteHandler();

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
        syncedValue.current = reconciled;
        if (reconciled !== value) push(reconciled);
      } catch {
        // Never let a serialization hiccup break typing.
      }
    });
    return unsub;
  }, [editor]);

  return (
    <BlockNoteView
      editor={editor}
      theme={resolvedTheme === "dark" ? "dark" : "light"}
      aria-label="Message (markdown)"
    />
  );
}
