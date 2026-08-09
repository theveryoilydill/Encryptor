"use client";

/**
 * RichTextEditor — the Encrypt-tab composer for "modern rich text" mode.
 *
 * A WYSIWYG Markdown editor (MDXEditor) with a Google-Docs-like formatting
 * toolbar (bold/italic/underline, headings, lists, link, quote, code block,
 * thematic break, table, image, undo/redo). Serializes to Markdown on every
 * change; the parent feeds that Markdown into `buildPlaintextForEncryptionV2`.
 *
 * Inline images use the same `envelope://filename` marker system as the
 * plaintext mode (pasting an image adds it to the attachments and drops a
 * marker) so rich and plaintext content compose identically on the wire.
 *
 * Styled to match the rest of Encryptor: bordered white card, #0055dc accents.
 * `next/dynamic(ssr:false)` Lazy-loaded by PgpApp so the heavy MDXEditor bundle
 * only ships when the user picks "Rich text".
 */
import {
  BoldItalicUnderlineToggles,
  BlockTypeSelect,
  CreateLink,
  InsertImage,
  ListsToggle,
  InsertThematicBreak,
  InsertCodeBlock,
  UndoRedo,
  InsertTable,
} from "@mdxeditor/editor";
import InitializedMDXEditor from "./InitializedMDXEditor";

export function RichTextEditor({
  value,
  onChange,
  placeholder,
}: {
  value: string;
  onChange: (markdown: string) => void;
  placeholder?: string;
}) {
  return (
    <div className="rounded-md border border-neutral-300 bg-white overflow-hidden focus-within:border-[#0055dc] focus-within:ring-2 focus-within:ring-[#0055dc]/30 transition-colors">
      <InitializedMDXEditor
        markdown={value}
        onChange={onChange}
        placeholder={placeholder ?? "Write a richly-formatted message…"}
        contentEditableClassName="min-h-[160px] px-3.5 py-3 text-sm leading-relaxed text-neutral-900 outline-none"
        toolbarContents={() => (
          // Toolbar styled to match Encryptor: thin bottom border, blue accents.
          <div className="flex flex-wrap items-center gap-1 border-b border-neutral-200 bg-neutral-50 px-2 py-1.5 [&_button]:h-7 [&_button]:rounded-md [&_button]:px-1.5 [&_button]:text-neutral-700 [&_button:hover]:bg-neutral-200/60 [&_button[aria-pressed='true']]:bg-[#0055dc]/10 [&_button[aria-pressed='true']]:text-[#0055dc] [&_svg]:size-4">
            <UndoRedo />
            <BlockTypeSelect />
            <BoldItalicUnderlineToggles />
            <ListsToggle />
            <CreateLink />
            <InsertImage />
            <InsertTable />
            <InsertThematicBreak />
            <InsertCodeBlock />
          </div>
        )}
      />
    </div>
  );
}
