"use client";

/**
 * InitializedMDXEditor — a Next.js App Router client wrapper that wires up
 * the MDXEditor formatting-plugin set once, and lets callers add a toolbar
 * + any extra plugins without repeating the list. Follows the official
 * MDXEditor Next.js guidance.
 *
 * The base plugin set is the "modern rich-text" feature surface
 * (Google-Docs-like): headings, lists, link (with dialog), quote, thematic
 * break, table, image, frontmatter, code blocks (CodeMirror syntax
 * highlighting), and markdown shortcuts (`**bold**` etc.).
 *
 * Pass `toolbarContents` to render a formatting toolbar (edit mode); omit it
 * for a read-only viewer. Extra plugins (e.g. `diffSourcePlugin`) can be passed
 * via `extraPlugins`.
 */
import type { ForwardedRef, ReactNode } from "react";
import {
  headingsPlugin,
  listsPlugin,
  quotePlugin,
  thematicBreakPlugin,
  linkPlugin,
  linkDialogPlugin,
  imagePlugin,
  tablePlugin,
  frontmatterPlugin,
  codeBlockPlugin,
  codeMirrorPlugin,
  markdownShortcutPlugin,
  toolbarPlugin,
  MDXEditor,
  type MDXEditorMethods,
  type MDXEditorProps,
} from "@mdxeditor/editor";
import "@mdxeditor/editor/style.css";

export default function InitializedMDXEditor({
  editorRef,
  toolbarContents,
  extraPlugins = [],
  ...props
}: {
  editorRef?: ForwardedRef<MDXEditorMethods>;
  /** When provided, a formatting toolbar is rendered above the content. */
  toolbarContents?: () => ReactNode;
  /** Additional plugins appended to the base set (e.g. diff source). */
  extraPlugins?: MDXEditorProps["plugins"];
} & Omit<MDXEditorProps, "plugins" | "ref">) {
  const plugins: MDXEditorProps["plugins"] = [
    toolbarContents ? toolbarPlugin({ toolbarContents }) : null,
    headingsPlugin(),
    listsPlugin(),
    quotePlugin(),
    thematicBreakPlugin(),
    linkPlugin(),
    linkDialogPlugin(),
    imagePlugin(),
    tablePlugin(),
    frontmatterPlugin(),
    codeBlockPlugin({ defaultCodeBlockLanguage: "txt" }),
    codeMirrorPlugin({
      codeBlockLanguages: {
        js: "JavaScript",
        ts: "TypeScript",
        tsx: "TypeScript React",
        jsx: "JavaScript React",
        css: "CSS",
        html: "HTML",
        json: "JSON",
        bash: "Bash",
        py: "Python",
        txt: "text",
      },
    }),
    markdownShortcutPlugin(),
    ...(extraPlugins ?? []),
  ].filter(Boolean) as MDXEditorProps["plugins"];

  return <MDXEditor plugins={plugins} {...props} ref={editorRef} />;
}
