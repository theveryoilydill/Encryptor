"use client";

/**
 * RichTextViewer — the Decrypt-tab renderer for "modern rich text" messages.
 *
 * Renders the stored Markdown (the envelope's `text` for `kind:"rich"`) using
 * the same MDXEditor in read-only mode (no toolbar), so the rendered output is
 * visually identical to what the sender composed. Zero new deps: the editor's
 * own Markdown-rendering path is reused rather than pulling in react-markdown.
 *
 * Inline `envelope://filename` image markers are pre-resolved to `data:` URLs
 * from the `files` array (same scheme as the plaintext DecryptedMessageView),
 * since MDXEditor's image plugin only understands real URLs.
 */
import { useMemo } from "react";
import type { EnvelopeFile } from "@/lib/pgp/envelope";

import InitializedMDXEditor from "./InitializedMDXEditor";
import { findInlineImageMarkers } from "@/lib/pgp/inline-image";

function RichTextViewer({
  text,
  files = [],
}: {
  text: string;
  files?: EnvelopeFile[];
}) {
  // Resolve `envelope://filename` markers inside markdown image tags to data
  // URLs that the editor's image plugin can render. Anything referencing a
  // missing attachment is stripped (rather than rendering a broken img).
  const resolvedMarkdown = useMemo(() => {
    if (!text) return "";
    const byName = new Map<string, EnvelopeFile>();
    for (const f of files) if (!byName.has(f.name)) byName.set(f.name, f);
    const markers = findInlineImageMarkers(text);
    let out = text;
    // Replace markers with data: URLs from right to left so indices stay valid.
    for (let i = markers.length - 1; i >= 0; i--) {
      const m = markers[i];
      const file = byName.get(m.filename);
      const url = file ? `data:${file.type};base64,${file.data}` : null;
      const replacement = url
        ? `![${m.displayName}](${url})`
        : m.displayName
          ? `*[missing image: ${m.displayName}]*`
          : "";
      out = out.slice(0, m.startIndex) + replacement + out.slice(m.endIndex);
    }
    return out;
  }, [text, files]);

  return (
    <div className="rounded-md border border-neutral-200 bg-white px-3.5 py-3 min-h-[100px]">
      <InitializedMDXEditor
        markdown={resolvedMarkdown}
        readOnly
        contentEditableClassName="text-sm leading-relaxed text-neutral-900 outline-none [&_img]:max-w-full [&_img]:rounded [&_img]:border [&_img]:border-neutral-200"
      />
    </div>
  );
}

export { RichTextViewer };
