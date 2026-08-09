"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  findInlineImageMarkers,
  updateMarkerTransform,
  removeMarker as removeInlineImageMarker,
  buildInlineImageMarker,
  MOVE_STEP_MICRO,
  MOVE_STEP_NORMAL,
  SCALE_STEP_MICRO,
  SCALE_STEP_NORMAL,
  type InlineImageMarker,
} from "@/lib/pgp/inline-image";
import type { EnvelopeFile } from "@/lib/pgp/envelope";

/**
 * InteractiveMessagePreview — renders a message with inline images and lets
 * the user scale/move each image with the mouse and keyboard.
 *
 * Two operating modes, selected by the `editable` prop:
 *
 *  - `editable={false}` (default): a read-only rendered preview (Encrypt-tab
 *    legacy "Preview" box, and the Decrypt-tab preview). Images can still be
 *    selected/dragged/scaled/deleted when an `onChange` is supplied, but the
 *    text is non-editable.
 *  - `editable={true}`: the surface becomes a contentEditable box — the user
 *    types text directly, and inline `envelope://` image markers render as
 *    draggable/scalable `<img>` chips live in the same surface. This is the
 *    plaintext "the message box IS the preview" mode: one unified surface.
 *
 * Mouse (every mode with `onChange`):
 *   - Click an image to select it (shown with a blue outline).
 *   - Drag a selected image to move it (updates dx, dy in real time).
 *
 * Keyboard (when an image is selected):
 *   - Arrow keys       → move by 10px (MOVE_STEP_NORMAL)
 *   - Shift + Arrow    → micro-move by 1px  (MOVE_STEP_MICRO)
 *   - Alt + Arrow      → scale by 5%        (SCALE_STEP_NORMAL)
 *   - Shift+Alt+Arrow  → micro-scale by 1%  (SCALE_STEP_MICRO)
 *   - Delete / Backspace → remove the image
 *   - Escape           → deselect
 *
 * The parent owns the plaintext state. In editable mode, typing fires `input`
 * → the DOM is walked to reconstruct the plaintext string (text segments +
 * image markers reconstructed from each chip's stable `data-*` attributes) and
 * `onChange(nextPlaintext)` is called. The DOM is the source of truth while
 * the surface is focused; we only re-render from the `plaintext` prop when the
 * surface is NOT focused (an external change, e.g. a paste inserting a
 * marker), which avoids clobbering the user's caret mid-keystroke.
 */

/** Stable attributes we stamp onto each image chip so we can reconstruct its
 *  marker from the DOM without re-parsing the text. */
const CHIP_FILENAME = "data-img-filename";
const CHIP_SCALE = "data-img-scale";
const CHIP_DX = "data-img-dx";
const CHIP_DY = "data-img-dy";
const CHIP_NAME = "data-img-name";
const CHIP_INDEX = "data-img-index";

/** Compute the character offset of the live text caret within an editable
 *  message surface, expressed as an index into the RECONSTRUCTED plaintext
 *  string (where image chips count as their full marker length).
 *
 *  Used by the plaintext paste handler to splice a new marker in at the caret
 *  across an async file read (a Range wouldn't survive the await, so we
 *  resolve to a stable integer offset first). Returns 0 if the surface has no
 *  selection or the caret isn't reachable. */
export function getEditableSelectionOffset(root: HTMLElement): number {
  const sel = window.getSelection();
  if (!sel || sel.rangeCount === 0) return 0;
  const range = sel.getRangeAt(0);
  // Typing at the shell edge can clone sibling `[data-content-root]` blocks;
  // fold them into one before resolving the caret so the offset is stable.
  normalizeContentRoots(root);
  const inner = (root.querySelector("[data-content-root]") ?? root) as HTMLElement;
  const container = range.startContainer;
  const offsetInContainer = range.startOffset;

  // If the caret lives directly in the content root (e.g. empty surface, or
  // between two chip elements), map the child offset to a character offset.
  if (container === inner) {
    let acc = 0;
    for (let i = 0; i < offsetInContainer && i < inner.childNodes.length; i++) {
      acc += nodeLength(inner.childNodes[i]);
    }
    return acc;
  }

  // Otherwise walk child nodes in document order, accumulating length until
  // we reach the caret's container node; then add the within-node caret offset.
  let acc = 0;
  let found = false;
  const visit = (n: Node): void => {
    if (found) return;
    if (n === container) {
      if (n.nodeType === Node.TEXT_NODE) {
        acc += Math.min(offsetInContainer, (n.textContent ?? "").length);
      } else if (n.nodeType === Node.ELEMENT_NODE) {
        // Caret inside an element: child offset maps to preceding siblings.
        let local = 0;
        for (let i = 0; i < offsetInContainer && i < n.childNodes.length; i++) {
          local += nodeLength(n.childNodes[i]);
        }
        acc += local;
      }
      found = true;
      return;
    }
    if (n.nodeType === Node.TEXT_NODE) {
      acc += (n.textContent ?? "").length;
    } else if (n.nodeType === Node.ELEMENT_NODE) {
      const el = n as HTMLElement;
      if (el.hasAttribute(CHIP_FILENAME)) {
        acc += chipMarkerLength(el);
        return; // don't descend into the chip
      }
      for (let i = 0; i < n.childNodes.length; i++) visit(n.childNodes[i]);
    }
  };
  for (let i = 0; i < inner.childNodes.length; i++) visit(inner.childNodes[i]);
  return Math.max(0, acc);
}

/** Reconstructed-plaintext length of a single DOM node (text → its length,
 *  chip element → its marker length, other element → its text length). */
function nodeLength(n: Node): number {
  if (n.nodeType === Node.TEXT_NODE) return (n.textContent ?? "").length;
  if (n.nodeType === Node.ELEMENT_NODE) {
    const el = n as HTMLElement;
    if (el.hasAttribute(CHIP_FILENAME)) return chipMarkerLength(el);
    return (el.textContent ?? "").length;
  }
  return 0;
}

/** Length of the inline-image marker a chip element reconstructs to. */
function chipMarkerLength(el: HTMLElement): number {
  return buildInlineImageMarker(
    el.getAttribute(CHIP_FILENAME) ?? "",
    Number(el.getAttribute(CHIP_SCALE) ?? "50"),
    Number(el.getAttribute(CHIP_DX) ?? "0"),
    Number(el.getAttribute(CHIP_DY) ?? "0"),
    el.getAttribute(CHIP_NAME) ?? undefined,
  ).length;
}

/** All `[data-content-root]` blocks under a shell, in document order. The
 *  editable surface seeds exactly one, but typing Enter at the shell edge
 *  makes the browser clone extra sibling `[data-content-root]` blocks (one
 *  per line); a single `querySelector` would miss them. Falls back to the
 *  shell itself when no root exists (e.g. the empty-state branch). */
function getContentRoots(shell: HTMLElement): HTMLElement[] {
  const roots = Array.from(shell.querySelectorAll<HTMLElement>("[data-content-root]"));
  return roots.length ? roots : [shell];
}

/** Collapse any browser-created sibling `[data-content-root]` blocks back
 *  into the first one, inserting a `<br>` at each block boundary so the line
 *  break survives the merge. Restores the single-root invariant the component
 *  relies on for reads, caret offsets, and `renderFromProp`. No-op when the
 *  surface already has one root. */
function normalizeContentRoots(shell: HTMLElement): void {
  const roots = Array.from(shell.querySelectorAll<HTMLElement>("[data-content-root]"));
  if (roots.length <= 1) return;
  const first = roots[0];
  for (let i = 1; i < roots.length; i++) {
    first.appendChild(document.createElement("br"));
    while (roots[i].firstChild) first.appendChild(roots[i].firstChild as Node);
    roots[i].remove();
  }
}

export function InteractiveMessagePreview({
  plaintext,
  files,
  onChange,
  readOnly = false,
  editable = false,
  minHeight = 120,
  emptyPlaceholder = "Your message preview will appear here.",
}: {
  plaintext: string;
  files: EnvelopeFile[];
  /** Called with the new plaintext whenever the user moves, scales, or
   *  removes an image, or (in editable mode) types into the surface. Ignored
   *  when `readOnly` is true. */
  onChange?: (next: string) => void;
  /** When true, images are not selectable/draggable, the surface is not
   *  editable, and no keyboard shortcuts are active. Used for the Decrypt-tab
   *  preview. Implies `editable={false}`. */
  readOnly?: boolean;
  /** When true, the surface is contentEditable: the user types text directly
   *  and inline images render as live chips in the same surface. Cannot be
   *  combined with `readOnly`. */
  editable?: boolean;
  minHeight?: number;
  emptyPlaceholder?: string;
}) {
  const isEditable = editable && !readOnly && !!onChange;

  const markers = useMemo(() => findInlineImageMarkers(plaintext), [plaintext]);

  const [selectedIndex, setSelectedIndex] = useState<number | null>(null);

  // Build a filename → data URL map for resolving `envelope://` URIs.
  const fileMap = useMemo(() => {
    const m = new Map<string, EnvelopeFile>();
    for (const f of files) {
      if (!m.has(f.name)) m.set(f.name, f);
    }
    return m;
  }, [files]);

  // Split plaintext into ordered text/image segments.
  const segments = useMemo(() => {
    const out: Array<
      | { type: "text"; content: string }
      | { type: "image"; marker: InlineImageMarker; markerIndex: number }
    > = [];
    let lastIndex = 0;
    markers.forEach((marker, markerIndex) => {
      if (marker.startIndex > lastIndex) {
        out.push({
          type: "text",
          content: plaintext.slice(lastIndex, marker.startIndex),
        });
      }
      out.push({ type: "image", marker, markerIndex });
      lastIndex = marker.endIndex;
    });
    if (lastIndex < plaintext.length) {
      out.push({ type: "text", content: plaintext.slice(lastIndex) });
    }
    return out;
  }, [plaintext, markers]);

  // --- Editable surface refs + reconciliation ---
  const containerRef = useRef<HTMLDivElement>(null);
  // True while we are programmatically rewriting the DOM from the `plaintext`
  // prop, so the resulting `input` event doesn't recurse back into onChange.
  const reconcilingRef = useRef(false);
  // The plaintext value the DOM currently reflects. Used to decide whether an
  // incoming `plaintext` prop change is external (needs a DOM reconcile) or is
  // just our own onChange echoing back (DOM already matches — skip).
  const domValueRef = useRef(plaintext);

  /** Rebuild the plaintext string from the live DOM: walk child nodes in
   *  order, emitting text for text nodes and a reconstructed marker for each
   *  image chip. This is the "DOM is source of truth" path. */
  const readDomValue = useCallback(() => {
    const root = containerRef.current;
    if (!root) return domValueRef.current;
    let out = "";
    // We render into a single inner content wrapper, but typing Enter at the
    // shell edge can clone extra sibling `[data-content-root]` blocks. Walk
    // every block in document order, inserting a newline at each block
    // boundary so the line breaks survive reconstruction.
    const roots = getContentRoots(root);
    for (let r = 0; r < roots.length; r++) {
      if (r > 0) out += "\n";
      roots[r].childNodes.forEach((node) => {
        if (node.nodeType === Node.TEXT_NODE) {
          out += node.textContent ?? "";
          return;
        }
        if (node.nodeType === Node.ELEMENT_NODE) {
          const el = node as HTMLElement;
          if (el.hasAttribute(CHIP_FILENAME)) {
            const filename = el.getAttribute(CHIP_FILENAME) ?? "";
            const scale = Number(el.getAttribute(CHIP_SCALE) ?? "50");
            const dx = Number(el.getAttribute(CHIP_DX) ?? "0");
            const dy = Number(el.getAttribute(CHIP_DY) ?? "0");
            const name = el.getAttribute(CHIP_NAME) ?? filename;
            out += buildInlineImageMarker(filename, scale, dx, dy, name);
            return;
          }
          // Unknown element (e.g. a <br> from Enter) — coerce to text/newlines.
          if (el.tagName === "BR") {
            out += "\n";
            return;
          }
          out += el.textContent ?? "";
        }
      });
    }
    return out;
  }, []);

  /** Render the `plaintext` prop into the DOM by clearing + rebuilding the
   *  children from `segments`. Called on external prop changes (surface not
   *  focused) and on initial mount. */
  const renderFromProp = useCallback(() => {
    const root = containerRef.current;
    if (!root) return;
    const inner = root.querySelector<HTMLElement>("[data-content-root]");
    if (!inner) return; // empty-state branch owns the DOM
    reconcilingRef.current = true;
    // Build the new content as a string of HTML-safe text + chip elements.
    const frag = document.createDocumentFragment();
    for (const seg of segments) {
      if (seg.type === "text") {
        frag.appendChild(document.createTextNode(seg.content));
      } else {
        const { marker } = seg;
        const file = fileMap.get(marker.filename);
        const src = file ? `data:${file.type};base64,${file.data}` : null;
        // The chip is a span wrapping an <img> (so the transform offset can
        // be applied to the wrapper without disrupting the text flow). It
        // carries the reconstruction attrs so typing around it doesn't lose
        // the image's position/scale. The marker index is stamped too so an
        // editable-mode click can map back to the selected marker (the chips
        // here are imperative DOM with no React event handlers).
        const wrap = document.createElement("span");
        wrap.setAttribute(CHIP_FILENAME, marker.filename);
        wrap.setAttribute(CHIP_SCALE, String(marker.scale));
        wrap.setAttribute(CHIP_DX, String(marker.dx));
        wrap.setAttribute(CHIP_DY, String(marker.dy));
        wrap.setAttribute(CHIP_NAME, marker.displayName);
        wrap.setAttribute(CHIP_INDEX, String(seg.markerIndex));
        wrap.setAttribute("contenteditable", "false");
        wrap.className = "inline-block align-middle my-1";
        wrap.style.transform = `translate(${marker.dx}px, ${marker.dy}px)`;
        wrap.style.position = "relative";
        if (src) {
          const img = document.createElement("img");
          img.src = src;
          img.alt = marker.displayName;
          img.style.width = `${marker.scale}%`;
          img.style.maxWidth = "100%";
          img.style.minHeight = "20px";
          img.className = "rounded border-2 border-neutral-300";
          img.draggable = false;
          // Click-to-select in editable mode. mousedown is captured so the
          // caret doesn't land inside the non-editable chip; the index attr
          // maps the chip to the selected marker.
          const onChipDown = (e: MouseEvent) => {
            e.preventDefault();
            e.stopPropagation();
            const idx = Number(wrap.getAttribute(CHIP_INDEX));
            if (Number.isFinite(idx)) setSelectedIndex(idx);
          };
          const onChipClick = (e: MouseEvent) => {
            e.preventDefault();
            e.stopPropagation();
          };
          img.addEventListener("mousedown", onChipDown);
          img.addEventListener("click", onChipClick);
          wrap.appendChild(img);
        } else {
          const badge = document.createElement("span");
          badge.className =
            "inline-block mx-1 px-2 py-0.5 rounded bg-red-50 border border-red-200 text-red-700 text-[11px] italic";
          badge.textContent = `[missing image: ${marker.displayName}]`;
          wrap.appendChild(badge);
        }
        frag.appendChild(wrap);
      }
    }
    inner.replaceChildren(frag);
    domValueRef.current = plaintext;
    reconcilingRef.current = false;
  }, [segments, fileMap, plaintext]);

  // Initial mount render + reconcile on external prop change (surface not
  // focused). When the surface IS focused, the DOM is the source of truth;
  // a prop change here is just our own onChange echoing back, so skip.
  useEffect(() => {
    if (!isEditable) return;
    const root = containerRef.current;
    const focused = root?.contains(document.activeElement) && document.activeElement === root;
    if (!focused) {
      renderFromProp();
    } else {
      // While focused, only reconcile if the prop diverged AND it wasn't from
      // our own typing (e.g. a paste inserted a marker from the parent). We
      // compare against what we last told the DOM it held.
      if (plaintext !== domValueRef.current) {
        renderFromProp();
      }
    }
  }, [isEditable, plaintext, renderFromProp]);

  // In editable mode, an `input` event fires whenever the user types or the
  // DOM changes. Walk the DOM to reconstruct the plaintext and push it up.
  const handleInput = useCallback(() => {
    if (!isEditable || reconcilingRef.current) return;
    // The browser may have cloned sibling `[data-content-root]` blocks while
    // typing at the shell edge; fold them back into one before reading so the
    // single-root invariant holds and the caret stays put.
    if (containerRef.current) normalizeContentRoots(containerRef.current);
    const next = readDomValue();
    domValueRef.current = next;
    onChange?.(next);
  }, [isEditable, readDomValue, onChange]);

  // --- Drag state ---
  const dragRef = useRef<{
    markerIndex: number;
    startMouseX: number;
    startMouseY: number;
    startDx: number;
    startDy: number;
    // The chip element being dragged (editable mode), so we update its
    // transform live rather than going through a full DOM reconcile.
    chipEl: HTMLElement | null;
  } | null>(null);

  const handleMouseDown = useCallback(
    (e: React.MouseEvent, markerIndex: number, chipEl?: HTMLElement) => {
      if (readOnly || !onChange) return;
      e.preventDefault();
      const marker = markers[markerIndex];
      if (!marker) return;
      setSelectedIndex(markerIndex);
      dragRef.current = {
        markerIndex,
        startMouseX: e.clientX,
        startMouseY: e.clientY,
        startDx: marker.dx,
        startDy: marker.dy,
        chipEl: chipEl ?? null,
      };
    },
    [markers, readOnly, onChange],
  );

  // Global mousemove + mouseup handlers for dragging.
  useEffect(() => {
    if (readOnly || !onChange) return;
    const handleChange = onChange;
    function onMouseMove(e: MouseEvent) {
      const drag = dragRef.current;
      if (!drag) return;
      const dx = drag.startDx + (e.clientX - drag.startMouseX);
      const dy = drag.startDy + (e.clientY - drag.startMouseY);
      // Live-update the chip's inline transform for smooth feedback in
      // editable mode (avoids a full DOM reconcile per mousemove).
      if (drag.chipEl) {
        drag.chipEl.style.transform = `translate(${dx}px, ${dy}px)`;
        drag.chipEl.setAttribute(CHIP_DX, String(dx));
        drag.chipEl.setAttribute(CHIP_DY, String(dy));
      }
      const next = updateMarkerTransform(plaintext, drag.markerIndex, {
        dx,
        dy,
      });
      domValueRef.current = next;
      handleChange(next);
    }
    function onMouseUp() {
      dragRef.current = null;
    }
    document.addEventListener("mousemove", onMouseMove);
    document.addEventListener("mouseup", onMouseUp);
    return () => {
      document.removeEventListener("mousemove", onMouseMove);
      document.removeEventListener("mouseup", onMouseUp);
    };
  }, [plaintext, onChange, readOnly]);

  // --- Keyboard shortcuts ---
  // When an image is selected, arrow keys move it, Alt+arrows scale it,
  // Shift makes either a micro-adjustment, Delete removes it, Escape deselects.
  useEffect(() => {
    if (readOnly || !onChange) return;
    const handleChange = onChange;
    function onKeyDown(e: KeyboardEvent) {
      // Only act when an image is selected.
      if (selectedIndex === null) return;
      const marker = markers[selectedIndex];
      if (!marker) return;

      // When an image is selected, intercept navigation keys (arrows,
      // Escape, Delete, Backspace) regardless of which element has focus.
      // This lets the user click an image and immediately use keyboard
      // shortcuts without first clicking away. Regular character input
      // (letters, numbers, etc.) passes through normally so the user can
      // still type.
      const isImageKey =
        e.key === "ArrowUp" ||
        e.key === "ArrowDown" ||
        e.key === "ArrowLeft" ||
        e.key === "ArrowRight" ||
        e.key === "Escape" ||
        e.key === "Delete" ||
        e.key === "Backspace";
      if (!isImageKey) return;

      const shift = e.shiftKey;
      const alt = e.altKey;

      // Escape — deselect.
      if (e.key === "Escape") {
        setSelectedIndex(null);
        return;
      }

      // Delete / Backspace — remove the image.
      if (e.key === "Delete" || e.key === "Backspace") {
        e.preventDefault();
        const next = removeInlineImageMarker(plaintext, selectedIndex);
        domValueRef.current = next;
        handleChange(next);
        setSelectedIndex(null);
        return;
      }

      // Arrow keys — move or scale depending on modifier.
      const isArrow =
        e.key === "ArrowUp" ||
        e.key === "ArrowDown" ||
        e.key === "ArrowLeft" ||
        e.key === "ArrowRight";
      if (!isArrow) return;

      e.preventDefault();

      if (alt) {
        // Alt+arrow = scale. Up/Right = bigger, Down/Left = smaller.
        const step = shift ? SCALE_STEP_MICRO : SCALE_STEP_NORMAL;
        let delta = 0;
        if (e.key === "ArrowUp" || e.key === "ArrowRight") delta = step;
        else delta = -step;
        const newScale = marker.scale + delta;
        const next = updateMarkerTransform(plaintext, selectedIndex, {
          scale: newScale,
        });
        domValueRef.current = next;
        handleChange(next);
        // Live-update the chip's width + scale attr in editable mode.
        const chip = chipForMarkerIndex(selectedIndex);
        if (chip) {
          const img = chip.querySelector("img");
          if (img) img.style.width = `${newScale}%`;
          chip.setAttribute(CHIP_SCALE, String(newScale));
        }
      } else {
        // Arrow = move. Shift = micro (1px), normal = 10px.
        const step = shift ? MOVE_STEP_MICRO : MOVE_STEP_NORMAL;
        let dx = marker.dx;
        let dy = marker.dy;
        if (e.key === "ArrowLeft") dx -= step;
        if (e.key === "ArrowRight") dx += step;
        if (e.key === "ArrowUp") dy -= step;
        if (e.key === "ArrowDown") dy += step;
        const next = updateMarkerTransform(plaintext, selectedIndex, {
          dx,
          dy,
        });
        domValueRef.current = next;
        handleChange(next);
        const chip = chipForMarkerIndex(selectedIndex);
        if (chip) {
          chip.style.transform = `translate(${dx}px, ${dy}px)`;
          chip.setAttribute(CHIP_DX, String(dx));
          chip.setAttribute(CHIP_DY, String(dy));
        }
      }
    }
    /** Find the rendered chip element for a given marker index. In editable
     *  mode the chips are real DOM elements stamped with CHIP_FILENAME. */
    function chipForMarkerIndex(index: number): HTMLElement | null {
      const root = containerRef.current;
      if (!root) return null;
      const chips = Array.from(
        root.querySelectorAll<HTMLElement>(`[${CHIP_FILENAME}]`),
      );
      return chips[index] ?? null;
    }
    // Attach to document so it works even if the container doesn't have focus.
    document.addEventListener("keydown", onKeyDown);
    return () => document.removeEventListener("keydown", onKeyDown);
  }, [selectedIndex, markers, plaintext, onChange, readOnly]);

  // In editable mode the chips are imperative DOM, so the selection ring
  // (blue border + shadow) is applied here rather than via React. Restyle each
  // chip's <img> whenever the selection changes.
  useEffect(() => {
    if (!isEditable) return;
    const root = containerRef.current;
    if (!root) return;
    const chips = Array.from(root.querySelectorAll<HTMLElement>(`[${CHIP_FILENAME}]`));
    for (let i = 0; i < chips.length; i++) {
      const img = chips[i].querySelector("img");
      if (!img) continue;
      if (selectedIndex === i) {
        img.className =
          "rounded border-2 border-[#0055dc] shadow-md transition-colors";
      } else {
        img.className = "rounded border-2 border-neutral-300";
      }
    }
  }, [selectedIndex, isEditable, plaintext]);

  // --- Rendering ---
  const showEmpty =
    !plaintext.trim() && markers.length === 0 && !isEditable;

  if (showEmpty) {
    return (
      <div
        className="rounded-md border border-neutral-200 bg-neutral-50 px-3.5 py-3 text-sm text-neutral-400"
        style={{ minHeight }}
      >
        {emptyPlaceholder}
      </div>
    );
  }

  // Editable surface: a single contentEditable div. We render the inner
  // content imperatively (renderFromProp) to keep full control of caret /
  // chip stability; the React tree only owns the outer shell. A minimal
  // placeholder is shown via CSS :empty:before.
  if (isEditable) {
    return (
      <div
        ref={containerRef}
        contentEditable
        suppressContentEditableWarning
        role="textbox"
        aria-multiline="true"
        data-content-shell
        onInput={handleInput}
        onBlur={() => {
          // On blur, reconcile from the authoritative prop so the DOM
          // re-renders chips exactly (e.g. refresh missing-image badges).
          renderFromProp();
        }}
        onClick={(e) => {
          // Clicking empty space deselects.
          const t = e.target as HTMLElement;
          if (t === e.currentTarget || t.hasAttribute("data-content-root")) {
            setSelectedIndex(null);
          }
        }}
        className="rounded-md border border-neutral-300 bg-white px-3.5 py-3 overflow-hidden focus:outline-none focus:border-[#0055dc] focus:ring-2 focus:ring-[#0055dc]/20 editable-message"
        style={{ minHeight }}
        data-placeholder={emptyPlaceholder}
      >
        {/* renderFromProp populates this node. It must exist before the
            effect runs, so we render an empty wrapper here. The placeholder
            attr is mirrored here so the CSS :empty:before selector (scoped to
            the content root) can read it. */}
        <div
          data-content-root
          data-placeholder={emptyPlaceholder}
          className="whitespace-pre-wrap break-words text-sm text-neutral-900 leading-relaxed"
        />
      </div>
    );
  }

  // Read-only / non-editable render: the original React-driven preview.
  return (
    <div
      ref={containerRef}
      className="rounded-md border border-neutral-200 bg-white px-3.5 py-3 overflow-hidden"
      style={{ minHeight }}
      onClick={(e) => {
        if (e.target === e.currentTarget) setSelectedIndex(null);
      }}
      tabIndex={readOnly ? -1 : 0}
    >
      <div className="whitespace-pre-wrap break-words text-sm text-neutral-900 leading-relaxed">
        {segments.map((seg, i) => {
          if (seg.type === "text") {
            return <span key={i}>{seg.content}</span>;
          }
          const { marker, markerIndex } = seg;
          const file = fileMap.get(marker.filename);
          const src = file ? `data:${file.type};base64,${file.data}` : null;
          const isSelected = selectedIndex === markerIndex && !readOnly;

          if (!src) {
            return (
              <span
                key={i}
                className="inline-block mx-1 px-2 py-0.5 rounded bg-red-50 border border-red-200 text-red-700 text-[11px] italic"
              >
                [missing image: {marker.displayName}]
              </span>
            );
          }

          return (
            <span
              key={i}
              className="inline-block align-middle my-1"
              style={{
                transform: `translate(${marker.dx}px, ${marker.dy}px)`,
                position: "relative",
              }}
            >
              <img
                src={src}
                alt={marker.displayName}
                style={{
                  width: `${marker.scale}%`,
                  maxWidth: "100%",
                  minHeight: "20px",
                }}
                className={`rounded border-2 transition-colors ${
                  isSelected
                    ? "border-[#0055dc] shadow-md"
                    : readOnly
                      ? "border-neutral-200"
                      : "border-neutral-300 hover:border-[#0055dc]/50 cursor-move"
                }`}
                onMouseDown={(e) =>
                  handleMouseDown(e, markerIndex, e.currentTarget.parentElement ?? undefined)
                }
                onClick={(e) => {
                  e.stopPropagation();
                  if (!readOnly) setSelectedIndex(markerIndex);
                }}
                draggable={false}
              />
              {isSelected && (
                <span className="absolute -top-6 left-0 text-[10px] font-mono bg-[#0055dc] text-white px-1.5 py-0.5 rounded whitespace-nowrap pointer-events-none">
                  {marker.scale}% @ ({marker.dx}, {marker.dy})
                </span>
              )}
            </span>
          );
        })}
      </div>

      {!readOnly && markers.length > 0 && (
        <div className="mt-3 pt-2 border-t border-neutral-100 text-[10px] text-neutral-400">
          {selectedIndex !== null ? (
            <span>
              <kbd className="px-1 py-0.5 bg-neutral-100 rounded border border-neutral-200 font-mono">
                ←↑↓→
              </kbd>{" "}
              move ·{" "}
              <kbd className="px-1 py-0.5 bg-neutral-100 rounded border border-neutral-200 font-mono">
                Shift+←↑↓→
              </kbd>{" "}
              micro-move (1px) ·{" "}
              <kbd className="px-1 py-0.5 bg-neutral-100 rounded border border-neutral-200 font-mono">
                Alt+←↑↓→
              </kbd>{" "}
              scale ·{" "}
              <kbd className="px-1 py-0.5 bg-neutral-100 rounded border border-neutral-200 font-mono">
                Del
              </kbd>{" "}
              remove ·{" "}
              <kbd className="px-1 py-0.5 bg-neutral-100 rounded border border-neutral-200 font-mono">
                Esc
              </kbd>{" "}
              deselect
            </span>
          ) : (
            <span>Click an image to select it, then use arrow keys to move/scale.</span>
          )}
        </div>
      )}
    </div>
  );
}
