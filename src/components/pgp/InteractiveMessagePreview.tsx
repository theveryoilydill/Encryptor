"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  findInlineImageMarkers,
  updateMarkerTransform,
  removeMarker as removeInlineImageMarker,
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
 * Mouse:
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
 * The component is purely presentational + interactive — it reads `plaintext`
 * and `files` and calls `onChange(nextPlaintext)` whenever the user moves,
 * scales, or removes an image. The parent owns the plaintext state.
 *
 * Used in the Encrypt tab as the primary "what your message looks like"
 * preview, and can also be used in the Decrypt tab (read-only mode).
 */
export function InteractiveMessagePreview({
  plaintext,
  files,
  onChange,
  readOnly = false,
  minHeight = 120,
  emptyPlaceholder = "Your message preview will appear here.",
}: {
  plaintext: string;
  files: EnvelopeFile[];
  /** Called with the new plaintext whenever the user moves, scales, or
   *  removes an image. Ignored when `readOnly` is true. */
  onChange?: (next: string) => void;
  /** When true, images are not selectable/draggable and no keyboard
   *  shortcuts are active. Used for the Decrypt-tab preview. */
  readOnly?: boolean;
  minHeight?: number;
  emptyPlaceholder?: string;
}) {
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

  // --- Drag state ---
  const dragRef = useRef<{
    markerIndex: number;
    startMouseX: number;
    startMouseY: number;
    startDx: number;
    startDy: number;
  } | null>(null);

  const handleMouseDown = useCallback(
    (e: React.MouseEvent, markerIndex: number) => {
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
      };
    },
    [markers, readOnly, onChange],
  );

  // Global mousemove + mouseup handlers for dragging.
  useEffect(() => {
    if (readOnly || !onChange) return;
    const handleChange = onChange; // capture for closure
    function onMouseMove(e: MouseEvent) {
      const drag = dragRef.current;
      if (!drag) return;
      const dx = drag.startDx + (e.clientX - drag.startMouseX);
      const dy = drag.startDy + (e.clientY - drag.startMouseY);
      const next = updateMarkerTransform(plaintext, drag.markerIndex, {
        dx,
        dy,
      });
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
  const containerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (readOnly || !onChange) return;
    const handleChange = onChange; // capture for closure
    function onKeyDown(e: KeyboardEvent) {
      // Only act when an image is selected.
      if (selectedIndex === null) return;
      const marker = markers[selectedIndex];
      if (!marker) return;

      // When an image is selected, intercept navigation keys (arrows,
      // Escape, Delete, Backspace) regardless of which element has focus.
      // This lets the user click an image and immediately use keyboard
      // shortcuts without first clicking away from the textarea.
      // Regular character input (letters, numbers, etc.) passes through
      // normally so the user can still type.
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
        handleChange(next);
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
        handleChange(next);
      }
    }
    // Attach to document so it works even if the container doesn't have focus.
    document.addEventListener("keydown", onKeyDown);
    return () => document.removeEventListener("keydown", onKeyDown);
  }, [selectedIndex, markers, plaintext, onChange, readOnly]);

  // --- Rendering ---
  if (!plaintext.trim() && markers.length === 0) {
    return (
      <div
        className="rounded-md border border-neutral-200 bg-neutral-50 px-3.5 py-3 text-sm text-neutral-400"
        style={{ minHeight }}
      >
        {emptyPlaceholder}
      </div>
    );
  }

  return (
    <div
      ref={containerRef}
      className="rounded-md border border-neutral-200 bg-white px-3.5 py-3 overflow-hidden"
      style={{ minHeight }}
      // Clicking the empty area deselects.
      onClick={(e) => {
        if (e.target === e.currentTarget) setSelectedIndex(null);
      }}
      // Make the container focusable so keyboard shortcuts work after click.
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
                // Apply the user's scale + position transform.
                // The image width is set to `scale%` of the container, then
                // the translate(dx, dy) offset is applied.
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
                  // Keep a min height so tiny scales don't vanish.
                  minHeight: "20px",
                }}
                className={`rounded border-2 transition-colors ${
                  isSelected
                    ? "border-[#0055dc] shadow-md"
                    : readOnly
                      ? "border-neutral-200"
                      : "border-neutral-300 hover:border-[#0055dc]/50 cursor-move"
                }`}
                onMouseDown={(e) => handleMouseDown(e, markerIndex)}
                onClick={(e) => {
                  e.stopPropagation();
                  if (!readOnly) setSelectedIndex(markerIndex);
                }}
                draggable={false}
              />
              {/* Show a small label with scale + position when selected. */}
              {isSelected && (
                <span className="absolute -top-6 left-0 text-[10px] font-mono bg-[#0055dc] text-white px-1.5 py-0.5 rounded whitespace-nowrap pointer-events-none">
                  {marker.scale}% @ ({marker.dx}, {marker.dy})
                </span>
              )}
            </span>
          );
        })}
      </div>

      {/* Help text — only shown in edit mode when there's at least one image. */}
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
