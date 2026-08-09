"use client";

/**
 * GraphBoard — Miro-style infinite whiteboard for Encryptor's "graph" mode.
 *
 * An infinite canvas (pan/zoom) where the user adds editable text-bearing
 * nodes (sticky note, rectangle, ellipse, text) and connectors between them.
 * The board state is a `GraphBoard` JSON object (see src/lib/pgp/envelope.ts)
 * that the parent serializes through the V2 envelope + PGP encrypt path.
 *
 * Interaction model (informed by Miro's web app, themed to Encryptor's blue/
 * white palette — no Miro branding):
 *
 *   Tools (left rail, icon buttons): Select, Sticky, Rect, Ellipse, Text,
 *   Image, Connector, Delete. Keyboard shortcuts mirror Miro: V select, T text,
 *   N sticky, R rect, O ellipse, I image, C connector.
 *
 *   Canvas: drag empty space (or hold Space + drag) to pan. Mouse wheel zooms
 *   toward the cursor. Bottom-right shows the zoom % and +/- / Fit buttons.
 *
 *   Nodes: click to select (blue outline + handles); drag body to move; drag
 *   the bottom-right handle to resize; double-click body to edit text inline;
 *   Delete/Backspace removes the selected node (and any connectors to/from it).
 *
 *   Connectors: with the Connector tool active, drag from a node's edge handle
 *   to another node. Edges render as straight arrows and follow node moves
 *   automatically (they're computed from node centers, not stored geometry).
 *
 *   `readOnly` (decrypt side) disables all mutation; nodes/edges still render
 *   and the canvas still pans/zooms for inspection.
 *
 * State lives in the parent (`board` prop + `onChange`); this component is
 * presentational + interactive, exactly like InteractiveMessagePreview.
 */
import {
  useCallback,
  useEffect,
  useRef,
  useState,
  type CSSProperties,
  type PointerEvent as ReactPointerEvent,
  type WheelEvent as ReactWheelEvent,
} from "react";
import { v4 as uuid } from "uuid";
import type {
  EnvelopeFile,
  GraphBoard as Board,
  GraphNode,
  NodeType,
  GraphEdge,
} from "@/lib/pgp/envelope";
import { SCALE_STEP_NORMAL, SCALE_STEP_MICRO } from "@/lib/pgp/inline-image";

// Image-node scale range — same bounds as inline image markers, but default
// scale for a freshly-placed board image is 100% (it has its own w/h box).
const DEFAULT_IMAGE_NODE_SCALE = 100;
const MIN_IMAGE_SCALE = 10;
const MAX_IMAGE_SCALE = 200;

/* ----------------------------- Tool palette ------------------------------- */

type Tool = "select" | "sticky" | "rect" | "ellipse" | "text" | "image" | "connect";

const TOOL_SHORTCUTS: Record<string, Tool> = {
  v: "select",
  t: "text",
  n: "sticky",
  r: "rect",
  o: "ellipse",
  i: "image",
  c: "connect",
};

// Node color palette — anchored on Encryptor blue, with a few neutrals.
const NODE_COLORS: Record<NodeType, string> = {
  sticky: "#fff7cc", // soft yellow, Miro-ish but muted
  rect: "#dbeafe", // light blue
  ellipse: "#e9e3ff", // light lavender
  text: "transparent",
  image: "transparent",
};
const NODE_BORDER: Record<NodeType, string> = {
  sticky: "#e6cf6b",
  rect: "#93c5fd",
  ellipse: "#c4b5fd",
  text: "transparent",
  image: "#93c5fd",
};

const DEFAULT_SIZE: Record<NodeType, { w: number; h: number }> = {
  sticky: { w: 200, h: 160 },
  rect: { w: 180, h: 110 },
  ellipse: { w: 160, h: 110 },
  text: { w: 180, h: 60 },
  image: { w: 200, h: 200 },
};

/* ------------------------------- Geometry ---------------------------------- */
// Everything is in canvas pixel space (unzoomed). The transform applies pan+zoom.

interface Viewport {
  zoom: number;
  panX: number;
  panY: number;
}

function center(node: GraphNode): { cx: number; cy: number } {
  return { cx: node.x + node.w / 2, cy: node.y + node.h / 2 };
}

/* ------------------------------- Component --------------------------------- */

export function GraphBoard({
  board,
  onChange,
  readOnly = false,
  minHeight = 360,
  files,
  onAddImageFile,
}: {
  board: Board;
  onChange?: (next: Board) => void;
  readOnly?: boolean;
  minHeight?: number;
  /**
   * Shared envelope attachments. Image nodes reference these by
   * `image.filename`; we resolve the matching file to a data URL for display.
   */
  files?: EnvelopeFile[];
  /**
   * Called when the user pastes an image directly onto the board. The parent
   * is responsible for adding it to the shared `files[]` pool (dedup + base64
   * conversion live there). GraphBoard uses the file's name as the node's
   * `image.filename` and resolves the pixel data from `files` on the next render.
   */
  onAddImageFile?: (file: File) => void;
}) {
  const [tool, setTool] = useState<Tool>("select");
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [viewport, setViewport] = useState<Viewport>({ zoom: 1, panX: 80, panY: 60 });
  const [spaceDown, setSpaceDown] = useState(false);

  const canvasRef = useRef<HTMLDivElement>(null);

  // Mutate the board immutably and report up.
  const update = useCallback(
    (mutator: (b: Board) => Board) => {
      if (readOnly || !onChange) return;
      onChange(mutator(structuredCloneSafe(board)));
    },
    [board, onChange, readOnly],
  );

  /* --------------------------- Tool: create node ---------------------------- */
  const addNode = useCallback(
    (type: NodeType, canvasX: number, canvasY: number) => {
      const { w, h } = DEFAULT_SIZE[type];
      // Image nodes reference the most-recently-added attachment by filename;
      // require one to exist before placing the node.
      if (type === "image") {
        const latest = files && files.length > 0 ? files[files.length - 1] : null;
        if (!latest) return; // nothing to place — the toolbar hint explains it
        const node: GraphNode = {
          id: uuid(),
          type: "image",
          x: Math.round(canvasX - w / 2),
          y: Math.round(canvasY - h / 2),
          w,
          h,
          text: "",
          color: NODE_COLORS.image,
          image: { filename: latest.name, scale: 100 },
        };
        update((b) => ({ ...b, nodes: [...b.nodes, node] }));
        setSelectedId(node.id);
        setTool("select");
        return;
      }
      const node: GraphNode = {
        id: uuid(),
        type,
        x: Math.round(canvasX - w / 2),
        y: Math.round(canvasY - h / 2),
        w,
        h,
        text: "",
        ...(type !== "text" ? { color: NODE_COLORS[type] } : {}),
      };
      update((b) => ({ ...b, nodes: [...b.nodes, node] }));
      setSelectedId(node.id);
      if (type !== "text") setEditingId(node.id);
      setTool("select");
    },
    [update, files],
  );

  /**
   * Paste an image directly onto the board: hand the raw File to the parent
   * (which owns dedup/base64 via `onAddImageFile`), then place an `image` node
   * at the center of the current viewport, keyed by the file's name.
   */
  const pasteImage = useCallback(
    async (file: File) => {
      const filename = file.name || `pasted-${uuid()}.${guessExt(file.type)}`;
      const resolved =
        file.name && files?.some((f) => f.name === file.name)
          ? file.name
          : filename;
      onAddImageFile?.(file);
      // Place at the canvas center of the current viewport.
      const el = canvasRef.current;
      if (!el) return;
      const rect = el.getBoundingClientRect();
      const cx = (rect.width / 2 - viewport.panX) / viewport.zoom;
      const cy = (rect.height / 2 - viewport.panY) / viewport.zoom;
      const { w, h } = DEFAULT_SIZE.image;
      const node: GraphNode = {
        id: uuid(),
        type: "image",
        x: Math.round(cx - w / 2),
        y: Math.round(cy - h / 2),
        w,
        h,
        text: "",
        color: NODE_COLORS.image,
        image: { filename: resolved, scale: 100 },
      };
      update((b) => ({ ...b, nodes: [...b.nodes, node] }));
      setSelectedId(node.id);
    },
    [onAddImageFile, update, viewport.panX, viewport.panY, viewport.zoom, files],
  );

  /* --------------------------- Paste / drop image --------------------------- */
  const extractImageFiles = (dataTransfer: DataTransfer | null): File[] => {
    if (!dataTransfer) return [];
    const out: File[] = [];
    if (dataTransfer.files && dataTransfer.files.length) {
      for (const f of Array.from(dataTransfer.files)) if (f.type.startsWith("image/")) out.push(f);
    }
    // Some browsers expose pasted images only via items.
    if (dataTransfer.items && dataTransfer.items.length) {
      for (const it of Array.from(dataTransfer.items)) {
        if (it.kind === "file" && it.type.startsWith("image/")) {
          const f = it.getAsFile();
          if (f && !out.some((x) => x === f)) out.push(f);
        }
      }
    }
    return out;
  };

  const onCanvasPaste = useCallback(
    (e: React.ClipboardEvent<HTMLDivElement>) => {
      if (readOnly) return;
      const imgs = extractImageFiles(e.clipboardData);
      if (imgs.length === 0) return; // let default paste proceed (do nothing)
      e.preventDefault();
      for (const img of imgs) void pasteImage(img);
    },
    [readOnly, pasteImage],
  );

  const onCanvasDragOver = useCallback(
    (e: React.DragEvent<HTMLDivElement>) => {
      if (readOnly) return;
      if (e.dataTransfer.types.includes("Files")) {
        // Allow drop so onCanvasDrop fires.
        e.preventDefault();
        e.dataTransfer.dropEffect = "copy";
      }
    },
    [readOnly],
  );

  const onCanvasDrop = useCallback(
    (e: React.DragEvent<HTMLDivElement>) => {
      if (readOnly) return;
      const imgs = extractImageFiles(e.dataTransfer);
      if (imgs.length === 0) return;
      e.preventDefault();
      for (const img of imgs) void pasteImage(img);
    },
    [readOnly, pasteImage],
  );

  /* ----------------------- Canvas → screen transform ------------------------ */
  const toCanvas = useCallback(
    (clientX: number, clientY: number) => {
      const el = canvasRef.current;
      if (!el) return { x: 0, y: 0 };
      const rect = el.getBoundingClientRect();
      const x = (clientX - rect.left - viewport.panX) / viewport.zoom;
      const y = (clientY - rect.top - viewport.panY) / viewport.zoom;
      return { x, y };
    },
    [viewport],
  );

  /* ------------------------------ Panning ---------------------------------- */
  const panRef = useRef<{ startX: number; startY: number; panX: number; panY: number } | null>(null);

  // Decide whether a pointer event landed on *empty canvas space* — i.e. the
  // bare canvas, the transparent content layer, or the empty-state hint — and
  // NOT on a node body, resize handle, or edge. Node/handle handlers call
  // `e.stopPropagation()`, but only on pointer DOWN; this check is the safety
  // net for the cases where a child still receives the event (e.g. the content
  // layer overlays the canvas and has no `data-empty` attribute of its own).
  const isEmptyCanvasSpace = (e: ReactPointerEvent): boolean => {
    const t = e.target as HTMLElement | null;
    if (!t) return false;
    // Anything carrying node/handle data is interactive board content.
    if (t.closest('[data-node-text],[data-node-editor],[data-graph-handle],[data-graph-canvas-node]')) {
      return false;
    }
    // The canvas itself, the content layer, and the empty-state placeholder
    // (pointer-events-none) are all "empty space" worth creating/panning on.
    return (
      t.hasAttribute("data-graph-canvas") ||
      t.hasAttribute("data-graph-content") ||
      e.currentTarget === t
    );
  };

  const onCanvasPointerDown = useCallback(
    (e: ReactPointerEvent<HTMLDivElement>) => {
      const emptySpace = isEmptyCanvasSpace(e);
      // Pan when: space held, or tool is select and clicking empty canvas,
      // or middle mouse.
      const shouldPan =
        !readOnly &&
        (spaceDown ||
          e.button === 1 ||
          (tool === "select" && emptySpace));
      // Create a node when a shape/text tool is active and clicking empty canvas.
      const wantCreate = !readOnly && tool !== "select" && tool !== "connect" && emptySpace;

      if (wantCreate) {
        e.preventDefault();
        const { x, y } = toCanvas(e.clientX, e.clientY);
        addNode(tool as NodeType, x, y);
        return;
      }
      if (shouldPan) {
        e.preventDefault();
        panRef.current = {
          startX: e.clientX,
          startY: e.clientY,
          panX: viewport.panX,
          panY: viewport.panY,
        };
        setSelectedId(null);
      } else if (emptySpace) {
        setSelectedId(null);
      }
    },
    [spaceDown, tool, readOnly, toCanvas, addNode, viewport.panX, viewport.panY],
  );

  useEffect(() => {
    function onMove(e: PointerEvent) {
      const pan = panRef.current;
      if (!pan) return;
      setViewport((v) => ({
        ...v,
        panX: pan.panX + (e.clientX - pan.startX),
        panY: pan.panY + (e.clientY - pan.startY),
      }));
    }
    function onUp() {
      panRef.current = null;
    }
    document.addEventListener("pointermove", onMove);
    document.addEventListener("pointerup", onUp);
    return () => {
      document.removeEventListener("pointermove", onMove);
      document.removeEventListener("pointerup", onUp);
    };
  }, []);

  /* ------------------------------- Zooming --------------------------------- */
  const onWheel = useCallback(
    (e: ReactWheelEvent<HTMLDivElement>) => {
      if (!e.ctrlKey && !e.metaKey && Math.abs(e.deltaY) < 20) {
        // Let plain vertical wheel pan the canvas (trackpad two-finger scroll).
        setViewport((v) => ({ ...v, panY: v.panY - e.deltaY }));
        return;
      }
      e.preventDefault();
      setViewport((v) => {
        const factor = Math.exp(-e.deltaY * 0.0015);
        const nextZoom = clamp(v.zoom * factor, 0.2, 3);
        // Zoom toward the cursor: keep the canvas point under the cursor fixed.
        const el = canvasRef.current;
        if (!el) return { ...v, zoom: nextZoom };
        const rect = el.getBoundingClientRect();
        const mx = e.clientX - rect.left;
        const my = e.clientY - rect.top;
        const cx = (mx - v.panX) / v.zoom;
        const cy = (my - v.panY) / v.zoom;
        return {
          zoom: nextZoom,
          panX: mx - cx * nextZoom,
          panY: my - cy * nextZoom,
        };
      });
    },
    [],
  );

  const setZoom = useCallback((z: number) => {
    setViewport((v) => {
      const el = canvasRef.current;
      const nextZoom = clamp(z, 0.2, 3);
      if (!el) return { ...v, zoom: nextZoom };
      const rect = el.getBoundingClientRect();
      // Keep center fixed when using the +/- buttons.
      const mx = rect.width / 2;
      const my = rect.height / 2;
      const cx = (mx - v.panX) / v.zoom;
      const cy = (my - v.panY) / v.zoom;
      return { zoom: nextZoom, panX: mx - cx * nextZoom, panY: my - cy * nextZoom };
    });
  }, []);

  /* ----------------------- Node drag + resize ------------------------------ */
  const dragRef = useRef<
    | { kind: "move"; id: string; startX: number; startY: number; nodeX: number; nodeY: number }
    | { kind: "resize"; id: string; startX: number; startY: number; w: number; h: number }
    | null
  >(null);

  const onNodePointerDown = useCallback(
    (e: ReactPointerEvent, node: GraphNode, mode: "move" | "resize") => {
      if (readOnly || tool === "connect") return;
      if (mode === "move") {
        dragRef.current = {
          kind: "move",
          id: node.id,
          startX: e.clientX,
          startY: e.clientY,
          nodeX: node.x,
          nodeY: node.y,
        };
      } else {
        dragRef.current = {
          kind: "resize",
          id: node.id,
          startX: e.clientX,
          startY: e.clientY,
          w: node.w,
          h: node.h,
        };
      }
      setSelectedId(node.id);
      e.stopPropagation();
      e.preventDefault();
    },
    [readOnly, tool],
  );

  useEffect(() => {
    if (readOnly) return;
    function onMove(e: PointerEvent) {
      const drag = dragRef.current;
      if (!drag) return;
      const dx = (e.clientX - drag.startX) / viewport.zoom;
      const dy = (e.clientY - drag.startY) / viewport.zoom;
      update((b) => ({
        ...b,
        nodes: b.nodes.map((n) => {
          if (n.id !== drag.id) return n;
          if (drag.kind === "move") return { ...n, x: Math.round(drag.nodeX + dx), y: Math.round(drag.nodeY + dy) };
          return {
            ...n,
            w: Math.max(40, Math.round(drag.w + dx)),
            h: Math.max(24, Math.round(drag.h + dy)),
          };
        }),
      }));
    }
    function onUp() {
      dragRef.current = null;
    }
    document.addEventListener("pointermove", onMove);
    document.addEventListener("pointerup", onUp);
    return () => {
      document.removeEventListener("pointermove", onMove);
      document.removeEventListener("pointerup", onUp);
    };
  }, [viewport.zoom, update, readOnly]);

  /* --------------------------- Connector drawing --------------------------- */
  const connectRef = useRef<{ fromId: string; startX: number; startY: number } | null>(null);

  const startConnect = useCallback(
    (e: ReactPointerEvent, from: GraphNode) => {
      if (readOnly || tool !== "connect") return;
      e.stopPropagation();
      e.preventDefault();
      const c = center(from);
      connectRef.current = { fromId: from.id, startX: c.cx, startY: c.cy };
      setSelectedId(from.id);
    },
    [readOnly, tool],
  );

  const [previewEdge, setPreviewEdge] = useState<{ x: number; y: number } | null>(null);

  useEffect(() => {
    if (readOnly) return;
    function onMove(e: PointerEvent) {
      const c = connectRef.current;
      if (!c) return;
      const el = canvasRef.current;
      if (!el) return;
      const rect = el.getBoundingClientRect();
      setPreviewEdge({
        x: (e.clientX - rect.left - viewport.panX) / viewport.zoom,
        y: (e.clientY - rect.top - viewport.panY) / viewport.zoom,
      });
    }
    function onUp(e: PointerEvent) {
      const c = connectRef.current;
      connectRef.current = null;
      setPreviewEdge(null);
      if (!c) return;
      const el = canvasRef.current;
      if (!el) return;
      const rect = el.getBoundingClientRect();
      const cx = (e.clientX - rect.left - viewport.panX) / viewport.zoom;
      const cy = (e.clientY - rect.top - viewport.panY) / viewport.zoom;
      // Hit-test the drop target against the center-closest node (not the source).
      const target = hitTest(board.nodes, cx, cy);
      if (target && target.id !== c.fromId) {
        update((b) => ({
          ...b,
          edges: [
            ...b.edges,
            { id: uuid(), from: c.fromId, to: target.id } satisfies GraphEdge,
          ],
        }));
      }
      setSelectedId(null);
    }
    document.addEventListener("pointermove", onMove);
    document.addEventListener("pointerup", onUp);
    return () => {
      document.removeEventListener("pointermove", onMove);
      document.removeEventListener("pointerup", onUp);
    };
  }, [board.nodes, viewport, update, readOnly]);

  /* ------------------------------ Deletion --------------------------------- */
  const deleteSelected = useCallback(() => {
    if (!selectedId) return;
    update((b) => ({
      nodes: b.nodes.filter((n) => n.id !== selectedId),
      edges: b.edges.filter((e) => e.from !== selectedId && e.to !== selectedId),
    }));
    setSelectedId(null);
    setEditingId(null);
  }, [selectedId, update]);

  /* ----------------------- Keyboard: tools + delete ------------------------ */
  useEffect(() => {
    if (readOnly) return;
    function onKeyDown(e: KeyboardEvent) {
      const target = e.target as HTMLElement;
      const typing = target.tagName === "TEXTAREA" || target.tagName === "INPUT" || target.isContentEditable;
      if (e.code === "Space" && !typing) {
        e.preventDefault();
        setSpaceDown(true);
        return;
      }
      if (typing) return; // don't hijack text editing
      if (e.key === "Delete" || e.key === "Backspace") {
        e.preventDefault();
        deleteSelected();
        return;
      }
      // Alt + ↑/↓ nudges the selected image node's scale (shift = micro step).
      if (e.altKey && (e.key === "ArrowUp" || e.key === "ArrowDown") && selectedId) {
        const node = board.nodes.find((n) => n.id === selectedId);
        if (node && node.type === "image" && node.image) {
          e.preventDefault();
          const step = (e.shiftKey ? SCALE_STEP_MICRO : SCALE_STEP_NORMAL) * (e.key === "ArrowUp" ? 1 : -1);
          update((b) => ({
            ...b,
            nodes: b.nodes.map((n) =>
              n.id !== node.id || !n.image
                ? n
                : {
                    ...n,
                    image: {
                      ...n.image,
                      scale: clamp(
                        (n.image.scale ?? DEFAULT_IMAGE_NODE_SCALE) + step,
                        MIN_IMAGE_SCALE,
                        MAX_IMAGE_SCALE,
                      ),
                    },
                  },
            ),
          }));
          return;
        }
      }
      const t = TOOL_SHORTCUTS[e.key.toLowerCase()];
      if (t) {
        e.preventDefault();
        setTool(t);
      }
    }
    function onKeyUp(e: KeyboardEvent) {
      if (e.code === "Space") setSpaceDown(false);
    }
    document.addEventListener("keydown", onKeyDown);
    document.addEventListener("keyup", onKeyUp);
    return () => {
      document.removeEventListener("keydown", onKeyDown);
      document.removeEventListener("keyup", onKeyUp);
    };
  }, [readOnly, deleteSelected, selectedId, board.nodes, update]);

  /* ------------------------------ Rendering -------------------------------- */

  const innerTransform: CSSProperties = {
    transform: `translate(${viewport.panX}px, ${viewport.panY}px) scale(${viewport.zoom})`,
    transformOrigin: "0 0",
  };

  const boardHasContent = board.nodes.length > 0 || board.edges.length > 0;

  return (
    <div className="rounded-md border border-neutral-300 bg-white overflow-hidden select-none">
      {/* Toolbar rail + tool labels */}
      {!readOnly && (
        <div className="flex items-center gap-1 border-b border-neutral-200 bg-neutral-50 px-2 py-1.5 text-xs">
          <ToolButton active={tool === "select"} onClick={() => setTool("select")} title="Select (V)">
            ▲ Select
          </ToolButton>
          <ToolButton active={tool === "sticky"} onClick={() => setTool("sticky")} title="Sticky note (N)">
            🟪 Sticky
          </ToolButton>
          <ToolButton active={tool === "rect"} onClick={() => setTool("rect")} title="Rectangle (R)">
            □ Rect
          </ToolButton>
          <ToolButton active={tool === "ellipse"} onClick={() => setTool("ellipse")} title="Ellipse (O)">
            ◯ Ellipse
          </ToolButton>
          <ToolButton active={tool === "text"} onClick={() => setTool("text")} title="Text (T)">
            T Text
          </ToolButton>
          <ToolButton
            active={tool === "image"}
            onClick={() => setTool("image")}
            title="Image (I) — uses the last added attachment; paste an image to add one"
          >
            🖼 Image
          </ToolButton>
          <ToolButton active={tool === "connect"} onClick={() => setTool("connect")} title="Connector (C)">
            ⟶ Connect
          </ToolButton>
          <div className="mx-1 h-5 w-px bg-neutral-200" />
          <ToolButton onClick={deleteSelected} disabled={!selectedId} title="Delete (Del)">
            🗑 Delete
          </ToolButton>
          <span className="ml-auto text-[11px] text-neutral-400">
            {readOnly
              ? ""
              : tool === "connect"
                ? "Drag from one node to another to connect"
                : tool === "image"
                  ? files && files.length > 0
                    ? "Click the canvas to place the last attachment as an image"
                    : "Add an attachment (or paste an image) first, then click to place it"
                  : tool !== "select"
                    ? `Click the canvas to place a ${tool} node`
                    : "Drag empty canvas to pan · wheel to zoom · double-click a node to edit text · paste an image to add it"}
          </span>
        </div>
      )}

      {/* Canvas */}
      <div
        ref={canvasRef}
        data-graph-canvas="true"
        data-empty={boardHasContent ? "false" : "true"}
        tabIndex={readOnly ? undefined : 0}
        onPointerDown={onCanvasPointerDown}
        onWheel={onWheel}
        onPaste={onCanvasPaste}
        onDrop={onCanvasDrop}
        onDragOver={onCanvasDragOver}
        className="relative overflow-hidden outline-none"
        style={{
          minHeight,
          // subtle dot-grid background, fixed to the canvas (not the content)
          backgroundColor: "#fbfbfc",
          backgroundImage: "radial-gradient(#d8dce1 1px, transparent 0)",
          backgroundSize: `${24 * viewport.zoom}px ${24 * viewport.zoom}px`,
          backgroundPosition: `${viewport.panX}px ${viewport.panY}px`,
          cursor: readOnly ? "grab" : spaceDown || panRef.current ? "grabbing" : cursorForTool(tool),
        }}
      >
        {!boardHasContent && (
          <div className="absolute inset-0 grid place-items-center text-sm text-neutral-400 pointer-events-none">
            {readOnly ? "This graph board is empty." : "Pick a tool above and click the canvas to add a node."}
          </div>
        )}

        {/* Content layer (transformed by pan + zoom). Carries a discriminator
            attribute so canvas pointer-down can treat clicks that land here
            (rather than on a node) as "empty canvas space" for create/pan. */}
        <div className="absolute inset-0" data-graph-content="true" style={innerTransform}>
          {/* Edges (SVG, canvas-space). */}
          <svg
            className="absolute top-0 left-0 overflow-visible pointer-events-none"
            style={{ width: 1, height: 1 }}
          >
            {board.edges.map((edge) => {
              const from = board.nodes.find((n) => n.id === edge.from);
              const to = board.nodes.find((n) => n.id === edge.to);
              if (!from || !to) return null;
              const a = center(from);
              const b = center(to);
              return (
                <g key={edge.id}>
                  <line
                    x1={a.cx}
                    y1={a.cy}
                    x2={b.cx}
                    y2={b.cy}
                    stroke="#0055dc"
                    strokeWidth={2 / viewport.zoom}
                    markerEnd="url(#encryptor-arrow)"
                  />
                  {edge.label && (
                    <text
                      x={(a.cx + b.cx) / 2}
                      y={(a.cy + b.cy) / 2 - 6 / viewport.zoom}
                      textAnchor="middle"
                      fontSize={12 / viewport.zoom}
                      fill="#374151"
                    >
                      {edge.label}
                    </text>
                  )}
                </g>
              );
            })}
            {/* Live connector preview while dragging. */}
            {connectRef.current && previewEdge && (() => {
              const from = board.nodes.find((n) => n.id === connectRef.current!.fromId);
              if (!from) return null;
              const a = center(from);
              return (
                <line
                  x1={a.cx}
                  y1={a.cy}
                  x2={previewEdge.x}
                  y2={previewEdge.y}
                  stroke="#0055dc"
                  strokeWidth={2 / viewport.zoom}
                  strokeDasharray={`${6 / viewport.zoom} ${4 / viewport.zoom}`}
                />
              );
            })()}
            <defs>
              <marker
                id="encryptor-arrow"
                markerWidth={10}
                markerHeight={10}
                refX={8}
                refY={5}
                orient="auto"
                markerUnits="userSpaceOnUse"
              >
                <path d="M0,0 L8,5 L0,10 z" fill="#0055dc" />
              </marker>
            </defs>
          </svg>

          {/* Nodes. */}
          {board.nodes.map((node) => {
            const selected = selectedId === node.id && !readOnly;
            const editing = editingId === node.id && !readOnly;
            const isImage = node.type === "image";
            const bg = node.color ?? NODE_COLORS[node.type];
            const border = NODE_BORDER[node.type];
            // Resolve the image's data URL from the shared files[] by filename.
            const imgFile = isImage ? files?.find((f) => f.name === node.image?.filename) : undefined;
            const imgSrc = isImage ? fileToDataUrl(imgFile) : "";
            const scale = isImage ? node.image?.scale ?? DEFAULT_IMAGE_NODE_SCALE : 100;
            return (
              <div
                key={node.id}
                data-node-text={node.text || undefined}
                data-graph-canvas-node={node.id}
                data-empty="false"
                onPointerDown={(e) => tool !== "connect" && onNodePointerDown(e, node, "move")}
                onPointerDownCapture={(e) => tool === "connect" && startConnect(e, node)}
                onDoubleClick={(e) => {
                  e.stopPropagation();
                  if (readOnly || isImage) return; // images aren't text-editable
                  setEditingId(node.id);
                  setSelectedId(node.id);
                }}
                className={`absolute group ${node.type === "text" ? "" : "shadow-sm"} ${
                  node.type === "ellipse" ? "rounded-full" : node.type === "text" ? "rounded" : "rounded-md"
                } ${selected ? "ring-2 ring-[#0055dc] ring-offset-1" : "ring-1 ring-black/5"}`}
                style={{
                  left: node.x,
                  top: node.y,
                  width: node.w,
                  height: node.h,
                  background: bg,
                  border: node.type === "text" ? "none" : `1.5px solid ${border}`,
                  pointerEvents: readOnly ? "auto" : tool === "connect" ? "auto" : "auto",
                }}
              >
                {isImage ? (
                  imgSrc ? (
                    <img
                      src={imgSrc}
                      alt={node.image?.filename ?? "image"}
                      draggable={false}
                      className="h-full w-full object-contain select-none"
                      // The scale % drives the rendered size relative to the node's
                      // w/h box; 100% fills the box, lower = smaller, higher = crop.
                      style={{ transform: `scale(${scale / 100})`, transformOrigin: "center" }}
                    />
                  ) : (
                    <div className="grid h-full w-full place-items-center rounded-md bg-neutral-50 text-[11px] text-neutral-400 italic">
                      {node.image?.filename
                        ? `Missing image: ${node.image.filename}`
                        : "Missing image"}
                    </div>
                  )
                ) : editing ? (
                  <textarea
                    autoFocus
                    defaultValue={node.text}
                    data-node-editor="true"
                    onBlur={(e) => {
                      update((b) => ({
                        ...b,
                        nodes: b.nodes.map((n) => (n.id === node.id ? { ...n, text: e.target.value } : n)),
                      }));
                      setEditingId(null);
                    }}
                    onKeyDown={(e) => {
                      e.stopPropagation();
                      if (e.key === "Escape") (e.target as HTMLTextAreaElement).blur();
                    }}
                    placeholder={node.type === "text" ? "Type…" : "Double-click a node to add text…"}
                    className="h-full w-full resize-none bg-transparent px-2.5 py-2 text-xs leading-snug text-neutral-900 outline-none placeholder:text-neutral-400"
                  />
                ) : (
                  <div
                    className={`h-full w-full px-2.5 py-2 whitespace-pre-wrap break-words text-xs leading-snug text-neutral-900 ${
                      node.type === "text" ? "font-medium" : ""
                    } ${!node.text ? "text-neutral-400 italic" : ""}`}
                  >
                    {node.text || (readOnly ? "" : node.type === "text" ? "Text" : "Double-click to edit")}
                  </div>
                )}

                {/* Resize handle (bottom-right), hidden in connect / readOnly. */}
                {!readOnly && tool !== "connect" && (
                  <div
                    data-empty="false"
                    data-graph-handle={node.id}
                    onPointerDown={(e) => onNodePointerDown(e, node, "resize")}
                    className="absolute -bottom-1 -right-1 size-3 rounded-full bg-white border-2 border-[#0055dc] cursor-nwse-resize"
                    title="Drag to resize"
                  />
                )}
              </div>
            );
          })}
        </div>

        {/* Zoom widget (bottom-right). */}
        <div className="absolute bottom-2 right-2 flex items-center gap-1 rounded-md border border-neutral-200 bg-white shadow-sm px-1 py-0.5 text-xs">
          <button type="button" onClick={() => setZoom(viewport.zoom - 0.2)} className="size-6 grid place-items-center rounded hover:bg-neutral-100 text-neutral-600" title="Zoom out">−</button>
          <button type="button" onClick={() => setZoom(1)} className="min-w-12 px-1 text-center text-neutral-700 tabular-nums" title="Reset to 100%">
            {Math.round(viewport.zoom * 100)}%
          </button>
          <button type="button" onClick={() => setZoom(viewport.zoom + 0.2)} className="size-6 grid place-items-center rounded hover:bg-neutral-100 text-neutral-600" title="Zoom in">+</button>
        </div>
      </div>
    </div>
  );
}

/* ------------------------------ Sub-UI bits -------------------------------- */

function ToolButton({
  children,
  active,
  onClick,
  disabled,
  title,
}: {
  children: React.ReactNode;
  active?: boolean;
  onClick?: () => void;
  disabled?: boolean;
  title?: string;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled}
      title={title}
      aria-pressed={active}
      className={`rounded-md px-2 py-1 font-medium transition-colors disabled:opacity-40 disabled:cursor-not-allowed ${
        active
          ? "bg-[#0055dc]/10 text-[#0055dc]"
          : "text-neutral-700 hover:bg-neutral-200/60"
      }`}
    >
      {children}
    </button>
  );
}

/* -------------------------------- Helpers --------------------------------- */

function clamp(n: number, min: number, max: number): number {
  return Math.max(min, Math.min(max, n));
}

/** Best-effort extension from a MIME type, for generating filenames on paste. */
function guessExt(mime: string): string {
  const map: Record<string, string> = {
    "image/png": "png",
    "image/jpeg": "jpg",
    "image/gif": "gif",
    "image/webp": "webp",
    "image/svg+xml": "svg",
    "image/bmp": "bmp",
  };
  return map[mime] || "png";
}

/** Build a `data:` URL for an envelope file (base64 → data URL); "" if none. */
function fileToDataUrl(file: EnvelopeFile | undefined): string {
  if (!file || !file.data) return "";
  const type = file.type || "application/octet-stream";
  return `data:${type};base64,${file.data}`;
}

function hitTest(nodes: GraphNode[], cx: number, cy: number): GraphNode | null {
  // Front-most node wins (search topmost in DOM order = last in array).
  for (let i = nodes.length - 1; i >= 0; i--) {
    const n = nodes[i];
    if (cx >= n.x && cx <= n.x + n.w && cy >= n.y && cy <= n.y + n.h) return n;
  }
  return null;
}

function cursorForTool(tool: Tool): string {
  switch (tool) {
    case "select":
      return "default";
    case "connect":
      return "crosshair";
    default:
      return "copy";
  }
}

/** structuredClone with a safe fallback (older runtimes / non-cloneable). */
function structuredCloneSafe<T>(value: T): T {
  if (typeof structuredClone === "function") {
    try {
      return structuredClone(value);
    } catch {
      // fall through
    }
  }
  return JSON.parse(JSON.stringify(value)) as T;
}
