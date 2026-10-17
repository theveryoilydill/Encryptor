"use client";

/**
 * Shared drag-drop affordance for loading TEXT files onto the Decrypt and
 * Verify tab input cards (R10): dropping a .asc armor file fills the input
 * textarea without a manual copy/paste.
 *
 * `useAsciiTextDrop` is THE shared implementation (one hook, no per-tab
 * duplication). It generalizes the proven dragDepth-counter pattern from
 * EncryptTab's attachments drop (increment on dragenter, clamp on
 * dragleave, reset on drop — avoids overlay flicker when the pointer
 * crosses child elements) and adds an armor-sniffing file loader:
 *
 *   - Only reacts to real file drags (dataTransfer.types includes "Files").
 *   - On drop, accepts the FIRST file that reads as text and (when
 *     requirePgpArmor, the default) whose trimmed content starts with
 *     "-----BEGIN PGP". Oversized files (2 MB cap — armor text is small;
 *     protects memory) and binary content are skipped with an error
 *     message.
 *   - When no file qualifies, calls onError once with the most relevant
 *     message (binary file, non-PGP text, oversized, or zero files).
 *
 * `AsciiDropOverlay` renders the same visual language as EncryptTab's drag
 * overlay (dashed brand border + tint + centered label pill), with the
 * caller's label. The parent card must be `relative` for it to position.
 * The overlay is pointer-events-none + aria-hidden: drag-drop is a
 * pointer-only affordance and the underlying textarea/paste path stays
 * fully interactive for keyboard and screen-reader users.
 */

import { useCallback, useState } from "react";
import type { DragEvent } from "react";

/** Accepted file size cap (armor text files are small; protects memory). */
const MAX_ASCII_DROP_BYTES = 2 * 1024 * 1024;

/** Marker every PGP armor block starts with (MESSAGE/SIGNATURE/KEY/…). */
const PGP_ARMOR_PREFIX = "-----BEGIN PGP";

export interface UseAsciiTextDropOptions {
	/** Called with the FULL file text and file name of the first valid file. */
	onText: (text: string, fileName: string) => void;
	/** Called once when no dropped file qualifies. */
	onError?: (message: string) => void;
	/**
	 * When true (default), the file content must start with "-----BEGIN PGP"
	 * (armor sniff). Set false for plaintext drop targets (e.g. the Verify
	 * tab's detached-signature plaintext field), where ANY text file is
	 * accepted.
	 */
	requirePgpArmor?: boolean;
	/** When false, all drag events are ignored entirely (default true). */
	enabled?: boolean;
}

export interface AsciiTextDrop {
	/** > 0 while files are being dragged over the target (render overlay). */
	dragDepth: number;
	/** Spread onto the drop target element. */
	dropProps: {
		onDragEnter: (e: DragEvent<HTMLElement>) => void;
		onDragOver: (e: DragEvent<HTMLElement>) => void;
		onDragLeave: (e: DragEvent<HTMLElement>) => void;
		onDrop: (e: DragEvent<HTMLElement>) => void;
	};
}

/**
 * Cheap binary sniff: text files never contain NUL bytes, binary files
 * almost always do. Used to reject binary drops in a way file.type (often
 * "" or "application/octet-stream") cannot.
 */
function looksBinary(text: string): boolean {
	return text.includes("\u0000");
}

export function useAsciiTextDrop({
	onText,
	onError,
	requirePgpArmor = true,
	enabled = true,
}: UseAsciiTextDropOptions): AsciiTextDrop {
	// Drag & drop depth counter (avoids flicker when crossing child elements).
	const [dragDepth, setDragDepth] = useState(0);

	const onDragEnter = useCallback(
		(e: DragEvent<HTMLElement>) => {
			if (!enabled) return;
			if (!e.dataTransfer.types.includes("Files")) return;
			e.preventDefault();
			setDragDepth((d) => d + 1);
		},
		[enabled],
	);

	const onDragOver = useCallback(
		(e: DragEvent<HTMLElement>) => {
			if (!enabled) return;
			if (!e.dataTransfer.types.includes("Files")) return;
			e.preventDefault();
		},
		[enabled],
	);

	const onDragLeave = useCallback(
		(e: DragEvent<HTMLElement>) => {
			if (!enabled) return;
			if (!e.dataTransfer.types.includes("Files")) return;
			setDragDepth((d) => Math.max(0, d - 1));
		},
		[enabled],
	);

	const onDrop = useCallback(
		(e: DragEvent<HTMLElement>) => {
			if (!enabled) return;
			if (!e.dataTransfer.types.includes("Files")) return;
			e.preventDefault();
			setDragDepth(0);

			// Loading files is async (file.text()); the handler itself stays
			// synchronous so React's synthetic event cannot be pooled mid-await.
			void (async () => {
				const files = Array.from(e.dataTransfer.files);
				// Last relevant reason no file qualified, for the final onError.
				let lastError: string | null = null;
				if (files.length === 0) {
					lastError = requirePgpArmor
						? "Drop a PGP-armored text file (.asc) to load it."
						: "Drop a text file to load it.";
				}
				for (const file of files) {
					if (file.size > MAX_ASCII_DROP_BYTES) {
						lastError = `"${file.name}" is too large — the limit is 2 MB (PGP armor files are small text files).`;
						continue;
					}
					let text: string;
					try {
						text = await file.text();
					} catch {
						lastError = `Could not read "${file.name}".`;
						continue;
					}
					if (looksBinary(text)) {
						lastError = `"${file.name}" is not a text file.`;
						continue;
					}
					if (requirePgpArmor && !text.trimStart().startsWith(PGP_ARMOR_PREFIX)) {
						lastError = `"${file.name}" is not a PGP-armored text file.`;
						continue;
					}
					// First qualifying file wins.
					onText(text, file.name);
					return;
				}
				if (lastError) onError?.(lastError);
			})();
		},
		[enabled, onError, onText, requirePgpArmor],
	);

	return { dragDepth, dropProps: { onDragEnter, onDragOver, onDragLeave, onDrop } };
}

/**
 * Visual overlay shown while files are dragged over the parent card (same
 * language as EncryptTab's attachments drop overlay, caller's label).
 * Parent must be `relative`; `active` is typically `dragDepth > 0`.
 */
export function AsciiDropOverlay({ active, label }: { active: boolean; label: string }) {
	if (!active) return null;
	return (
		<div
			aria-hidden
			className="pointer-events-none absolute inset-0 z-10 flex items-center justify-center rounded-xl border-2 border-dashed border-[#0055dc] bg-[#0055dc]/5 dark:border-[#5e94ff] dark:bg-[#5e94ff]/10 animate-fade-up"
		>
			<span className="rounded-lg bg-background/95 px-4 py-2 text-sm font-medium text-[#0055dc] shadow-sm dark:text-[#5e94ff]">
				{label}
			</span>
		</div>
	);
}
