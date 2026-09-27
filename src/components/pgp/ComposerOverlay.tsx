"use client";

/**
 * Shared full-screen composer overlay ("blow up the editor") for the Encrypt
 * and Sign tabs.
 *
 * # Mr. AI Acting on s183173's Behalf
 *
 * One component owns everything the two tab overlays used to duplicate:
 * the portal dialog, the click-off / Escape / chord wiring (dialog-safe, via
 * lib/pgp/composer-overlay.ts) and — new — the enter/exit transitions. The
 * feedback round asked for a full-bleed layout ("the whole screen"): the
 * old max-w-4xl reading column is gone, the caller fills the viewport with
 * whatever the screen needs (recipients bar on top, editor, status bar).
 *
 * The overlay stays mounted while its parent toggles `open`, so the exit
 * animation can play before it unmounts itself — a plain conditional render
 * would pop the overlay out with no way to animate it.
 */

import {
	useEffect,
	useRef,
	useState,
	type AnimationEvent as ReactAnimationEvent,
	type KeyboardEvent as ReactKeyboardEvent,
	type PointerEvent as ReactPointerEvent,
	type ReactNode,
} from "react";
import { createPortal } from "react-dom";
import {
	isComposerToggleChord,
	isNestedDialogTarget,
	isPrimaryActionChord,
} from "@/lib/pgp/composer-overlay";

/** Exit animation duration — must match the Tailwind duration-150 below.
 *  Fallback timer for motion-reduce users (no animationend event fires). */
const EXIT_MS = 160;

export function ComposerOverlay({
	owner,
	open,
	onClose,
	onPrimaryAction,
	topRight,
	children,
}: {
	/** Which composer owns the overlay — routes stacked-overlay Escape/chords. */
	owner: "encrypt" | "sign";
	open: boolean;
	onClose: () => void;
	/** Ctrl/Cmd+Enter inside the overlay (Encrypt → encrypt, Sign → sign). */
	onPrimaryAction: () => void;
	/** Floating control pinned to the overlay's top-right corner — the
	 *  collapse toggle lives there in full-screen mode (feedback mockup:
	 *  the whole screen is recipients + editor, nothing else). */
	topRight?: ReactNode;
	children: ReactNode;
}) {
	// Rendered = actually in the DOM (includes the exit-animation window).
	const [rendered, setRendered] = useState(open);
	const [leaving, setLeaving] = useState(false);
	// Timer ref so a re-open mid-exit cancels the pending unmount.
	const exitTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

	useEffect(() => {
		if (open) {
			if (exitTimer.current) clearTimeout(exitTimer.current);
			setLeaving(false);
			setRendered(true);
			return;
		}
		if (!rendered) return;
		setLeaving(true);
		exitTimer.current = setTimeout(() => setRendered(false), EXIT_MS);
	}, [open, rendered]);

	if (!rendered) return null;

	const handlePointerDown = (e: ReactPointerEvent<HTMLDivElement>) => {
		// Click-off close: a press on the backdrop itself (never on composer
		// content, which targets deeper nodes).
		if (e.target === e.currentTarget) {
			e.preventDefault();
			onClose();
		}
	};

	const handleEscapeCapture = (e: ReactKeyboardEvent<HTMLDivElement>) => {
		if (e.key !== "Escape" || e.defaultPrevented) return;
		if (isNestedDialogTarget(e.target)) return;
		e.preventDefault();
		onClose();
	};

	const handleKeyDown = (e: ReactKeyboardEvent<HTMLDivElement>) => {
		// Mirror the tab's Ctrl/Cmd+Enter primary action — the portal sits
		// outside the <section> keydown handler.
		if (isPrimaryActionChord(e)) {
			e.preventDefault();
			onPrimaryAction();
		}
		// Ctrl/Cmd+Shift+E collapses the overlay — same dialog-safe guard as
		// the Escape path: nested dialogs/popovers opened FROM the composer
		// keep their keys for themselves.
		if (isComposerToggleChord(e) && !e.defaultPrevented && !isNestedDialogTarget(e.target)) {
			e.preventDefault();
			onClose();
		}
	};

	const handleAnimationEnd = (e: ReactAnimationEvent<HTMLDivElement>) => {
		if (leaving && e.target === e.currentTarget) setRendered(false);
	};

	return createPortal(
		<div
			data-composer-overlay={owner}
			role="dialog"
			aria-modal="true"
			aria-label="Composer, full screen"
			onPointerDown={handlePointerDown}
			onKeyDownCapture={handleEscapeCapture}
			onKeyDown={handleKeyDown}
			onAnimationEnd={handleAnimationEnd}
			className={
				"fixed inset-0 z-50 bg-background p-2 sm:p-3 md:p-4 motion-reduce:transition-none " +
				(leaving
					? "animate-out fade-out-0 zoom-out-[0.985] duration-150"
					: "animate-in fade-in-0 zoom-in-[0.985] duration-200")
			}
		>
			{/* Full-bleed screen container ("the whole screen"): a single rounded
                            card filling the viewport. Callers stack the recipients bar and
                            the editor (flex-1) inside; no reading-column cap. */}
			<div className="relative flex h-full min-h-0 w-full flex-col gap-2 overflow-hidden rounded-2xl border border-border bg-card shadow-xl sm:gap-3">
				{topRight && <div className="absolute right-3 top-2.5 z-10">{topRight}</div>}
				{children}
			</div>
		</div>,
		document.body,
	);
}
