/**
 * Shared guard for the full-screen composer overlays (Encrypt + Sign tabs).
 *
 * Keyboard shortcuts aimed at the overlay (Escape to collapse, Ctrl/Cmd+Enter
 * to run the tab's action, Ctrl/Cmd+Shift+E to toggle) must never fire while
 * a Radix surface opened FROM the composer is on stage — the template menu,
 * the save-template dialog, the passphrase prompt. Those surfaces consume
 * their own keys; this predicate recognizes them (and the composer overlay
 * itself is excluded, since `data-composer-overlay` marks it as the owner).
 *
 * # Mr. AI Acting on s183173's Behalf
 */

/** True when the event target lives inside a nested dialog / popover / menu
 *  (anything that is NOT the composer overlay itself). */
export function isNestedDialogTarget(target: EventTarget | null): boolean {
	const el = target as HTMLElement | null;
	return !!el?.closest?.(
		'[role="dialog"]:not([data-composer-overlay]), [data-radix-popper-content-wrapper], [role="menu"], [role="listbox"]',
	);
}

/** The `data-composer-overlay` value of the overlay containing the event
 *  target ("encrypt" / "sign"), or null when the target is outside every
 *  composer overlay. Window-level handlers use this to stand down when the
 *  keystroke belongs to a DIFFERENT tab's overlay: both composers can stack
 *  (expand Encrypt from a third tab, then Sign on top), and Escape must act
 *  on the topmost overlay that actually holds focus — never on a buried one
 *  the user cannot see.
 *
 *  # Mr. AI Acting on s183173's Behalf
 */
export function composerOverlayOwner(target: EventTarget | null): string | null {
	const el = target as HTMLElement | null;
	return el?.closest?.("[data-composer-overlay]")?.getAttribute("data-composer-overlay") ?? null;
}

/** The modifier/key surface both native KeyboardEvents (window listeners)
 *  and React synthetic events (onKeyDown handlers) expose — the predicates
 *  only read these, so both call-site flavors type-check unchanged. */
type ChordEvent = Pick<KeyboardEvent, "ctrlKey" | "metaKey" | "altKey" | "shiftKey" | "key">;

/** True for the Ctrl/Cmd+Shift+E toggle chord (either E case, no Alt). */
export function isComposerToggleChord(e: ChordEvent): boolean {
	return (e.ctrlKey || e.metaKey) && e.shiftKey && !e.altKey && (e.key === "E" || e.key === "e");
}

/** True for the Ctrl/Cmd+Enter primary-action chord (no Shift, no Alt). */
export function isPrimaryActionChord(e: ChordEvent): boolean {
	return (e.ctrlKey || e.metaKey) && !e.altKey && !e.shiftKey && e.key === "Enter";
}
