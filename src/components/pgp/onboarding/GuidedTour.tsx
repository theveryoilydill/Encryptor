"use client";

/**
 * Guided tour — coach-mark walkthrough of the main app.
 *
 * Design (owner feedback after the #45 full-screen takeover): no takeover.
 * Each step spotlights a REAL element of the UI ([data-tour] anchors) and
 * floats a textbox next to it explaining what it does, so the user learns
 * the app on the app itself. Steps that live on a specific tab activate that
 * tab first; the spotlight re-measures after the panel settles.
 *
 * Auto-starts once, right after the first key is set up (see PgpApp), and
 * can be replayed from Settings → Help. Finishing OR skipping records
 * "done" so returning users never see it unprompted.
 */
import { useCallback, useEffect, useLayoutEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { ChevronLeft, ChevronRight, X } from "lucide-react";

import { Button } from "@/components/ui/button";
import type { Tab } from "@/components/pgp/contracts";
import { STORAGE_KEYS } from "@/lib/constants";

type TourStep = {
	id: string;
	/** Selector of the element to spotlight ([data-tour="…"]). */
	anchor: string;
	/** Tab to activate on entry so the anchor is mounted and visible. */
	tab?: Tab;
	title: string;
	body: string;
	/** Preferred callout side; flips automatically when out of viewport. */
	side?: "bottom" | "top";
};

/** The tour, in the order a new user meets the app. */
const STEPS: TourStep[] = [
	{
		id: "modes",
		anchor: '[data-tour="mode-tabs"]',
		tab: "encrypt",
		title: "Four modes, one app",
		body: "Encrypt a message, decrypt one you received, sign with your key, or verify someone's signature. Click a tab — or press Alt+1–4 from anywhere.",
	},
	{
		id: "recipients",
		anchor: '[data-tour="recipients"]',
		tab: "encrypt",
		title: "Choose who can read it",
		body: "Search people by name, email, fingerprint or Keybase username — their public keys are fetched automatically. “Include me” adds your own key so you can still read what you send.",
	},
	{
		id: "composer",
		anchor: '[data-tour="composer"]',
		tab: "encrypt",
		title: "Write the message",
		body: "Type or paste text, drop in attachments (up to 25 MB each) and format with Markdown. Ctrl+Enter runs the blue action button — “Encrypt & sign” by default.",
	},
	{
		id: "key",
		anchor: '[data-tour="key-button"]',
		tab: "encrypt",
		title: "Your key lives here",
		body: "This button shows the key you're signed in with. Click it to view the fingerprint, switch keys, or set up a different one. The private key never leaves this browser.",
	},
	{
		id: "settings",
		anchor: '[data-tour="settings-button"]',
		tab: "encrypt",
		title: "Tune how the app behaves",
		body: "Editor style, compression, the remembered-passphrase auto-lock and backups are in Settings (Ctrl+,). You can replay this tour from there anytime.",
	},
	{
		id: "shortcuts",
		anchor: '[data-tour="shortcuts-button"]',
		tab: "encrypt",
		title: "Work at keyboard speed",
		body: "Alt+1–4 switches modes, Ctrl+Enter runs the action, Ctrl+, opens Settings. The keyboard icon lists them all.",
	},
];

/** Has the user already finished (or skipped) the tour? */
export function isTourDone(): boolean {
	try {
		return localStorage.getItem(STORAGE_KEYS.tourDone) === "1";
	} catch {
		return false;
	}
}

/** Record the tour as seen — called on finish and on skip. */
export function markTourDone(): void {
	try {
		localStorage.setItem(STORAGE_KEYS.tourDone, "1");
	} catch {
		// storage unavailable — tour would repeat next visit; harmless
	}
}

/* Spotlight breathing room around the anchor, callout gap and width. */
const SPOT_PAD = 10;
const GAP = 14;
const CALLOUT_W = 344;

const clamp = (v: number, lo: number, hi: number) => Math.min(Math.max(v, lo), hi);

export function GuidedTour({
	open,
	onOpenChange,
	tab,
	onTabChange,
}: {
	open: boolean;
	onOpenChange: (open: boolean) => void;
	/** Parent's active tab + setter: steps can drive it to reach anchors. */
	tab: Tab;
	onTabChange: (t: Tab) => void;
}) {
	const [index, setIndex] = useState(0);
	// Measurement probe per step: "pending" until the settle timer runs, then
	// "found" (anchor measured) or "missing" (anchor absent/hidden → skip
	// forward). "missing" NEVER fires before measurement has had its chance —
	// rect === null alone is not enough to judge.
	const [probe, setProbe] = useState<"pending" | "found" | "missing">("pending");
	const [rect, setRect] = useState<DOMRect | null>(null);
	const [calloutH, setCalloutH] = useState(0);
	const calloutRef = useRef<HTMLDivElement | null>(null);
	const step = STEPS[index];

	const finish = useCallback(() => onOpenChange(false), [onOpenChange]);
	const next = useCallback(() => {
		if (index >= STEPS.length - 1) finish();
		else setIndex((i) => i + 1);
	}, [index, finish]);
	const back = useCallback(() => setIndex((i) => Math.max(0, i - 1)), []);

	// Reopen from step 0 every time the tour starts, and re-arm the probe on
	// every step entry.
	useEffect(() => {
		if (open) {
			setIndex(0);
			setProbe("pending");
			setRect(null);
		}
	}, [open]);

	useEffect(() => {
		setProbe("pending");
		setRect(null);
	}, [index]);

	// Step entry: reach the anchor's tab, then measure after the panel
	// swap settles (panel-enter runs 0.18s).
	useEffect(() => {
		if (!open) return;
		if (step.tab && step.tab !== tab) onTabChange(step.tab);
		// eslint-disable-next-line react-hooks/exhaustive-deps -- entry-only by design
	}, [open, index]);

	useEffect(() => {
		if (!open) return;
		let raf1 = 0;
		let raf2 = 0;
		const timer = window.setTimeout(() => {
			const el = document.querySelector<HTMLElement>(step.anchor);
			if (!el || el.getClientRects().length === 0) {
				setRect(null);
				setProbe("missing");
				return;
			}
			el.scrollIntoView({ block: "center", inline: "nearest" });
			raf1 = requestAnimationFrame(() => {
				raf2 = requestAnimationFrame(() => {
					setRect(el.getBoundingClientRect());
					setProbe("found");
				});
			});
		}, 260);
		// Keep the spotlight glued while the page resizes or any container scrolls.
		const refresh = () => {
			const el = document.querySelector<HTMLElement>(step.anchor);
			if (el && el.getClientRects().length > 0) setRect(el.getBoundingClientRect());
		};
		window.addEventListener("resize", refresh);
		window.addEventListener("scroll", refresh, true);
		return () => {
			window.clearTimeout(timer);
			cancelAnimationFrame(raf1);
			cancelAnimationFrame(raf2);
			window.removeEventListener("resize", refresh);
			window.removeEventListener("scroll", refresh, true);
		};
	}, [open, index, step.anchor]);

	// Anchor gone (element unmounted mid-tour): skip forward instead of
	// pointing at nothing; on the last step, close.
	useEffect(() => {
		if (!open || probe !== "missing") return;
		if (index >= STEPS.length - 1) finish();
		else setIndex((i) => i + 1);
	}, [open, probe, index, finish]);

	// Measure the callout so "above" placement can flip with real height.
	useLayoutEffect(() => {
		if (calloutRef.current) setCalloutH(calloutRef.current.offsetHeight);
	}, [index, rect]);

	// Focus the callout on every step so keyboard and screen readers follow.
	useEffect(() => {
		if (!open || rect === null) return;
		const raf = requestAnimationFrame(() => calloutRef.current?.focus());
		return () => cancelAnimationFrame(raf);
	}, [open, index, rect]);

	// Escape skips; arrows navigate; Tab stays inside the callout.
	useEffect(() => {
		if (!open) return;
		const onKey = (e: KeyboardEvent) => {
			if (e.key === "Escape") {
				e.preventDefault();
				finish();
			} else if (e.key === "ArrowRight") {
				e.preventDefault();
				next();
			} else if (e.key === "ArrowLeft") {
				e.preventDefault();
				back();
			} else if (e.key === "Tab" && calloutRef.current) {
				const focusables = calloutRef.current.querySelectorAll<HTMLElement>("button");
				if (focusables.length === 0) return;
				const first = focusables[0];
				const last = focusables[focusables.length - 1];
				if (e.shiftKey && document.activeElement === first) {
					e.preventDefault();
					last.focus();
				} else if (!e.shiftKey && document.activeElement === last) {
					e.preventDefault();
					first.focus();
				}
			}
		};
		window.addEventListener("keydown", onKey, true);
		return () => window.removeEventListener("keydown", onKey, true);
	}, [open, index, finish, next, back]);

	if (!open || typeof document === "undefined") return null;

	const isLast = index === STEPS.length - 1;

	// Geometry (only render once the anchor produced a real rect).
	let spot: { left: number; top: number; width: number; height: number } | null = null;
	let calloutStyle: { left: number; top: number } | null = null;
	if (rect && probe === "found" && rect.width > 0) {
		spot = {
			left: rect.left - SPOT_PAD,
			top: rect.top - SPOT_PAD,
			width: rect.width + SPOT_PAD * 2,
			height: rect.height + SPOT_PAD * 2,
		};
		const vh = window.innerHeight;
		const vw = window.innerWidth;
		const h = calloutH || 190;
		let side = step.side ?? "bottom";
		const fitsBelow = rect.bottom + GAP + h <= vh - 12;
		const fitsAbove = rect.top - GAP - h >= 12;
		if (side === "bottom" && !fitsBelow) side = fitsAbove ? "top" : "bottom";
		if (side === "top" && !fitsAbove) side = fitsBelow ? "bottom" : "top";
		calloutStyle = {
			left: clamp(
				rect.left + rect.width / 2 - CALLOUT_W / 2,
				12,
				Math.max(12, vw - CALLOUT_W - 12),
			),
			top: side === "bottom" ? rect.bottom + GAP : rect.top - GAP - h,
		};
	}

	return createPortal(
		<>
			{/* Click blocker: the tour is driven by its buttons, not the page.
                            Only rendered WITH the callout — if the anchor probe hasn't
                            resolved yet, an invisible full-screen blocker with no visible
                            tour would dead-lock every click in the app. */}
			{spot && calloutStyle && <div aria-hidden="true" className="fixed inset-0 z-[60]" />}

			{/* Spotlight hole — the giant box-shadow dims everything else. */}
			{spot && (
				<div
					aria-hidden="true"
					className="pointer-events-none fixed z-[65] rounded-xl ring-2 ring-[#0055dc] transition-all duration-200 ease-out motion-reduce:transition-none dark:ring-[#5e94ff]"
					style={{
						left: spot.left,
						top: spot.top,
						width: spot.width,
						height: spot.height,
						boxShadow: "0 0 0 9999px rgba(0, 0, 0, 0.55)",
					}}
				/>
			)}

			{/* The explanation textbox, anchored to the spotlighted element. */}
			{spot && calloutStyle && (
				<div
					ref={calloutRef}
					role="dialog"
					aria-modal="true"
					aria-label={`Guided tour, step ${index + 1} of ${STEPS.length}: ${step.title}`}
					tabIndex={-1}
					data-testid="guided-tour-callout"
					className="fixed z-[70] w-[344px] max-w-[calc(100vw-24px)] rounded-xl border bg-card p-4 text-card-foreground shadow-xl outline-none animate-fade-up motion-reduce:animate-none"
					style={{ left: calloutStyle.left, top: calloutStyle.top }}
				>
					<div className="flex items-center justify-between gap-2">
						<p className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
							Step {index + 1} of {STEPS.length}
						</p>
						<Button
							type="button"
							variant="ghost"
							size="icon"
							onClick={finish}
							aria-label="Skip the tour"
							title="Skip the tour"
							className="size-7 text-muted-foreground transition-colors hover:text-foreground"
						>
							<X aria-hidden className="size-3.5" />
						</Button>
					</div>
					<h3 className="mt-0.5 text-sm font-semibold text-[#0055dc] dark:text-[#5e94ff]">
						{step.title}
					</h3>
					<p aria-live="polite" className="mt-1 text-xs leading-relaxed text-muted-foreground">
						{step.body}
					</p>
					<div className="mt-3 flex items-center justify-between gap-2">
						{index === 0 ? (
							<Button
								type="button"
								variant="ghost"
								size="sm"
								onClick={finish}
								className="h-7 px-2 text-xs text-muted-foreground"
							>
								Skip tour
							</Button>
						) : (
							<Button
								type="button"
								variant="ghost"
								size="sm"
								onClick={back}
								className="h-7 gap-1 px-2 text-xs"
							>
								<ChevronLeft aria-hidden className="size-3.5" />
								Back
							</Button>
						)}
						<Button
							type="button"
							size="sm"
							onClick={next}
							className="h-7 gap-1 bg-[#0055dc] px-3 text-xs text-white hover:bg-[#0046b8]"
						>
							{isLast ? "Finish" : "Next"}
							<ChevronRight aria-hidden className="size-3.5" />
						</Button>
					</div>
				</div>
			)}
		</>,
		document.body,
	);
}
