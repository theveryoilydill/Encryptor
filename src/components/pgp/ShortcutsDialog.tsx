"use client";

/**
 * "Keyboard shortcuts" help dialog.
 *
 * Lists the global Alt+1..4 tab bindings implemented in PgpApp.tsx (TABS
 * order: encrypt, decrypt, sign, verify) — keep SHORTCUTS in sync if that
 * order ever changes. Opened from a ghost icon button in the header, next
 * to the theme toggle (same a11y pattern as ConfigureModal/PassphrasePrompt:
 * DialogTitle required + DialogDescription to avoid Radix warnings).
 */
import { useState } from "react";
import { Keyboard } from "lucide-react";

import { Button } from "@/components/ui/button";
import {
	Dialog,
	DialogContent,
	DialogDescription,
	DialogHeader,
	DialogTitle,
} from "@/components/ui/dialog";

/** The global bindings from PgpApp.tsx (tab order: TABS array), plus the
 *  per-tab bindings handled inside the tab components: Ctrl/Cmd+Enter runs
 *  the tab's action; Ctrl/Cmd+Shift+E toggles the Encrypt tab's full-screen
 *  composer. */
const SHORTCUTS: { keys: string; description: string }[] = [
	{ keys: "Alt+1", description: "Encrypt" },
	{ keys: "Alt+2", description: "Decrypt" },
	{ keys: "Alt+3", description: "Sign" },
	{ keys: "Alt+4", description: "Verify" },
	{ keys: "Ctrl+Enter", description: "Run the tab's action (encrypt / sign / verify)" },
	{ keys: "Ctrl+Shift+E", description: "Expand / collapse the composer" },
	{ keys: "Ctrl+,", description: "Open Settings" },
];

export function ShortcutsDialog() {
	const [open, setOpen] = useState(false);

	return (
		<Dialog open={open} onOpenChange={setOpen}>
			<Button
				variant="ghost"
				size="icon"
				onClick={() => setOpen(true)}
				aria-label="Keyboard shortcuts"
				title="Keyboard shortcuts"
				data-tour="shortcuts-button"
				className="size-11 text-muted-foreground transition-colors hover:text-foreground press-effect sm:size-8"
			>
				<Keyboard className="size-4" aria-hidden />
			</Button>
			<DialogContent className="max-h-[90vh] gap-0 overflow-hidden p-0 sm:max-w-sm">
				<DialogHeader className="border-b px-5 py-3.5">
					<DialogTitle className="text-base font-semibold">Keyboard shortcuts</DialogTitle>
					<DialogDescription className="text-xs text-muted-foreground">
						Switch modes from anywhere in the app.
					</DialogDescription>
				</DialogHeader>
				<ul className="space-y-2 px-5 py-4">
					{SHORTCUTS.map((s) => (
						<li key={s.keys} className="flex items-center justify-between gap-3">
							<span className="text-sm text-muted-foreground">{s.description}</span>
							<kbd className="rounded border bg-muted px-1.5 py-0.5 text-[10px] font-mono">
								{s.keys}
							</kbd>
						</li>
					))}
				</ul>
				{/* Tips section (R11): drop-to-load affordance added by R10-a. Styled
            after the dialog's existing rhythm (border-t footer band, px-5,
            muted text with an inline foreground-weighted lead label — the
            same "Detected format:" inline-label pattern the tabs use). */}
				<div className="border-t px-5 py-3.5">
					<p className="text-xs text-muted-foreground">
						<span className="font-medium text-foreground">Tip:</span> dropping a .asc file onto the
						Decrypt or Verify input cards loads it.
					</p>
				</div>
			</DialogContent>
		</Dialog>
	);
}
