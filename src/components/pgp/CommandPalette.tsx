"use client";

/**
 * Command palette (Ctrl/Cmd+K).
 *
 * # Mr. AI Acting on s183173's Behalf
 *
 * A keyboard-first launcher for everything the app can do from anywhere:
 * switch modes, open your key, run app actions. Built on cmdk (the
 * dependency was already present for shadcn) via the ui/command primitives —
 * no new dependencies.
 *
 * SECURITY: pure UI navigation. Nothing here reads or persists key
 * material; "Copy public key" copies exactly the public armor block that
 * the "Your key" dialog already offers, via the same clipboard path.
 *
 * Accessibility: Radix dialog semantics (title + description provided by
 * CommandDialog are visually hidden but announced), roving arrow-key
 * selection and Enter activation come from cmdk. Motion respects the
 * global motion-reduce guard on DialogContent.
 */
import { useTheme } from "next-themes";
import {
	Compass,
	Copy,
	FlaskConical,
	Keyboard as KeyboardIcon,
	Lock,
	LockOpen,
	PenLine,
	Settings as SettingsIcon,
	ShieldCheck,
	Command as CommandIcon,
	KeyRound,
} from "lucide-react";

import {
	CommandDialog,
	CommandEmpty,
	CommandGroup,
	CommandInput,
	CommandItem,
	CommandList,
	CommandShortcut,
} from "@/components/ui/command";
import { TABS, type Tab } from "@/components/pgp/contracts";

export function CommandPalette({
	open,
	onOpenChange,
	onSwitchTab,
	onOpenKeyModal,
	onCopyPublicKey,
	onOpenSettings,
	onOpenShortcuts,
	onReplayTour,
	onSelfTest,
	passphraseCached,
	onLockNow,
}: {
	open: boolean;
	onOpenChange: (open: boolean) => void;
	/** Flip to a tab (same handler the Alt+1..4 bindings use). */
	onSwitchTab: (tab: Tab) => void;
	onOpenKeyModal: () => void;
	onCopyPublicKey: () => void;
	onOpenSettings: () => void;
	onOpenShortcuts: () => void;
	onReplayTour: () => void;
	onSelfTest: () => void;
	/** Whether a session passphrase is currently cached in memory — the lock
	 *  action only exists while there is something to lock. */
	passphraseCached: boolean;
	/** Forget the cached session passphrase now (same handler the "Your key"
	 *  dialog uses — it already toasts confirmation). */
	onLockNow: () => void;
}) {
	const { theme, setTheme } = useTheme();
	const current = theme === "light" || theme === "dark" ? theme : "system";
	const next = current === "light" ? "dark" : current === "dark" ? "system" : "light";
	const themeLabel =
		next === "light"
			? "Theme: switch to light"
			: next === "dark"
				? "Theme: switch to dark"
				: "Theme: follow system";

	/** Run an action, then close the palette — every item shares this. */
	const run = (action: () => void) => () => {
		onOpenChange(false);
		action();
	};

	/** Tab icons keyed by id (order matches TABS in contracts.ts). */
	const tabIcons: Record<Tab, typeof Lock> = {
		encrypt: Lock,
		decrypt: LockOpen,
		sign: PenLine,
		verify: ShieldCheck,
	};

	return (
		<CommandDialog
			open={open}
			onOpenChange={onOpenChange}
			title="Command palette"
			description="Search for a command to run — switch modes, manage your key, or open app actions."
			className="top-[16%] translate-y-0 sm:max-w-md"
			showCloseButton={false}
		>
			<CommandInput placeholder="Type a command or search…" />
			<CommandList>
				<CommandEmpty>No matching commands.</CommandEmpty>
				<CommandGroup heading="Go to">
					{TABS.map((t, i) => {
						const Icon = tabIcons[t.id];
						return (
							<CommandItem
								key={t.id}
								value={`${t.label} tab`}
								onSelect={run(() => onSwitchTab(t.id))}
							>
								<Icon aria-hidden />
								{t.label}
								<CommandShortcut>Alt+{i + 1}</CommandShortcut>
							</CommandItem>
						);
					})}
				</CommandGroup>
				<CommandGroup heading="Your key">
					<CommandItem value="your key manage identity" onSelect={run(onOpenKeyModal)}>
						<KeyRound aria-hidden />
						Your key
					</CommandItem>
					<CommandItem value="copy public key armor share" onSelect={run(onCopyPublicKey)}>
						<Copy aria-hidden />
						Copy public key
					</CommandItem>
				</CommandGroup>
				<CommandGroup heading="App">
					<CommandItem value="settings preferences auto-lock" onSelect={run(onOpenSettings)}>
						<SettingsIcon aria-hidden />
						Settings
						<CommandShortcut>Ctrl+,</CommandShortcut>
					</CommandItem>
					<CommandItem value="keyboard shortcuts help bindings" onSelect={run(onOpenShortcuts)}>
						<KeyboardIcon aria-hidden />
						Keyboard shortcuts
					</CommandItem>
					<CommandItem value="replay guided tour walkthrough help" onSelect={run(onReplayTour)}>
						<Compass aria-hidden />
						Replay guided tour
					</CommandItem>
					<CommandItem
						value="theme light dark system appearance toggle"
						onSelect={run(() => setTheme(next))}
					>
						<CommandIcon aria-hidden />
						{themeLabel}
					</CommandItem>
					<CommandItem
						value="crypto self test diagnostics verify implementation"
						onSelect={run(onSelfTest)}
					>
						<FlaskConical aria-hidden />
						Crypto self-test
					</CommandItem>
					{passphraseCached && (
						<CommandItem
							value="lock session passphrase forget lock now security"
							onSelect={run(onLockNow)}
						>
							<Lock aria-hidden />
							Lock session passphrase now
						</CommandItem>
					)}
				</CommandGroup>
			</CommandList>
		</CommandDialog>
	);
}
