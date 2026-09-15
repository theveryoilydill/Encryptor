"use client";

/**
 * Vault manifest import review (round 18): shows what a picked manifest
 * contains BEFORE anything touches the vault, and lets the user choose
 * between Merge (add the entries — duplicates skipped, nothing removed)
 * and Replace all (the vault becomes exactly this manifest). Pure
 * presentation: the counts arrive already computed by parseVaultManifest
 * (the same sanitizers as the localStorage load path) and both actions
 * are the parent's callbacks — this component never mutates the vault.
 *
 * # Mr. AI Acting on s183173's Behalf
 */

import { CalendarDays, History, Paperclip, ShieldCheck, Sparkles } from "lucide-react";

import { Button } from "@/components/ui/button";
import {
	Dialog,
	DialogContent,
	DialogDescription,
	DialogFooter,
	DialogHeader,
	DialogTitle,
} from "@/components/ui/dialog";

export function VaultImportDialog({
	open,
	onOpenChange,
	entryCount,
	vaultCount,
	skippedRows,
	signedCount,
	quantumCount,
	filesCount,
	exportedAt,
	onMerge,
	onReplace,
}: {
	open: boolean;
	/** Escape, outside click or Cancel all route here — the parent treats
	 *  `false` as "cancelled, touch nothing". */
	onOpenChange: (open: boolean) => void;
	/** Intact entries the manifest carries (post-sanitize). */
	entryCount: number;
	/** Entries the user's vault currently holds. */
	vaultCount: number;
	/** Manifest rows the validator skipped as unusable. */
	skippedRows: number;
	/** Manifest entries carrying a signer label. */
	signedCount: number;
	/** Manifest entries carrying a quantum-sealed copy. */
	quantumCount: number;
	/** Summed attachment counts across manifest entries. */
	filesCount: number;
	/** Manifest exportedAt passthrough — display only. */
	exportedAt?: string;
	onMerge: () => void;
	onReplace: () => void;
}) {
	const exported = exportedAt ? new Date(exportedAt) : null;
	const exportedLabel =
		exported && !Number.isNaN(exported.getTime())
			? exported.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" })
			: undefined;

	return (
		<Dialog open={open} onOpenChange={onOpenChange}>
			<DialogContent className="sm:max-w-md">
				<DialogHeader>
					<DialogTitle>
						{entryCount} intact {entryCount === 1 ? "entry" : "entries"} found · your vault holds{" "}
						{vaultCount}
						{skippedRows > 0
							? `, ${skippedRows} unusable ${skippedRows === 1 ? "row" : "rows"} skipped`
							: ""}
					</DialogTitle>
					<DialogDescription>
						Nothing is imported until you choose — cancel and the vault stays untouched.
					</DialogDescription>
				</DialogHeader>

				{/* Stats panel: what the manifest holds, at a glance. */}
				<div className="grid grid-cols-2 gap-1.5 rounded-xl border border-border bg-muted/30 p-3 text-xs">
					<span className="flex items-center gap-1.5">
						<History aria-hidden="true" className="size-3.5 text-muted-foreground" />
						{entryCount} in the manifest
					</span>
					<span className="flex items-center gap-1.5 text-emerald-600 dark:text-emerald-500">
						<ShieldCheck aria-hidden="true" className="size-3.5" />
						{signedCount} signed
					</span>
					<span className="flex items-center gap-1.5 text-violet-600 dark:text-violet-500">
						<Sparkles aria-hidden="true" className="size-3.5" />
						{quantumCount} quantum-sealed
					</span>
					<span className="flex items-center gap-1.5">
						<Paperclip aria-hidden="true" className="size-3.5 text-muted-foreground" />
						{filesCount} attached
					</span>
					{exportedLabel && (
						<span className="col-span-2 flex items-center gap-1.5 text-muted-foreground">
							<CalendarDays aria-hidden="true" className="size-3.5" />
							Exported {exportedLabel}
						</span>
					)}
				</div>

				{/* Merge-vs-Replace explainer — Replace is destructive, so say exactly
				    what each choice does before it happens. */}
				<div className="space-y-1 text-[11px] leading-relaxed text-muted-foreground">
					<p>
						<span className="font-medium text-foreground">Merge</span> adds the manifest entries —
						duplicates (same ciphertext) are skipped and nothing is removed.
					</p>
					<p>
						<span className="font-medium text-foreground">Replace all</span> makes your vault
						exactly this manifest — entries you hold that aren't in it are gone.
					</p>
				</div>

				<DialogFooter className="gap-2 sm:gap-1.5">
					<Button type="button" variant="ghost" onClick={() => onOpenChange(false)}>
						Cancel
					</Button>
					<Button
						type="button"
						variant="outline"
						onClick={onReplace}
						className="border-red-500/50 text-red-600 hover:bg-red-500/10 hover:text-red-600 dark:text-red-500 dark:hover:text-red-500"
					>
						Replace all
					</Button>
					<Button type="button" onClick={onMerge}>
						Merge
					</Button>
				</DialogFooter>
			</DialogContent>
		</Dialog>
	);
}
