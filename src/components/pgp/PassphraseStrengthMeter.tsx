"use client";

/**
 * PassphraseStrengthMeter — animated 4-segment strength gauge for the
 * key-pair generation and local-import passphrase fields.
 * # Mr. AI Acting on s183173's Behalf
 *
 * Design brief: #0055dc accent family is reserved for actions; strength
 * uses a semantic red→orange→amber→emerald ramp. Transitions stay in the
 * 150–200 ms range. Renders nothing for an empty passphrase so the form
 * stays calm until the user starts typing.
 */

import { useMemo } from "react";

import { estimatePassphraseStrength } from "@/lib/pgp/passphrase-strength";
import { cn } from "@/lib/utils";

const SEGMENT_COLORS = [
	"bg-red-500 dark:bg-red-400",
	"bg-orange-500 dark:bg-orange-400",
	"bg-amber-500 dark:bg-amber-400",
	"bg-emerald-500 dark:bg-emerald-400",
	"bg-emerald-600 dark:bg-emerald-300",
] as const;

const LABEL_COLORS = [
	"text-red-600 dark:text-red-400",
	"text-orange-600 dark:text-orange-400",
	"text-amber-600 dark:text-amber-400",
	"text-emerald-600 dark:text-emerald-400",
	"text-emerald-700 dark:text-emerald-300",
] as const;

export function PassphraseStrengthMeter({
	passphrase,
	idPrefix = "keys-pass",
}: {
	passphrase: string;
	/** Used for aria wiring against the owning input's id. */
	idPrefix?: string;
}) {
	const strength = useMemo(() => estimatePassphraseStrength(passphrase), [passphrase]);

	if (!passphrase) return null;

	return (
		<div
			className="space-y-1 pt-0.5"
			role="status"
			aria-label={`Passphrase strength: ${strength.label}`}
		>
			<div className="flex items-center gap-2" aria-hidden="true">
				<div className="flex flex-1 gap-1">
					{[0, 1, 2, 3].map((i) => (
						<div
							key={i}
							className={cn(
								"h-1 flex-1 rounded-full transition-colors duration-200 ease-out",
								i <= strength.score - 1 ? SEGMENT_COLORS[strength.score] : "bg-border",
							)}
						/>
					))}
				</div>
				<span
					className={cn(
						"min-w-16 text-right text-[11px] font-medium tabular-nums transition-colors duration-200",
						LABEL_COLORS[strength.score],
					)}
				>
					{strength.label}
				</span>
			</div>
			{strength.hint ? (
				<p
					id={`${idPrefix}-strength-hint`}
					className="text-[11px] leading-snug text-muted-foreground"
				>
					{strength.hint}
				</p>
			) : (
				<p
					id={`${idPrefix}-strength-hint`}
					className="text-[11px] leading-snug text-muted-foreground"
				>
					≈{strength.entropyBits} bits of entropy — good protection for an escrowed key.
				</p>
			)}
		</div>
	);
}
