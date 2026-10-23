"use client";

import { useTheme } from "next-themes";
import { Toaster as Sonner, ToasterProps } from "sonner";

/**
 * Sonner <Toaster /> themed to the app's dialog language (R8-b):
 * - surface, text, and border come from the shared popover/border tokens;
 * - radius uses the shared --radius token (= DialogContent's rounded-lg),
 *   replacing sonner's 8px default;
 * - richColors is enabled so success/error/info toasts use sonner's tinted
 *   surfaces, and the SUCCESS palette is remapped to the brand accent via
 *   token CSS variables (--link = #0055dc light / #5e94ff dark) — no
 *   hardcoded hex; icon, title, and description all follow the toast's
 *   `color` (sonner default structure). Error/info/warning keep sonner's
 *   own palettes.
 * The remaining box-shadow default is aligned to the shadow-sm token in
 * globals.css ([data-sonner-toast] rule).
 *
 * Note: today the mounted toast surface is the Radix ui/toaster.tsx; this
 * component stays theme-correct for a drop-in swap.
 */
const Toaster = ({ ...props }: ToasterProps) => {
	const { resolvedTheme = "system" } = useTheme();

	return (
		<Sonner
			theme={
				(resolvedTheme === "dark"
					? "dark"
					: resolvedTheme === "light"
						? "light"
						: "system") as ToasterProps["theme"]
			}
			className="toaster group"
			richColors
			style={
				{
					"--normal-bg": "var(--popover)",
					"--normal-text": "var(--popover-foreground)",
					"--normal-border": "var(--border)",
					"--normal-bg-hover": "var(--accent)",
					"--border-radius": "var(--radius)",
					"--success-bg": "color-mix(in srgb, var(--link) 8%, var(--popover))",
					"--success-border": "color-mix(in srgb, var(--link) 30%, transparent)",
					"--success-text": "var(--link)",
				} as React.CSSProperties
			}
			{...props}
		/>
	);
};

export { Toaster };
