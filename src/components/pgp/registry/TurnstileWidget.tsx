"use client";

/**
 * Cloudflare Turnstile anti-bot widget for registry writes.
 *
 * Owner request (PR #25 review): "Make a Cloudflare Turnstile to add things
 * to the database" — this is the client half. The server half lives in
 * src/lib/registry/turnstile.ts and only enforces when TURNSTILE_SECRET_KEY
 * is configured, so this component also degrades gracefully when the PUBLIC
 * site key is absent (local dev, preview builds): it renders a subtle
 * "not configured" note instead of an impossible challenge.
 *
 * Provisioning (production): set NEXT_PUBLIC_TURNSTILE_SITE_KEY at build
 * time (Workers Builds env) AND TURNSTILE_SECRET_KEY as a worker secret —
 * both halves must exist together or publishing is either blocked (secret
 * without site key) or ungated (site key without secret).
 *
 * The script is loaded ON DEMAND (explicit render, onload callback) so
 * challenges.cloudflare.com is only contacted when a publish form is
 * actually mounted. Tokens are single-use: after a failed publish the
 * parent remounts the widget via a changing `key` prop to mint a new one.
 *
 * # Mr. AI Acting on s183173's Behalf
 */
import { useEffect, useRef, useState } from "react";
import { Loader2, ShieldCheck } from "lucide-react";

/** Shape of the explicit-render API we use (subset). */
interface TurnstileApi {
	render: (el: HTMLElement, opts: Record<string, unknown>) => string;
	reset: (id?: string) => void;
	remove: (id: string) => void;
}

declare global {
	interface Window {
		turnstile?: TurnstileApi;
		__encryptorTurnstileOnLoad?: () => void;
	}
}

const SCRIPT_SRC =
	"https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit&onload=__encryptorTurnstileOnLoad";

/** Build-time public site key (harmless to expose; the secret stays server-side). */
const SITE_KEY: string = process.env.NEXT_PUBLIC_TURNSTILE_SITE_KEY ?? "";

/** Whether the widget can render at all on this deployment. */
export function turnstileSiteKeyConfigured(): boolean {
	return SITE_KEY.length > 0;
}

export function TurnstileWidget({
	id,
	onToken,
}: {
	/** Unique DOM id so tests can target the container. */
	id: string;
	/** Called with the fresh token, or null when it expires/errors/resets. */
	onToken: (token: string | null) => void;
}) {
	const holderRef = useRef<HTMLDivElement | null>(null);
	const widgetIdRef = useRef<string | null>(null);
	const onTokenRef = useRef(onToken);
	onTokenRef.current = onToken;
	const [ready, setReady] = useState(false);

	useEffect(() => {
		if (!SITE_KEY) return;
		let cancelled = false;
		let pollTimer: ReturnType<typeof setInterval> | null = null;

		const render = () => {
			if (cancelled || widgetIdRef.current !== null) return;
			if (!holderRef.current || !window.turnstile) return;
			widgetIdRef.current = window.turnstile.render(holderRef.current, {
				sitekey: SITE_KEY,
				callback: (token: string) => onTokenRef.current(token),
				"expired-callback": () => onTokenRef.current(null),
				"timeout-callback": () => onTokenRef.current(null),
				"error-callback": () => onTokenRef.current(null),
				theme: "auto",
				tabindex: 0,
			});
			setReady(true);
		};

		if (window.turnstile) {
			render();
		} else if (!document.querySelector(`script[src^="${SCRIPT_SRC.split("?")[0]}"]`)) {
			window.__encryptorTurnstileOnLoad = render;
			const script = document.createElement("script");
			script.src = SCRIPT_SRC;
			script.async = true;
			script.defer = true;
			document.head.appendChild(script);
		} else {
			// Another widget's mount already injected the script; wait for it.
			pollTimer = setInterval(() => {
				if (window.turnstile) {
					if (pollTimer) clearInterval(pollTimer);
					render();
				}
			}, 120);
		}

		return () => {
			cancelled = true;
			if (pollTimer) clearInterval(pollTimer);
			if (widgetIdRef.current !== null && window.turnstile) {
				try {
					window.turnstile.remove(widgetIdRef.current);
				} catch {
					// The iframe may already be gone on unmount races.
				}
				widgetIdRef.current = null;
			}
		};
	}, []);

	if (!SITE_KEY) {
		return (
			<p
				id={id}
				data-testid="turnstile-disabled-note"
				className="flex items-start gap-1.5 rounded-md border border-dashed border-border bg-muted/30 px-2.5 py-2 text-[11px] leading-snug text-muted-foreground"
			>
				<ShieldCheck aria-hidden="true" className="mt-0.5 size-3.5 shrink-0" />
				<span>
					Bot protection (Cloudflare Turnstile) is not configured on this deployment — registry
					writes are not captcha-gated here.
				</span>
			</p>
		);
	}

	return (
		<div
			id={id}
			data-testid="turnstile-widget"
			className="min-h-[65px] transition-opacity duration-200"
			role="group"
			aria-label="Cloudflare Turnstile anti-bot verification"
		>
			<div ref={holderRef} />
			{!ready && (
				<p className="mt-1 flex items-center gap-1.5 text-[11px] text-muted-foreground">
					<Loader2 aria-hidden="true" className="size-3 animate-spin" />
					Loading bot-protection challenge…
				</p>
			)}
		</div>
	);
}
