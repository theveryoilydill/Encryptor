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
 * Review round addition: the widget now SURFACES failure codes instead of
 * failing silently. A Turnstile site key is hostname-allowlisted, so a
 * preview/branch deployment renders the widget but every challenge fails
 * with 110200 ("invalid domain") — which used to look exactly like the
 * "can't add keys" mystery from the review. The diagnostics below make the
 * mismatch (and the two owner-side fixes) explicit in the UI.
 *
 * Provisioning (production): the PUBLIC site key is committed in
 * `.env.production` (public by design — it ships in every visitor's HTML;
 * owner created the widget in PR #25). ONLY TURNSTILE_SECRET_KEY remains
 * owner-side (`wrangler secret put TURNSTILE_SECRET_KEY`): with the secret
 * absent the server keeps Turnstile disabled, so both halves must exist
 * together or publishing is either blocked (secret without site key) or
 * ungated (site key without secret) — the health endpoint reports the
 * active mode. The site key's hostname allowlist must include the exact
 * hostnames that render it (no wildcards): the production workers.dev host,
 * localhost for local tests, and each branch-preview hostname being tested;
 * anything else fails with 110200, surfaced by the diagnostics below.
 *
 * The script is loaded ON DEMAND (explicit render, onload callback) so
 * challenges.cloudflare.com is only contacted when a publish form is
 * actually mounted. Tokens are single-use: after a failed publish the
 * parent remounts the widget via a changing `key` prop to mint a new one.
 *
 * # Mr. AI Acting on s183173's Behalf
 */
import { useEffect, useRef, useState } from "react";
import { Loader2, ShieldAlert, ShieldCheck } from "lucide-react";

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

/** Human-readable diagnosis for a Turnstile error callback code. */
function describeTurnstileError(code: string): string {
	// Well-known codes from Cloudflare's client-side error list.
	if (code === "110200" || code === "110442" || code === "300030" || code === "600010") {
		return `This hostname is not allowlisted for the Turnstile site key (error ${code}) — publishing is impossible here until the owner adds this preview domain to the site key's hostname list, or switches preview builds to the always-pass dummy site key.`;
	}
	if (code.startsWith("1104")) {
		return `The Turnstile site key looks invalid for this widget (error ${code}) — check NEXT_PUBLIC_TURNSTILE_SITE_KEY at build time.`;
	}
	if (code === "110500" || code.startsWith("3")) {
		return `The Turnstile challenge could not run in this browser (error ${code}) — disable script blockers for challenges.cloudflare.com and retry.`;
	}
	return `The Turnstile challenge failed (error ${code}) — retry, or check the deployment's Turnstile site key configuration.`;
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
	const [errorCode, setErrorCode] = useState<string | null>(null);

	useEffect(() => {
		if (!SITE_KEY) return;
		let cancelled = false;
		let pollTimer: ReturnType<typeof setInterval> | null = null;

		const render = () => {
			if (cancelled || widgetIdRef.current !== null) return;
			if (!holderRef.current || !window.turnstile) return;
			widgetIdRef.current = window.turnstile.render(holderRef.current, {
				sitekey: SITE_KEY,
				callback: (token: string) => {
					setErrorCode(null);
					onTokenRef.current(token);
				},
				"expired-callback": () => onTokenRef.current(null),
				"timeout-callback": () => onTokenRef.current(null),
				"error-callback": (code: string) => {
					// Surface the failure instead of looping silently: the caller
					// sees WHY no token ever arrives (domain allowlist, bad site
					// key, blocked script) rather than a mystery 403 on publish.
					setErrorCode(code || "unknown");
					onTokenRef.current(null);
				},
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
			{errorCode && (
				<p
					data-testid="turnstile-error"
					className="mt-1 flex items-start gap-1.5 rounded-md border border-amber-500/40 bg-amber-500/5 px-2.5 py-2 text-[11px] leading-snug text-amber-800 dark:text-amber-300"
					role="alert"
				>
					<ShieldAlert aria-hidden="true" className="mt-0.5 size-3.5 shrink-0" />
					<span>{describeTurnstileError(errorCode)}</span>
				</p>
			)}
		</div>
	);
}
