"use client";

/**
 * ApiReferenceDialog — the "little docs somewhere about how to use the
 * public API" the owner asked for (PR #25). A compact, self-hosted cheat
 * sheet living in the app footer: every registry endpoint with its method,
 * one-line purpose, and two copy-pasteable curl examples. Static content —
 * no fetches, no state beyond open/close.
 *
 * # Mr. AI Acting on s183173's Behalf
 */
import { useState } from "react";
import { Code2 } from "lucide-react";

import { Button } from "@/components/ui/button";
import {
	Dialog,
	DialogContent,
	DialogDescription,
	DialogHeader,
	DialogTitle,
} from "@/components/ui/dialog";
import { CopyButton } from "@/components/pgp/shared";

const ENDPOINTS: {
	method: "GET" | "POST";
	path: string;
	purpose: string;
	note?: string;
}[] = [
	{
		method: "GET",
		path: "/api/registry/lookup?fingerprint=|key_id=|email=",
		purpose: "Find a published public key (armored + metadata)",
		note: "No auth, CORS *, cached 60s",
	},
	{
		method: "GET",
		path: "/api/registry/private-key?fingerprint=",
		purpose: "Fetch the passphrase-ENCRYPTED escrow backup (restore)",
		note: "null when none — never usable key bytes",
	},
	{
		method: "POST",
		path: "/api/registry/publish",
		purpose: "Publish { armored } public key (+ optional encryptedPrivate escrow)",
		note: "Returns a one-time revocationToken — shown once",
	},
	{
		method: "GET",
		path: "/api/registry/challenge?fingerprint=",
		purpose: "Mint a one-time nonce to sign (replace / revoke proofs)",
	},
	{
		method: "POST",
		path: "/api/registry/revoke",
		purpose: "Retract with { fingerprint, token } or a signed challenge",
		note: "Permanent — revoked fingerprints can't re-publish",
	},
	{
		method: "POST",
		path: "/api/registry/private-key",
		purpose: "Store/delete the escrow with a key-signed challenge",
	},
	{
		method: "GET",
		path: "/api/registry/health",
		purpose: "Operator probe: schema, limiter, Turnstile, write-lock state",
	},
];

const CURL_LOOKUP = `curl -s "https://<worker>/api/registry/lookup?email=you@example.com" | jq`;

const CURL_REVOKE = `curl -s -X POST "https://<worker>/api/registry/revoke" \\
  -H "Content-Type: application/json" \\
  -d '{"fingerprint":"<40 hex>","token":"<your one-time token>"}'`;

function MethodBadge({ method }: { method: "GET" | "POST" }) {
	return (
		<span
			className={`inline-block w-11 shrink-0 rounded px-1 py-0.5 text-center font-mono text-[10px] font-semibold ${
				method === "GET"
					? "bg-emerald-500/10 text-emerald-700 dark:text-emerald-300"
					: "bg-amber-500/10 text-amber-700 dark:text-amber-300"
			}`}
		>
			{method}
		</span>
	);
}

export function ApiReferenceDialog() {
	const [open, setOpen] = useState(false);
	return (
		<Dialog open={open} onOpenChange={setOpen}>
			<Button
				variant="ghost"
				size="sm"
				onClick={() => setOpen(true)}
				className="h-7 gap-1.5 px-2 text-[11px] text-muted-foreground transition-colors hover:text-[#0055dc] dark:hover:text-[#5e94ff] press-effect"
				title="How to use the public key registry API"
			>
				<Code2 className="size-3" aria-hidden />
				Public API
			</Button>
			<DialogContent className="sm:max-w-lg max-h-[85dvh] overflow-y-auto">
				<DialogHeader>
					<DialogTitle>Public registry API</DialogTitle>
					<DialogDescription>
						Look up published keys from any client. Reads are open (CORS *); writes are rate-limited
						and proof-gated. Replace {"<worker>"} with this deployment&apos;s origin.
					</DialogDescription>
				</DialogHeader>

				<ul className="space-y-2" data-testid="api-endpoints">
					{ENDPOINTS.map((e) => (
						<li key={e.path} className="flex gap-2 rounded-lg border border-border px-2.5 py-2">
							<MethodBadge method={e.method} />
							<div className="min-w-0">
								<code className="block break-all font-mono text-[11px] leading-snug">{e.path}</code>
								<span className="mt-0.5 block text-[11px] text-muted-foreground">{e.purpose}</span>
								{e.note && (
									<span className="mt-0.5 block text-[10px] italic text-muted-foreground/80">
										{e.note}
									</span>
								)}
							</div>
						</li>
					))}
				</ul>

				<div className="space-y-2" data-testid="api-curl-examples">
					<div>
						<p className="mb-1 text-[11px] font-medium">Look up a key</p>
						<div className="flex items-start gap-1.5">
							<pre className="min-w-0 flex-1 overflow-x-auto rounded-md bg-muted px-2.5 py-2 font-mono text-[11px] leading-relaxed">
								{CURL_LOOKUP}
							</pre>
							<CopyButton text={CURL_LOOKUP} label="Copy" ariaLabel="Copy lookup example" />
						</div>
					</div>
					<div>
						<p className="mb-1 text-[11px] font-medium">Revoke a key (one-time token)</p>
						<div className="flex items-start gap-1.5">
							<pre className="min-w-0 flex-1 overflow-x-auto rounded-md bg-muted px-2.5 py-2 font-mono text-[11px] leading-relaxed">
								{CURL_REVOKE}
							</pre>
							<CopyButton text={CURL_REVOKE} label="Copy" ariaLabel="Copy revoke example" />
						</div>
					</div>
				</div>

				<p className="text-[11px] leading-relaxed text-muted-foreground">
					Full design doc:{" "}
					<code className="rounded bg-muted px-1 font-mono text-[10px]">docs/key-registry.md</code>{" "}
					in the repository.
				</p>
			</DialogContent>
		</Dialog>
	);
}
