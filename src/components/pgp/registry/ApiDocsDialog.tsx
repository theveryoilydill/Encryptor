"use client";

/**
 * In-app public API reference (Task 24 owner feedback: "make some little
 * docs somewhere about how to use the public api" — the repo has
 * docs/key-registry.md, but a visitor of the deployed app never sees the
 * repository). This dialog renders the stable public endpoints with
 * copy-paste curl examples so the registry is consumable without reading
 * source. Content mirrors the docs; when you change an endpoint contract,
 * update BOTH. # Mr. AI Acting on s183173's Behalf
 */
import { Code2, ExternalLink } from "lucide-react";

import { Button } from "@/components/ui/button";
import {
	Dialog,
	DialogContent,
	DialogDescription,
	DialogHeader,
	DialogTitle,
} from "@/components/ui/dialog";

type ApiEndpoint = {
	method: "GET" | "POST";
	path: string;
	auth: string;
	notes: string;
};

const ENDPOINTS: ApiEndpoint[] = [
	{
		method: "GET",
		path: "/api/registry/lookup?fingerprint=|key_id=|email=",
		auth: "none",
		notes:
			"Public search (CORS *). Params take priority fingerprint > key_id > email. Add &words=1 to get the 20 PGP-word verification tokens per key. 120/h/IP.",
	},
	{
		method: "GET",
		path: "/api/registry/health",
		auth: "none",
		notes:
			"Schema + capability probe. Self-migrates a fresh database just by being hit. Reports limiterWrite:false when D1 writes are failing while reads still work.",
	},
	{
		method: "POST",
		path: "/api/registry/publish",
		auth: "rate-limited (5/h/IP)",
		notes:
			"JSON body { armored, encryptedPrivate?, dropEncryptedPrivate? }. The server parses and canonicalizes; private material in `armored` is rejected, escrow blobs must be passphrase-encrypted. Returns a one-time revocationToken — losing it means losing the token-based revoke path. Replacing an existing fingerprint requires a signed challenge.",
	},
	{
		method: "GET",
		path: "/api/registry/challenge?fingerprint=",
		auth: "rate-limited",
		notes:
			"One-time nonce plus the exact canonical message to sign with the private key (possession proof for replace / escrow writes / revoke-by-key). 10-minute TTL, single use.",
	},
	{
		method: "GET",
		path: "/api/registry/private-key?fingerprint=",
		auth: "rate-limited (30/h/IP)",
		notes:
			"Returns the escrowed ENCRYPTED private key blob (null when none). No CORS header, no caching. Revoked or unknown records only ever yield null.",
	},
	{
		method: "POST",
		path: "/api/registry/private-key",
		auth: "key-signed challenge",
		notes:
			"Store ({ encryptedPrivate }) or delete the escrow for a fingerprint. The nonce is consumed atomically; revoked records refuse escrow writes.",
	},
	{
		method: "POST",
		path: "/api/registry/revoke",
		auth: "revocation token OR signed challenge OR admin token",
		notes:
			"Permanent and irreversible. The token path works even without the private key. Purges any escrowed backup.",
	},
];

const METHOD_TINT: Record<ApiEndpoint["method"], string> = {
	GET: "bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border-emerald-500/30",
	POST: "bg-violet-500/10 text-violet-600 dark:text-violet-400 border-violet-500/30",
};

const CURL_EXAMPLES = `# Find a key by email (add &words=1 for PGP-word verification)
curl -s "$BASE/api/registry/lookup?email=alice@example.org" | jq

# Same lookup, results include the 20 PGP words per key
curl -s "$BASE/api/registry/lookup?fingerprint=<40-hex>&words=1" | jq

# Deployment health: schema, Turnstile, and whether D1 WRITES work
curl -s "$BASE/api/registry/health" | jq

# Publish (rate limited 5/h/IP — see docs/key-registry.md for the
# canonical-armor rules and the challenge-signed replace flow)
curl -s -X POST "$BASE/api/registry/publish" \\
  -H 'Content-Type: application/json' \\
  -d '{"armored":"-----BEGIN PGP PUBLIC KEY BLOCK-..."}' | jq`;

export function ApiDocsDialog({
	open,
	onOpenChange,
}: {
	open: boolean;
	onOpenChange: (open: boolean) => void;
}) {
	return (
		<Dialog open={open} onOpenChange={onOpenChange}>
			<DialogContent
				data-testid="registry-api-dialog"
				className="max-h-[85vh] overflow-y-auto sm:max-w-2xl"
			>
				<DialogHeader>
					<DialogTitle>Public registry API</DialogTitle>
					<DialogDescription>
						Every endpoint speaks JSON. Public reads need no auth; writes are rate limited per IP
						and gated where noted. <code className="font-mono">$BASE</code> is this
						deployment&apos;s origin.
					</DialogDescription>
				</DialogHeader>

				<ul className="space-y-2" aria-label="Registry endpoints">
					{ENDPOINTS.map((e) => (
						<li
							key={e.path + e.method}
							data-testid="api-endpoint-row"
							className="rounded-lg border border-border bg-card/60 px-3 py-2.5 transition-colors hover:border-violet-500/40"
						>
							<div className="flex flex-wrap items-center gap-2">
								<span
									className={`inline-flex items-center rounded-md border px-1.5 py-0.5 font-mono text-[10px] font-bold tracking-wide ${METHOD_TINT[e.method]}`}
								>
									{e.method}
								</span>
								<code className="min-w-0 break-all font-mono text-xs">{e.path}</code>
							</div>
							<p className="mt-1.5 text-[11px] font-medium text-muted-foreground">Auth: {e.auth}</p>
							<p className="mt-1 text-xs leading-relaxed text-muted-foreground">{e.notes}</p>
						</li>
					))}
				</ul>

				<div>
					<p className="mb-1.5 text-xs font-semibold">Quickstart with curl</p>
					<pre className="max-h-64 overflow-auto rounded-lg border border-border bg-muted/40 p-3 font-mono text-[11px] leading-relaxed">
						{CURL_EXAMPLES}
					</pre>
				</div>

				<p className="text-[11px] text-muted-foreground">
					Full contract, threat model and deployment notes live in{" "}
					<code className="font-mono">docs/key-registry.md</code> in the repository.
				</p>
			</DialogContent>
		</Dialog>
	);
}

/** Header action that opens the API reference. */
export function ApiDocsButton({ onClick }: { onClick: () => void }) {
	return (
		<Button
			type="button"
			variant="outline"
			size="sm"
			data-testid="registry-api-docs"
			onClick={onClick}
			className="h-7 gap-1.5 rounded-full px-3 text-[11px] font-medium text-muted-foreground hover:text-foreground"
		>
			<Code2 aria-hidden="true" className="size-3.5" />
			Public API
			<ExternalLink aria-hidden="true" className="size-3 opacity-60" />
		</Button>
	);
}
