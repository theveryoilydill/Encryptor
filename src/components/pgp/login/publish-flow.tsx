"use client";

/**
 * Shared registry-publish machinery for the login gate.
 *
 * One implementation of: Turnstile gating → publish → (409 "already
 * exists" → possession-proof replace) → outcome card with the one-time
 * revocation token. Used by the "Encryptor Registry" card (publish a
 * pasted key) and the "Local keys" card (publish a generated pair).
 *
 * Simplified from the old Keys tab per the PR #25 review: no my-keys
 * bookkeeping, no backup import/export, no watch layer — the outcome card
 * surfaces everything that matters (fingerprint, escrow state, revocation
 * token shown ONCE) at publish time.
 *
 * # Mr. AI Acting on s183173's Behalf
 */
import { useCallback, useEffect, useState } from "react";
import { TriangleAlert } from "lucide-react";

import { Alert, AlertDescription } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { CopyButton } from "@/components/pgp/shared";
import {
	TurnstileWidget,
	turnstileSiteKeyConfigured,
} from "@/components/pgp/registry/TurnstileWidget";
import {
	RegistryClientError,
	formatRegistryError,
	registryChallenge,
	registryHealth,
	registryPublish,
	signChallenge,
	type RegistryHealth,
} from "@/lib/registry/client";
import { formatFingerprint } from "@/lib/pgp/pgp";

/** Result of a successful publish (subset the UI needs). */
export interface PublishOutcome {
	fingerprint: string;
	keyId: string;
	emails: string[];
	replaced: boolean;
	revocationToken?: string;
	escrowed: boolean;
	/** A replace that skipped escrow left a previously stored escrow behind
	 *  (it predates the new key version — restoring it would hand back stale
	 *  material). Amber-flagged on the outcome card. */
	escrowLag?: boolean;
}

/**
 * Derive the publishable public armor from a (possibly passphrase-encrypted)
 * private key. toPublic() strips the secret parameters without needing the
 * passphrase, so this never asks for one.
 */
export async function publicFromPrivate(armoredPrivate: string): Promise<string> {
	const openpgp = await import("openpgp");
	const key = await openpgp.readKey({ armoredKey: armoredPrivate });
	if (!key.isPrivate()) return key.armor();
	return key.toPublic().armor();
}

/**
 * Memoized health probe shared by every publish-surface consumer
 * (TurnstileGate, useWritesLocked). One network probe per 30s window per
 * page instead of one per mounted component — health is slow-changing
 * configuration, and the probe hits D1 server-side so it should stay rare.
 * A failed probe resolves null so consumers fail open (UI stays usable and
 * the server still has the final word).
 */
let sharedHealthCache: { at: number; promise: Promise<RegistryHealth | null> } | null = null;
export function sharedHealth(ttlMs = 30_000): Promise<RegistryHealth | null> {
	if (!sharedHealthCache || Date.now() - sharedHealthCache.at > ttlMs) {
		sharedHealthCache = {
			at: Date.now(),
			promise: registryHealth().catch(() => null),
		};
	}
	return sharedHealthCache.promise;
}

/**
 * Tri-state "does THIS deployment allow registry writes?": true only when
 * the server EXPLICITLY reports writesAllowedHere:false (REGISTRY_PROD_ORIGIN
 * set + non-production host). null (probe failed / field missing) and false
 * both mean "assume writable" — the lock UX must never appear on healthy
 * deployments, and the server still rejects anything the UI misses.
 */
export function useWritesLocked(): boolean | null {
	const [locked, setLocked] = useState<boolean | null>(null);
	useEffect(() => {
		let cancelled = false;
		void sharedHealth().then((h) => {
			if (!cancelled) setLocked(h?.writesAllowedHere === false);
		});
		return () => {
			cancelled = true;
		};
	}, []);
	return locked;
}

/**
 * Read-only notice for write-locked deployments (branch previews while the
 * owner enforces REGISTRY_PROD_ORIGIN). Rendered above publish actions —
 * pairs with disabling them so users never fill a form that can only 403.
 */
export function WritesLockedNotice() {
	return (
		<div
			data-testid="writes-locked-notice"
			role="note"
			className="rounded-lg border border-amber-500/40 bg-amber-500/5 px-3 py-2 text-[11px] leading-relaxed text-amber-800 dark:text-amber-300"
		>
			This deployment is <span className="font-semibold">read-only</span>: registry writes are
			locked to the production origin (REGISTRY_PROD_ORIGIN). Lookups and restores still work —
			publish from the production site instead.
		</div>
	);
}

/**
 * Turnstile gate: renders the challenge only when the SERVER enforces it.
 * Probes /api/registry/health once and pairs that with the build-time site
 * key so every mismatch is explainable instead of a mystery 403:
 *  - enforced + site key  → widget (token required before publish);
 *  - enforced + no site key → amber note (build/deploy mismatch, owner-fixable);
 *  - disabled → nothing (no bot gate on this deployment).
 */
export function TurnstileGate({
	onToken,
	attempt,
}: {
	onToken: (t: string | null) => void;
	/** Bump to remount the widget — tokens are single-use. */
	attempt: number;
}) {
	const [enforced, setEnforced] = useState<boolean | null>(null);

	useEffect(() => {
		let cancelled = false;
		void sharedHealth().then((h) => {
			if (!cancelled) setEnforced(h ? h.turnstile === "enforced" : null);
		});
		return () => {
			cancelled = true;
		};
	}, []);

	if (enforced === null) return null;
	if (!enforced) return null; // deployment does not gate writes
	if (!turnstileSiteKeyConfigured()) {
		return (
			<Alert className="border-amber-500/40 bg-amber-500/5">
				<TriangleAlert className="size-4 text-amber-600" />
				<AlertDescription className="text-xs">
					This deployment enforces Turnstile bot verification, but this build has no{" "}
					<code className="rounded bg-muted px-1">NEXT_PUBLIC_TURNSTILE_SITE_KEY</code> — publishing
					would always 403. Set that build variable (or remove{" "}
					<code className="rounded bg-muted px-1">TURNSTILE_SECRET_KEY</code> from the worker) and
					rebuild.
				</AlertDescription>
			</Alert>
		);
	}
	return <TurnstileWidget key={attempt} id={`turnstile-publish-${attempt}`} onToken={onToken} />;
}

/** Shared publish state machine (Turnstile + 409 possession-proof replace). */
export function useRegistryPublish() {
	const [publishing, setPublishing] = useState(false);
	const [replaceNeeded, setReplaceNeeded] = useState(false);
	const [replacing, setReplacing] = useState(false);
	const [error, setError] = useState<string | null>(null);
	// Tokens are single-use: every attempt that consumed one (or errored)
	// bumps the attempt counter so the widget remounts and mints a new one.
	const [tsToken, setTsToken] = useState<string | null>(null);
	const [tsAttempt, setTsAttempt] = useState(0);

	const resetTs = useCallback(() => {
		setTsToken(null);
		setTsAttempt((a) => a + 1);
	}, []);

	/**
	 * Publish `publicArmored` (escrow optional). On 409 "already exists",
	 * flips to replace-needed: the caller shows a passphrase field and calls
	 * `confirmReplace` with the same input. Returns the outcome, or null
	 * when the flow stopped for input (error/replace state is on the hook).
	 */
	const publish = useCallback(
		async (input: {
			publicArmored: string;
			encryptedPrivate?: string;
			/** Private armor used to sign a replace challenge (possession proof). */
			signArmor?: string;
		}): Promise<PublishOutcome | null> => {
			setError(null);
			setPublishing(true);
			try {
				const result = await registryPublish({
					armored: input.publicArmored,
					...(input.encryptedPrivate ? { encryptedPrivate: input.encryptedPrivate } : {}),
					...(tsToken ? { turnstileToken: tsToken } : {}),
				});
				return {
					fingerprint: result.fingerprint,
					keyId: result.keyId,
					emails: result.emails,
					replaced: result.replaced,
					revocationToken: result.revocationToken,
					escrowed: Boolean(input.encryptedPrivate),
				};
			} catch (e) {
				if (
					e instanceof RegistryClientError &&
					e.status === 409 &&
					/already exists/i.test(e.message)
				) {
					// The 409 arrives AFTER requireTurnstile on the server, so the
					// single-use token was already consumed by this attempt — drop
					// it and remount the widget (which stays rendered beside the
					// replace panel) so the retry can mint a fresh one.
					setReplaceNeeded(true);
					setError(null);
					resetTs();
					return null;
				}
				setError(formatRegistryError(e, "Publishing failed"));
				resetTs();
				return null;
			} finally {
				setPublishing(false);
			}
		},
		[resetTs, tsToken],
	);

	/** Retry a 409'd publish with a signed possession proof. */
	const confirmReplace = useCallback(
		async (input: {
			publicArmored: string;
			encryptedPrivate?: string;
			signArmor: string;
			signPassphrase: string;
		}): Promise<PublishOutcome | null> => {
			setError(null);
			setReplacing(true);
			try {
				const openpgp = await import("openpgp");
				const parsed = await openpgp.readKey({ armoredKey: input.signArmor });
				const fingerprint = parsed.getFingerprint().toUpperCase();
				const challenge = await registryChallenge(fingerprint);
				const signature = await signChallenge(
					input.signArmor,
					input.signPassphrase,
					fingerprint,
					challenge.nonce,
				);
				const result = await registryPublish({
					armored: input.publicArmored,
					...(input.encryptedPrivate ? { encryptedPrivate: input.encryptedPrivate } : {}),
					...(tsToken ? { turnstileToken: tsToken } : {}),
					nonce: challenge.nonce,
					signature,
				});
				setReplaceNeeded(false);
				return {
					fingerprint: result.fingerprint,
					keyId: result.keyId,
					emails: result.emails,
					replaced: true,
					// A replace never mints a new token — the FIRST publish's
					// token remains the only way to revoke this fingerprint.
					revocationToken: result.revocationToken,
					escrowed: Boolean(input.encryptedPrivate),
				};
			} catch (e) {
				const msg = e instanceof Error ? e.message : String(e);
				if (/passphrase|checksum|decrypt/i.test(msg)) {
					setError("That passphrase doesn't unlock this key — possession proof requires it.");
				} else {
					setError(formatRegistryError(e, "Replace failed"));
				}
				resetTs();
				return null;
			} finally {
				setReplacing(false);
			}
		},
		[resetTs, tsToken],
	);

	return {
		publish,
		confirmReplace,
		publishing,
		replacing,
		replaceNeeded,
		setReplaceNeeded,
		error,
		tsToken,
		setTsToken,
		tsAttempt,
	};
}

/** Publish result card: what landed on the registry + the one-time token. */
export function PublishOutcomeCard({ outcome }: { outcome: PublishOutcome }) {
	return (
		<div className="space-y-3" data-testid="publish-outcome">
			<div className="flex flex-wrap items-center gap-2">
				<Badge
					variant="outline"
					className={outcome.escrowed ? "border-emerald-500/40 text-emerald-700" : ""}
				>
					{outcome.escrowed ? "public + encrypted backup" : "public only"}
				</Badge>
				{outcome.replaced && <Badge variant="outline">replaced existing record</Badge>}
			</div>
			<div className="grid gap-1 text-sm">
				<p>
					<span className="text-muted-foreground">Fingerprint: </span>
					<code className="font-mono text-xs">{formatFingerprint(outcome.fingerprint)}</code>
				</p>
				{outcome.emails.length > 0 && (
					<p>
						<span className="text-muted-foreground">Findable by: </span>
						{outcome.emails.join(", ")}
					</p>
				)}
			</div>
			{outcome.escrowLag && (
				<Alert className="border-amber-500/40 bg-amber-500/5">
					<TriangleAlert className="size-4 text-amber-600" />
					<AlertDescription className="text-xs">
						The previous encrypted backup was kept on the registry but predates this key version —
						restoring it would return the OLD key. Store a fresh escrow to fix the drift.
					</AlertDescription>
				</Alert>
			)}
			{outcome.revocationToken ? (
				<Alert className="border-amber-500/40 bg-amber-500/5">
					<TriangleAlert className="size-4 shrink-0 text-amber-600" />
					<AlertDescription className="space-y-2 text-xs">
						<p className="font-medium text-amber-800 dark:text-amber-300">
							Save this revocation token NOW — it is shown only once and is the only way to retract
							this key without publishing a replacement.
						</p>
						<div className="flex items-center gap-2">
							<code className="min-w-0 flex-1 break-all rounded bg-muted px-2 py-1 font-mono text-[11px]">
								{outcome.revocationToken}
							</code>
							<CopyButton text={outcome.revocationToken} label="Copy token" />
						</div>
					</AlertDescription>
				</Alert>
			) : (
				outcome.replaced && (
					<p className="text-xs text-muted-foreground">
						No new token was issued — the token from the first publish of this fingerprint still
						revokes it.
					</p>
				)
			)}
		</div>
	);
}

/** Compact possession-proof panel shown after a 409 "already exists". */
export function ReplacePanel({
	passphrase,
	onPassphraseChange,
	onConfirm,
	busy,
	error,
	locked = false,
}: {
	passphrase: string;
	onPassphraseChange: (v: string) => void;
	onConfirm: () => void;
	busy: boolean;
	error: string | null;
	/** Write-locked deployment: possession proof ends in a server 403. */
	locked?: boolean;
}) {
	return (
		<div
			className="space-y-2 rounded-lg border border-amber-500/40 bg-amber-500/5 p-3"
			data-testid="replace-panel"
		>
			<p className="text-xs font-medium">
				This fingerprint is already published. To replace it, sign a one-time challenge with the
				private key (proof of possession).
			</p>
			<div className="grid gap-1.5">
				<Label htmlFor="replace-pass">Key passphrase</Label>
				<Input
					id="replace-pass"
					type="password"
					value={passphrase}
					onChange={(e) => onPassphraseChange(e.target.value)}
					placeholder="Passphrase of the existing key"
					autoComplete="off"
				/>
			</div>
			{error && (
				<p role="alert" className="text-xs text-destructive">
					{error}
				</p>
			)}
			<Button type="button" size="sm" onClick={onConfirm} disabled={busy || locked || !passphrase}>
				{busy ? "Signing & replacing…" : "Sign challenge & replace"}
			</Button>
		</div>
	);
}
