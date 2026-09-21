"use client";

/**
 * Recipient picker with multi-source keyserver autocomplete + manual key paste.
 *
 * Logic, strings, and defaults are ported verbatim from the original app
 * (RecipientPicker + ManualRecipientAdd in PgpApp.tsx) — only the styling is
 * modernized (shadcn/ui + #0055dc accent, 150–200ms transitions, a11y).
 */
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Check } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import {
	lookupKeybaseUsersClient,
	searchAllKeyserversClient,
	type KeySearchResult,
} from "@/lib/pgp/keybase";
import { fetchKeysFromAllSources } from "@/lib/pgp/key-lookup";
import { registryLookup } from "@/lib/registry/client";
import { formatFingerprint, validateArmoredKey } from "@/lib/pgp/pgp";
import { getKeyExpiryStatus, humanizeRawAlgorithm } from "@/lib/pgp/key-details";
import { PROXIES, type Recipient } from "@/components/pgp/contracts";
import { STORAGE_KEYS } from "@/lib/constants";

const ACCENT_TEXT = "text-[#0055dc] dark:text-[#5e94ff]";

/** Loose email shape — enough to decide when a recipient query should ALSO
 *  hit the Encryptor Registry's exact-match email index. */
const EMAIL_SUGGEST_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

/**
 * Chip tooltip text (R10): label, then the key's algorithm when known
 * (humanized from the raw openpgp identifier; keybase adds store
 * already-humanized labels which pass through), then the formatted
 * fingerprint. A missing/empty algorithm simply omits that line.
 */
function chipTitle(
	label: string,
	algorithm: string | null | undefined,
	fingerprint: string,
): string {
	const lines = [label];
	if (algorithm) lines.push(`Algorithm: ${humanizeRawAlgorithm(algorithm)}`);
	lines.push(formatFingerprint(fingerprint));
	return lines.join("\n");
}

/* ------------------------- Recent recipients (additive) --------------------- */

/** Max number of recent recipients kept (most recent first). */
const MAX_RECENT_RECIPIENTS = 5;

/** Minimal serializable record of a recently used recipient, persisted to
 *  localStorage under STORAGE_KEYS.recentRecipients. */
interface RecentRecipient {
	label: string;
	fingerprint?: string;
	username?: string;
}

/** Load + sanitize the recent-recipients list (deduped by fingerprint||label,
 *  most recent first, capped) — guarded like every other storage access. */
function loadRecentRecipients(): RecentRecipient[] {
	try {
		const raw = localStorage.getItem(STORAGE_KEYS.recentRecipients);
		if (!raw) return [];
		const parsed: unknown = JSON.parse(raw);
		if (!Array.isArray(parsed)) return [];
		const cleaned: RecentRecipient[] = [];
		for (const item of parsed) {
			if (typeof item !== "object" || item === null) continue;
			const r = item as Partial<RecentRecipient>;
			if (typeof r.label !== "string" || r.label.trim() === "") continue;
			const entry: RecentRecipient = { label: r.label };
			if (typeof r.fingerprint === "string" && r.fingerprint) entry.fingerprint = r.fingerprint;
			if (typeof r.username === "string" && r.username) entry.username = r.username;
			cleaned.push(entry);
		}
		const seen = new Set<string>();
		const deduped: RecentRecipient[] = [];
		for (const r of cleaned) {
			const key = r.fingerprint || r.label;
			if (seen.has(key)) continue;
			seen.add(key);
			deduped.push(r);
		}
		return deduped.slice(0, MAX_RECENT_RECIPIENTS);
	} catch {
		return [];
	}
}

export function RecipientPicker({
	recipients,
	setRecipients,
	selfRecipient,
	includeSelf,
	onIncludeSelfChange,
}: {
	recipients: Recipient[];
	setRecipients: (updater: (prev: Recipient[]) => Recipient[]) => void;
	selfRecipient: Recipient | null;
	includeSelf: boolean;
	onIncludeSelfChange: (v: boolean) => void;
}) {
	const [input, setInput] = useState("");
	const [suggestions, setSuggestions] = useState<KeySearchResult[]>([]);
	const [showSuggestions, setShowSuggestions] = useState(false);
	const [busy, setBusy] = useState(false);
	const [adding, setAdding] = useState(false);
	const [error, setError] = useState<string | null>(null);
	// Additive: recently used recipients (most recent first, max 5).
	const [recentRecipients, setRecentRecipients] = useState<RecentRecipient[]>(loadRecentRecipients);
	const debounceRef = useRef<ReturnType<typeof setTimeout> | null>(null);
	const containerRef = useRef<HTMLDivElement>(null);

	// Persist recent recipients (try/catch-guarded like all storage use).
	useEffect(() => {
		try {
			localStorage.setItem(STORAGE_KEYS.recentRecipients, JSON.stringify(recentRecipients));
		} catch {
			// ignore
		}
	}, [recentRecipients]);

	// Self is never offered as a recent entry (the include-me checkbox already
	// covers encrypting to yourself); the whole section hides when nothing
	// visible remains.
	const visibleRecentRecipients = useMemo(
		() =>
			recentRecipients.filter(
				(r) => !(selfRecipient?.fingerprint && r.fingerprint === selfRecipient.fingerprint),
			),
		[recentRecipients, selfRecipient],
	);

	/** Record a successfully added recipient (deduped, most recent first). */
	const rememberRecentRecipient = useCallback((entry: RecentRecipient) => {
		setRecentRecipients((prev) => {
			const key = entry.fingerprint || entry.label;
			const rest = prev.filter((r) => (r.fingerprint || r.label) !== key);
			const stored: RecentRecipient = { label: entry.label };
			if (entry.fingerprint) stored.fingerprint = entry.fingerprint;
			if (entry.username) stored.username = entry.username;
			return [stored, ...rest].slice(0, MAX_RECENT_RECIPIENTS);
		});
	}, []);

	// Suggestions only ever correspond to the CURRENT query: cleared input
	// hides stale results instantly, even before the debounce timer fires.
	// # Mr. AI Acting on s183173's Behalf
	const visibleSuggestions = input.trim() === "" ? [] : suggestions;

	/** Query the Encryptor Registry for email / 40-hex / 16-hex queries and map
	 *  live keys to suggestion results (owner feedback: surface Encryptor keys
	 *  in the recipients box like the other key directories, so keys published
	 *  on Encryptor are discoverable). Public armor comes back with the
	 *  lookup, so the add path needs no second fetch; revoked keys are never
	 *  suggested. Non-matching query shapes resolve to []. */
	const registrySuggest = useCallback(async (q: string): Promise<KeySearchResult[]> => {
		const trimmed = q.trim();
		let keys: Awaited<ReturnType<typeof registryLookup>> = [];
		const flat = trimmed.replace(/\s+/g, "");
		if (EMAIL_SUGGEST_RE.test(trimmed)) {
			keys = await registryLookup({ email: trimmed.toLowerCase() });
		} else if (/^[0-9A-Fa-f]{40}$/.test(flat)) {
			keys = await registryLookup({ fingerprint: flat.toUpperCase() });
		} else if (/^(0x)?[0-9A-Fa-f]{16}$/.test(flat)) {
			keys = await registryLookup({ keyId: flat.replace(/^0x/i, "").toUpperCase() });
		} else {
			return [];
		}
		const live = keys.filter((k) => !k.revoked).slice(0, 5);
		return Promise.all(
			live.map(async (k) => {
				let label = k.fingerprint;
				try {
					const described = await validateArmoredKey(k.armored);
					const first = described.info?.userIDs?.[0];
					if (first?.name && first?.email) label = `${first.name} <${first.email}>`;
					else if (first?.email) label = first.email;
					else if (first?.name) label = first.name;
				} catch {
					// label falls back to the fingerprint
				}
				return {
					source: "encryptor" as const,
					label,
					fingerprint: k.fingerprint,
					keyID: k.fingerprint.slice(-16),
					armored: k.armored,
				};
			}),
		);
	}, []);

	// Debounced multi-source search
	useEffect(() => {
		if (debounceRef.current) clearTimeout(debounceRef.current);
		const q = input.trim();
		debounceRef.current = setTimeout(async () => {
			if (q.length < 1) {
				setSuggestions([]);
				return;
			}
			setBusy(true);
			try {
				// Encryptor Registry results first, then the classic keyservers —
				// each source fails independently so one outage never blanks the
				// dropdown.
				const [registryResults, keyserverResults] = await Promise.all([
					registrySuggest(q).catch(() => [] as KeySearchResult[]),
					searchAllKeyserversClient(q, PROXIES.searchAllProxy).catch(() => [] as KeySearchResult[]),
				]);
				// Dedupe by fingerprint (registry entries win ties).
				const seen = new Set<string>();
				const merged: KeySearchResult[] = [];
				for (const r of [...registryResults, ...keyserverResults]) {
					const key = r.fingerprint || `nb-${r.source}-${r.label}`;
					if (seen.has(key)) continue;
					seen.add(key);
					merged.push(r);
				}
				setSuggestions(merged);
				setShowSuggestions(true);
			} catch {
				setSuggestions([]);
			} finally {
				setBusy(false);
			}
		}, 250);
		return () => {
			if (debounceRef.current) clearTimeout(debounceRef.current);
		};
	}, [input]);

	// Click-outside to close suggestions
	useEffect(() => {
		function onClick(e: MouseEvent) {
			if (containerRef.current && !containerRef.current.contains(e.target as Node)) {
				setShowSuggestions(false);
			}
		}
		document.addEventListener("mousedown", onClick);
		return () => document.removeEventListener("mousedown", onClick);
	}, []);

	const addRecipient = useCallback(
		async (result: KeySearchResult) => {
			setError(null);
			setAdding(true);
			try {
				if (result.source === "encryptor") {
					// The registry lookup already returned the public armor.
					let armoredKey = result.armored;
					if (!armoredKey && result.fingerprint) {
						const again = await registryLookup({ fingerprint: result.fingerprint });
						armoredKey = again.find((k) => !k.revoked)?.armored;
					}
					if (!armoredKey || !result.fingerprint) {
						setError("Could not fetch that key from the Encryptor Registry.");
						return;
					}
					// Narrowed once (TS cannot keep narrowing an optional property
					// inside the setRecipients closure below).
					const fpr = result.fingerprint;
					if (recipients.some((p) => p.fingerprint === fpr)) {
						setInput("");
						setSuggestions([]);
						setShowSuggestions(false);
						return;
					}
					// Expiry + algorithm backfill — the same describe-once pattern as
					// the keyserver path (never blocks the add on failure).
					let expiresAt: number | null = null;
					let algorithm = "Unknown";
					try {
						const described = await validateArmoredKey(armoredKey);
						const exp = described.info?.expirationTime;
						if (exp instanceof Date && Number.isFinite(exp.getTime())) {
							expiresAt = exp.getTime();
						}
						if (described.info?.algorithm) {
							algorithm = described.info.algorithm;
						}
					} catch {
						expiresAt = null;
					}
					setRecipients((prev) => [
						...prev,
						{
							source: "local",
							label: result.label,
							armored: armoredKey,
							fingerprint: fpr,
							keyID: result.keyID ?? fpr.slice(-16),
							algorithm,
							expiresAt,
						},
					]);
					rememberRecentRecipient({ label: result.label, fingerprint: fpr });
				} else if (result.source === "keybase" && result.username) {
					// Fetch the full public key from Keybase
					const r = await lookupKeybaseUsersClient([result.username], PROXIES.keybaseProxy);
					if (r.found.length === 0) {
						setError(`No Keybase key found for @${result.username}.`);
						return;
					}
					const k = r.found[0];
					if (recipients.some((p) => p.fingerprint === k.fingerprint)) {
						setInput("");
						setSuggestions([]);
						setShowSuggestions(false);
						return;
					}
					setRecipients((prev) => [
						...prev,
						{
							source: "keybase",
							username: k.username,
							label: `@${k.username}`,
							armored: k.armored,
							fingerprint: k.fingerprint,
							keyID: k.keyID,
							algorithm: k.algorithm,
							expiresAt: k.expiresAt,
						},
					]);
					rememberRecentRecipient({
						label: `@${k.username}`,
						username: k.username,
						fingerprint: k.fingerprint,
					});
				} else if (result.fingerprint) {
					// Fetch the key from keys.openpgp.org or Ubuntu keyserver
					const fetched = await fetchKeysFromAllSources(
						[result.fingerprint],
						PROXIES.fetchkeyProxy,
						PROXIES.fetchkeyOpgProxy,
					);
					if (fetched.length === 0) {
						setError(`Could not fetch key ${result.keyID || result.fingerprint}.`);
						return;
					}
					const k = fetched[0];
					if (recipients.some((p) => p.fingerprint === k.fingerprint)) {
						setInput("");
						setSuggestions([]);
						setShowSuggestions(false);
						return;
					}
					const addedLabel = result.fullName
						? result.email
							? `${result.fullName} <${result.email}>`
							: result.fullName
						: result.label;
					// Expiry backfill (R8): the fetched armored key is already in hand,
					// so describe it to learn its expiration — the same data the
					// manual-paste path stores. The add must never fail or block
					// because of this step: isolated try/catch, and the fallback is
					// expiresAt: null (the previous value).
					// Algorithm backfill (R9): reuses the SAME describe result — stores
					// the raw openpgp algorithm value (info.algorithm), exactly what
					// the manual-paste path stores (v.info.algorithm). Falls back to
					// "Unknown" only when the describe failed or returned nothing.
					let expiresAt: number | null = null;
					let algorithm = "Unknown";
					try {
						const described = await validateArmoredKey(k.armored);
						const exp = described.info?.expirationTime;
						if (exp instanceof Date && Number.isFinite(exp.getTime())) {
							expiresAt = exp.getTime();
						}
						if (described.info?.algorithm) {
							algorithm = described.info.algorithm;
						}
					} catch {
						expiresAt = null;
					}
					setRecipients((prev) => [
						...prev,
						{
							source: "local",
							label: addedLabel,
							armored: k.armored,
							fingerprint: k.fingerprint,
							keyID: k.keyID,
							algorithm,
							expiresAt,
						},
					]);
					rememberRecentRecipient({ label: addedLabel, fingerprint: k.fingerprint });
				} else {
					setError("No key fingerprint available for this result.");
				}
				setInput("");
				setSuggestions([]);
				setShowSuggestions(false);
			} catch (e) {
				setError((e as Error).message);
			} finally {
				setAdding(false);
			}
		},
		[recipients, setRecipients, rememberRecentRecipient],
	);

	/** Add a recent recipient via the exact same path as picking a search
	 *  result (dedupe/validation inside addRecipient still applies). */
	const addRecentRecipient = useCallback(
		(r: RecentRecipient) => {
			const result: KeySearchResult = r.username
				? { source: "keybase", label: r.label, username: r.username, fingerprint: r.fingerprint }
				: { source: "openpgp.org", label: r.label, fingerprint: r.fingerprint };
			void addRecipient(result);
		},
		[addRecipient],
	);

	/** Manual-paste path — same commit as before, plus recent-recipients
	 *  persistence when the key is actually new. */
	const handleManualAdd = useCallback(
		(r: Recipient) => {
			if (!recipients.some((p) => p.fingerprint === r.fingerprint)) {
				rememberRecentRecipient({
					label: r.label,
					fingerprint: r.fingerprint || undefined,
					username: r.username,
				});
			}
			setRecipients((prev) =>
				prev.some((p) => p.fingerprint === r.fingerprint) ? prev : [...prev, r],
			);
		},
		[recipients, rememberRecentRecipient, setRecipients],
	);

	const handleKeyDown = useCallback(
		(e: React.KeyboardEvent<HTMLInputElement>) => {
			if (e.key === "Enter" && visibleSuggestions.length > 0) {
				e.preventDefault();
				addRecipient(visibleSuggestions[0]);
			} else if (e.key === "Escape") {
				setShowSuggestions(false);
			}
		},
		[visibleSuggestions, addRecipient],
	);

	const sourceColors: Record<string, string> = {
		encryptor: "bg-emerald-100 text-emerald-700 dark:bg-emerald-500/15 dark:text-emerald-400",
		keybase: `bg-[#0055dc]/10 ${ACCENT_TEXT}`,
		ubuntu: "bg-orange-100 text-orange-700 dark:bg-orange-500/15 dark:text-orange-400",
		"openpgp.org": "bg-green-100 text-green-700 dark:bg-green-500/15 dark:text-green-400",
		mailvelope: "bg-purple-100 text-purple-700 dark:bg-purple-500/15 dark:text-purple-400",
	};

	return (
		<div>
			<div className="mb-1.5 flex items-center gap-2">
				<span
					aria-hidden="true"
					className="h-3.5 w-[3px] shrink-0 rounded-full bg-[#0055dc] dark:bg-[#5e94ff]"
				/>
				<Label htmlFor="recipient-search">Recipients</Label>
			</div>

			{/* Include-me checkbox (only shown when a private key is configured) */}
			{selfRecipient && (
				<div className="-my-1 mb-2 flex min-h-11 items-start gap-2 py-1.5 text-xs text-foreground sm:min-h-0">
					<Checkbox
						id="include-self-recipient"
						checked={includeSelf}
						onCheckedChange={(v) => onIncludeSelfChange(v === true)}
						className="mt-0.5 size-3.5"
						aria-label="Include me as a recipient"
					/>
					<label
						htmlFor="include-self-recipient"
						className="cursor-pointer select-none leading-snug"
					>
						Include me as a recipient{" "}
						<span className="text-muted-foreground">
							(encrypts a copy to myself — stays {includeSelf ? "on" : "off"} for next time)
						</span>
					</label>
				</div>
			)}

			{/* Recipients list — show self chip first when included */}
			{(recipients.length > 0 || (includeSelf && selfRecipient)) && (
				<ul className="mb-2 flex flex-wrap gap-1.5">
					{includeSelf && selfRecipient && (
						<li
							className={`inline-flex items-center gap-1.5 rounded-full border border-[#0055dc]/30 bg-[#0055dc]/5 py-1 pl-2.5 pr-1.5 text-xs dark:border-[#5e94ff]/40 dark:bg-[#5e94ff]/10`}
							title={chipTitle(
								selfRecipient.label,
								selfRecipient.algorithm,
								selfRecipient.fingerprint,
							)}
						>
							<span className={`font-medium ${ACCENT_TEXT}`}>{selfRecipient.label}</span>
							<span className={`text-[10px] ${ACCENT_TEXT} opacity-70`}>auto</span>
						</li>
					)}
					{recipients.map((r) => {
						// Expiry awareness (R7): badges render ONLY when real expiration
						// data exists on the recipient (manual-paste and Keybase adds
						// populate expiresAt; keyserver-fetch adds legitimately carry
						// none — null/undefined never fabricates a badge). Recipient.
						// expiresAt is an epoch-ms number; key-details' getKeyExpiryStatus
						// accepts Date | ISO string, so convert once here.
						const expiry =
							typeof r.expiresAt === "number" ? getKeyExpiryStatus(new Date(r.expiresAt)) : null;
						return (
							<li
								key={r.fingerprint}
								className={`inline-flex items-center gap-1.5 rounded-full border py-1 pl-2.5 pr-1.5 text-xs shadow-xs transition-colors ${
									expiry?.status === "expired"
										? // R8: whole-chip red tint when the key is expired — the
											// badge alone was easy to miss in a busy chip row.
											"border-red-300/70 bg-red-50 dark:border-red-900/50 dark:bg-red-950/30"
										: "bg-background"
								}`}
								title={chipTitle(r.label, r.algorithm, r.fingerprint)}
							>
								<span className={`font-medium ${ACCENT_TEXT}`}>{r.label}</span>
								{expiry?.status === "expired" && (
									<span className="shrink-0 rounded-full bg-red-100 px-1.5 py-0.5 text-[10px] font-medium text-red-800 dark:bg-red-950/50 dark:text-red-300">
										Expired
									</span>
								)}
								{expiry?.status === "expiring" && (
									<span className="shrink-0 rounded-full bg-amber-100 px-1.5 py-0.5 text-[10px] font-medium text-amber-800 dark:bg-amber-950/50 dark:text-amber-300">
										{expiry.label}
									</span>
								)}
								<button
									type="button"
									onClick={() =>
										setRecipients((prev) => prev.filter((p) => p.fingerprint !== r.fingerprint))
									}
									className="ml-1 grid size-5 place-items-center rounded-full text-sm leading-none text-muted-foreground transition-colors hover:bg-destructive/10 hover:text-destructive"
									aria-label={`Remove ${r.label}`}
								>
									×
								</button>
							</li>
						);
					})}
				</ul>
			)}

			{/* Input + autocomplete dropdown */}
			<div className="relative" ref={containerRef}>
				<Input
					id="recipient-search"
					type="text"
					value={input}
					onChange={(e) => setInput(e.target.value)}
					onKeyDown={handleKeyDown}
					onFocus={() => visibleSuggestions.length > 0 && setShowSuggestions(true)}
					placeholder={
						recipients.length === 0
							? "Search by name, email, Keybase username, or fingerprint…"
							: "Add another recipient…"
					}
					className="min-h-11 pr-8 sm:min-h-0 sm:py-2"
					disabled={adding}
					aria-label="Search recipients by name, email, Keybase username, or fingerprint"
					autoComplete="off"
				/>
				{busy && (
					<div className="absolute right-2.5 top-1/2 -translate-y-1/2 animate-pulse text-[10px] text-muted-foreground">
						…
					</div>
				)}

				{/* Suggestions dropdown - BELOW the input */}
				{showSuggestions && visibleSuggestions.length > 0 && (
					<ul
						className="scrollbar-thin absolute inset-x-0 top-full z-20 mt-1 max-h-64 overflow-y-auto rounded-lg border bg-popover p-1 text-popover-foreground shadow-lg"
						role="listbox"
						aria-label="Recipient search results"
					>
						{visibleSuggestions.map((s, i) => {
							const alreadyAdded = recipients.some(
								(p) =>
									(s.username && p.username === s.username) ||
									(s.fingerprint && p.fingerprint === s.fingerprint),
							);
							return (
								<li
									key={`${s.source}-${s.label}-${i}`}
									role="option"
									aria-selected={false}
									className="mx-1"
								>
									<button
										type="button"
										onClick={() => addRecipient(s)}
										disabled={alreadyAdded}
										className={`flex w-full items-center gap-2.5 rounded-lg px-3 py-2.5 text-left text-sm transition-colors hover:bg-[#0055dc]/5 dark:hover:bg-[#5e94ff]/5 ${
											alreadyAdded
												? "cursor-not-allowed bg-[#0055dc]/5 opacity-50 dark:bg-[#5e94ff]/10"
												: ""
										}`}
									>
										{/* No avatar here — person photos/initials in the key
                        picker were noise (and a privacy leak of profile
                        pictures); results are identified by their labels. */}
										<div className="min-w-0 flex-1">
											<div className="truncate font-medium">{s.label}</div>
											{s.fullName && s.username && (
												<div className="truncate text-[11px] text-muted-foreground">
													{s.fullName}
												</div>
											)}
											{s.email && !s.username && (
												<div className="truncate text-[11px] text-muted-foreground">{s.email}</div>
											)}
										</div>
										<span
											className={`shrink-0 rounded-full px-1.5 py-0.5 text-[9px] font-medium ${
												sourceColors[s.source] || "bg-muted text-muted-foreground"
											}`}
										>
											{s.source}
										</span>
										{alreadyAdded && (
											<span className="flex shrink-0 items-center gap-1 text-[10px] text-muted-foreground">
												<Check aria-hidden="true" className="size-3.5 text-emerald-600" />
												added
											</span>
										)}
									</button>
								</li>
							);
						})}
					</ul>
				)}
			</div>

			{error && (
				<p role="alert" className="mt-1.5 text-[11px] text-red-600 dark:text-red-400">
					{error}
				</p>
			)}

			{/* Additive: recent recipients — shown only when the search box is empty
          and no dropdown results are on screen. Clicking routes through the
          same addRecipient path as picking a search result. Self is never
          offered as a recent entry. */}
			{input.trim() === "" &&
				!(showSuggestions && visibleSuggestions.length > 0) &&
				visibleRecentRecipients.length > 0 && (
					<div className="mt-2">
						<p className="flex items-center gap-2 text-[10px] text-muted-foreground">
							Recent:
							{/* Privacy affordance: wipe the recent-recipients list without
                  touching the saved key or recipients. */}
							<button
								type="button"
								onClick={() => setRecentRecipients([])}
								aria-label="Clear recent recipients"
								className="rounded text-[10px] text-muted-foreground underline-offset-2 transition-colors hover:text-destructive hover:underline focus-visible:outline-2 focus-visible:outline-offset-1 focus-visible:outline-[#0055dc] dark:focus-visible:outline-[#5e94ff]"
							>
								Clear
							</button>
						</p>
						<div className="mt-1 flex flex-wrap gap-1.5">
							{visibleRecentRecipients.map((r, i) => {
								const alreadyAdded = recipients.some(
									(p) =>
										(r.username !== undefined && p.username === r.username) ||
										(r.fingerprint !== undefined && p.fingerprint === r.fingerprint),
								);
								return (
									<button
										key={`${r.fingerprint || r.label}-${i}`}
										type="button"
										onClick={() => addRecentRecipient(r)}
										disabled={alreadyAdded}
										aria-label={`Add recent recipient ${r.label}`}
										className={`inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-[11px] text-muted-foreground transition-colors hover:bg-[#0055dc]/5 hover:text-foreground dark:hover:bg-[#5e94ff]/5 ${
											alreadyAdded ? "cursor-not-allowed opacity-50" : ""
										}`}
									>
										<span className="max-w-40 truncate">{r.label}</span>
									</button>
								);
							})}
						</div>
					</div>
				)}

			<p className="mt-1.5 text-[11px] text-muted-foreground">
				Searches Keybase, Ubuntu keyserver, and keys.openpgp.org.
			</p>

			<ManualRecipientAdd onAdd={handleManualAdd} />
		</div>
	);
}

/* ------------------------- Manual recipient (paste key) ---------------------- */

function ManualRecipientAdd({ onAdd }: { onAdd: (r: Recipient) => void }) {
	const [open, setOpen] = useState(false);
	const [armored, setArmored] = useState("");
	const [busy, setBusy] = useState(false);
	const [error, setError] = useState<string | null>(null);

	const handleAdd = useCallback(async () => {
		setError(null);
		if (!armored.trim()) {
			setError("Paste an armored public key.");
			return;
		}
		setBusy(true);
		try {
			const v = await validateArmoredKey(armored.trim());
			if (!v.ok || !v.info) {
				setError(v.error ?? "Invalid public key.");
				return;
			}
			if ("isPrivate" in v.info && v.info.isPrivate) {
				setError("That's a private key. Paste a public key for recipients.");
				return;
			}
			onAdd({
				source: "local",
				label: v.info.userIDs[0]?.name || v.info.userIDs[0]?.email || "Pasted key",
				armored: armored.trim(),
				fingerprint: v.info.fingerprint,
				keyID: v.info.keyID,
				algorithm: v.info.algorithm,
				expiresAt: v.info.expirationTime?.getTime() ?? null,
			});
			setArmored("");
			setOpen(false);
		} catch (e) {
			setError((e as Error).message);
		} finally {
			setBusy(false);
		}
	}, [armored, onAdd]);

	return (
		<div className="mt-2">
			<button
				type="button"
				onClick={() => setOpen((v) => !v)}
				className={`inline-flex min-h-11 items-center text-[11px] font-medium transition-colors hover:underline sm:min-h-0 ${ACCENT_TEXT}`}
				aria-expanded={open}
			>
				{open ? "Hide manual paste" : "+ Paste a public key manually"}
			</button>
			{open && (
				<div className="mt-1.5 space-y-2">
					<Textarea
						value={armored}
						onChange={(e) => setArmored(e.target.value)}
						placeholder={
							"-----BEGIN PGP PUBLIC KEY BLOCK-----\n...\n-----END PGP PUBLIC KEY BLOCK-----"
						}
						rows={5}
						className="field-sizing-fixed font-mono text-xs"
						aria-label="Paste an armored public key"
						spellCheck={false}
					/>
					{error && (
						<div
							role="alert"
							className="rounded-lg border border-destructive/30 bg-destructive/10 px-3 py-2 text-xs text-destructive"
						>
							{error}
						</div>
					)}
					<Button
						type="button"
						variant="outline"
						onClick={handleAdd}
						disabled={busy}
						className="h-11 text-sm sm:h-9"
					>
						{busy ? "Validating…" : "Add public key"}
					</Button>
				</div>
			)}
		</div>
	);
}
