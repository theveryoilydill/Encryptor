"use client";

/**
 * Keys tab — key pair generation, registry publishing, escrow restore.
 *
 * Three key sources: generate inside Encryptor, import from Keybase, or
 * bring a locally-managed key (GnuPG & co). Public keys publish to the
 * registry; a passphrase-encrypted private key MAY be escrowed opt-in for
 * cross-device restore. The passphrase and decrypted secrets never leave
 * the browser.
 *
 * # Mr. AI Acting on s183173's Behalf
 */
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
	AudioLines,
	Clock,
	ChevronDown,
	ChevronUp,
	Download,
	Eye,
	EyeOff,
	Fingerprint,
	Layers,
	Globe,
	HardDrive,
	KeyRound,
	Loader2,
	Lock,
	RefreshCw,
	Search,
	Send,
	ShieldAlert,
	ShieldCheck,
	Trash2,
	TriangleAlert,
	Upload,
	UserCheck,
	UserRound,
} from "lucide-react";

import { Alert, AlertDescription } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Checkbox } from "@/components/ui/checkbox";
import { PassphraseStrengthMeter } from "@/components/pgp/PassphraseStrengthMeter";
import { estimatePassphraseStrength } from "@/lib/pgp/passphrase-strength";
import {
	Dialog,
	DialogContent,
	DialogDescription,
	DialogFooter,
	DialogHeader,
	DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import {
	type MyKeyAudit,
	type MyKeyAuditOutcome,
	type MyRegistryKey,
	type ParsedBackup,
	type RegistryHealth,
	type RestoreReport,
	auditMyKeysOnRegistry,
	exportMyKeys,
	forgetMyKey,
	formatRegistryError,
	listMyKeys,
	mergeMyKeys,
	parseKeysBackup,
	previewRestore,
	registryFetchEscrow,
	registryHealth,
	registryLookup,
	registryPublish,
	registryRevokeByToken,
	registryAdminRevoke,
	rememberMyKey,
	updateMyKey,
} from "@/lib/registry/client";
import {
	TurnstileWidget,
	turnstileSiteKeyConfigured,
} from "@/components/pgp/registry/TurnstileWidget";
import { FingerprintQrButton } from "@/components/pgp/registry/FingerprintQr";
import { ScanQrButton } from "@/components/pgp/registry/QrScanner";
import {
	BackupDecryptFailure,
	decryptKeysBackup,
	encryptKeysBackup,
	isEncryptedBackupText,
} from "@/lib/registry/backup-crypto";
import { getKeySighting, noteKeySighted } from "@/lib/registry/watch";
import { toast } from "@/hooks/use-toast";
import { KEYBASE_USERNAME_RE } from "@/lib/constants";
import { lookupKeybaseUsersClient } from "@/lib/pgp/keybase";
import {
	describePublicKey,
	formatFingerprint,
	formatKeyDate,
	generateKeyPair,
	validateArmoredKey,
	type AnyKeyInfo,
} from "@/lib/pgp/pgp";
import { fingerprintToPgpWords } from "@/lib/pgp/pgp-words";
import type { PrivateKeyConfig, Recipient } from "@/components/pgp/contracts";
import { CopyButton } from "@/components/pgp/shared";

type KeySource = "encryptor" | "keybase" | "local";

const SOURCES: { id: KeySource; label: string; blurb: string; icon: typeof KeyRound }[] = [
	{
		id: "encryptor",
		label: "Encryptor",
		blurb: "Generate a new key pair right here",
		icon: KeyRound,
	},
	{
		id: "keybase",
		label: "Keybase",
		blurb: "Import the public key from a Keybase account",
		icon: Globe,
	},
	{
		id: "local",
		label: "Local",
		blurb: "Paste a key you manage with your own tools",
		icon: HardDrive,
	},
];

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function downloadText(filename: string, text: string): void {
	const blob = new Blob([text], { type: "text/plain" });
	const url = URL.createObjectURL(blob);
	const a = document.createElement("a");
	a.href = url;
	a.download = filename;
	a.click();
	URL.revokeObjectURL(url);
}

/** Display label + private-key flags for either key-info variant. */
function keyInfoSummary(info: AnyKeyInfo): {
	label: string;
	isPrivate: boolean;
	isDecrypted: boolean;
} {
	const first = info.userIDs[0];
	const label =
		first?.name || first?.email
			? `${first?.name ?? ""}${first?.email ? ` <${first.email}>` : ""}`
			: formatFingerprint(info.fingerprint);
	return {
		label,
		isPrivate: "isPrivate" in info && info.isPrivate === true,
		isDecrypted: "isDecrypted" in info && info.isDecrypted,
	};
}

/**
 * Derive the publishable public armor from a (possibly passphrase-encrypted)
 * private key. toPublic() strips the secret parameters without needing the
 * passphrase, so this never asks for one.
 */
async function publicFromPrivate(armoredPrivate: string): Promise<string> {
	const openpgp = await import("openpgp");
	const key = await openpgp.readKey({ armoredKey: armoredPrivate });
	if (!key.isPrivate()) return key.armor();
	return key.toPublic().armor();
}

/** Published-record summary shared by all three source panels. */
interface PublishOutcome {
	fingerprint: string;
	keyId: string;
	emails: string[];
	replaced: boolean;
	revocationToken?: string;
	escrowed: boolean;
	/** Human algorithm label for the local my-keys list badge. */
	algo?: string;
}

/** Status chip — probes /api/registry/health (which also self-migrates a
 *  fresh remote database) and surfaces schema + captcha state at a glance. */
function RegistryHealthChip() {
	const [health, setHealth] = useState<RegistryHealth | null>(null);
	const [checking, setChecking] = useState(false);

	const refresh = useCallback(async () => {
		setChecking(true);
		try {
			setHealth(await registryHealth());
		} catch {
			setHealth({ ok: false, db: false, error: "Health endpoint unreachable" });
		} finally {
			setChecking(false);
		}
	}, []);

	useEffect(() => {
		void refresh();
	}, [refresh]);

	const dot =
		health === null || checking
			? "bg-muted-foreground/50"
			: health.ok
				? "bg-emerald-500 animate-pulse"
				: "bg-red-500";
	const label =
		health === null || checking
			? "Checking registry…"
			: health.ok
				? `Registry connected (${health.schema?.applied.length ?? 0} migrations)`
				: `Registry issue: ${health.error ?? "unhealthy"}`;

	return (
		<div className="flex flex-wrap items-center gap-2">
			<span
				data-testid="registry-health-chip"
				title={
					health?.ok
						? `Schema ${health.schema?.applied.join(", ")} · Turnstile ${health.turnstile ?? "unknown"}`
						: (health?.error ?? "Probing the registry database…")
				}
				className="inline-flex items-center gap-1.5 rounded-full border border-border bg-card px-2.5 py-1 text-[11px] font-medium text-muted-foreground shadow-xs transition-colors"
				role="status"
				aria-live="polite"
			>
				<span aria-hidden="true" className={`size-2 rounded-full ${dot}`} />
				{label}
			</span>
			<Button
				type="button"
				variant="ghost"
				size="icon"
				aria-label="Re-check registry health"
				onClick={() => void refresh()}
				className="size-7 rounded-full text-muted-foreground hover:text-foreground"
			>
				<RefreshCw aria-hidden="true" className={`size-3.5 ${checking ? "animate-spin" : ""}`} />
			</Button>
		</div>
	);
}

export function KeysTab({
	onUseKey,
	onEncryptTo,
}: {
	onUseKey: (config: PrivateKeyConfig) => void;
	/** Optional: looked-up public keys can be sent straight to Encrypt. */
	onEncryptTo?: (recipient: Recipient) => void;
}) {
	const [source, setSource] = useState<KeySource>("encryptor");
	const [outcome, setOutcome] = useState<PublishOutcome | null>(null);
	const [myKeys, setMyKeys] = useState<MyRegistryKey[]>(() => listMyKeys());

	const refreshMyKeys = useCallback(() => setMyKeys(listMyKeys()), []);

	const handlePublished = useCallback(
		(result: PublishOutcome, label: string) => {
			setOutcome(result);
			rememberMyKey({
				fingerprint: result.fingerprint,
				keyId: result.keyId,
				emails: result.emails,
				label,
				publishedAt: Date.now(),
				revocationToken: result.revocationToken,
				escrowed: result.escrowed,
				algo: result.algo,
				updatedAt: Date.now(),
			});
			refreshMyKeys();
		},
		[refreshMyKeys],
	);

	return (
		<div className="space-y-6" aria-label="Key registry">
			<div className="space-y-1.5">
				<div className="flex flex-wrap items-center justify-between gap-2">
					<h2 className="text-base font-semibold">Key registry</h2>
					<RegistryHealthChip />
				</div>
				<p className="text-xs leading-relaxed text-muted-foreground">
					Publish public keys so anyone can find and verify them, and optionally back up your
					passphrase-encrypted private key for cross-device restore. Private keys are accepted only
					when fully encrypted — the server rejects anything else.
				</p>
			</div>

			<div role="radiogroup" aria-label="Key source" className="grid gap-3 sm:grid-cols-3">
				{SOURCES.map((s) => {
					const selected = source === s.id;
					const Icon = s.icon;
					return (
						<button
							key={s.id}
							type="button"
							role="radio"
							aria-checked={selected}
							onClick={() => setSource(s.id)}
							className={`rounded-xl border p-3.5 text-left transition-all focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[#0055dc] ${
								selected
									? "border-[#0055dc]/60 bg-[#0055dc]/5 shadow-sm dark:border-[#5e94ff]/60 dark:bg-[#5e94ff]/10"
									: "border-border bg-card hover:border-[#0055dc]/30 hover:bg-[#0055dc]/[0.03] dark:hover:border-[#5e94ff]/30 dark:hover:bg-[#5e94ff]/[0.05]"
							}`}
						>
							<span className="flex items-center gap-2">
								<Icon
									aria-hidden="true"
									className={`size-4 ${selected ? "text-[#0055dc] dark:text-[#5e94ff]" : "text-muted-foreground"}`}
								/>
								<span className="text-sm font-medium">{s.label}</span>
								{selected && (
									<Badge
										variant="outline"
										className="ml-auto border-[#0055dc]/40 px-1.5 py-0 text-[10px] text-[#0055dc] dark:border-[#5e94ff]/40 dark:text-[#5e94ff]"
									>
										Selected
									</Badge>
								)}
							</span>
							<span className="mt-1 block text-[11px] leading-snug text-muted-foreground">
								{s.blurb}
							</span>
						</button>
					);
				})}
			</div>

			{source === "encryptor" && (
				<EncryptorSource onPublished={handlePublished} onUseKey={onUseKey} />
			)}
			{source === "keybase" && <KeybaseSource onPublished={handlePublished} />}
			{source === "local" && <LocalSource onPublished={handlePublished} onUseKey={onUseKey} />}

			{outcome && <PublishOutcomeCard outcome={outcome} />}

			<RestoreEscrow onUseKey={onUseKey} />
			<RegistryLookup onEncryptTo={onEncryptTo} myKeys={myKeys} onMyKeysChanged={refreshMyKeys} />

			<MyKeysList keys={myKeys} onChanged={refreshMyKeys} />

			<AdminConsole />
		</div>
	);
}

/* ------------------------------ outcome card ----------------------------- */

function PublishOutcomeCard({ outcome }: { outcome: PublishOutcome }) {
	return (
		<Card className="border-emerald-300/60 bg-emerald-50/50 dark:border-emerald-900/50 dark:bg-emerald-950/20">
			<CardContent className="space-y-3 p-4">
				<div className="flex items-center gap-2">
					<ShieldCheck
						aria-hidden="true"
						className="size-4 text-emerald-600 dark:text-emerald-400"
					/>
					<span className="text-sm font-medium">
						{outcome.replaced ? "Key record replaced" : "Key published"}
					</span>
					<Badge variant="outline" className="ml-auto font-mono text-[10px]">
						{outcome.escrowed ? "public + encrypted private" : "public only"}
					</Badge>
				</div>
				<div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs">
					<span className="flex items-center gap-1.5 text-muted-foreground">
						<Fingerprint aria-hidden="true" className="size-3.5" />
						<span className="font-mono text-foreground">
							{formatFingerprint(outcome.fingerprint)}
						</span>
					</span>
					{outcome.emails.length > 0 && (
						<span className="text-muted-foreground">{outcome.emails.join(", ")}</span>
					)}
				</div>
				{outcome.revocationToken && (
					<Alert className="border-amber-300/70 bg-amber-50 dark:border-amber-900/50 dark:bg-amber-950/30">
						<TriangleAlert
							aria-hidden="true"
							className="size-4 text-amber-700 dark:text-amber-400"
						/>
						<AlertDescription className="space-y-2 text-xs text-amber-900 dark:text-amber-200">
							<p>
								Save this revocation token NOW — it is shown only once and is required to retract
								the key if you ever lose the private key.
							</p>
							<div className="flex items-center gap-2">
								<code className="min-w-0 flex-1 truncate rounded bg-background/70 px-2 py-1.5 font-mono text-[11px]">
									{outcome.revocationToken}
								</code>
								<CopyButton text={outcome.revocationToken} label="Copy token" />
							</div>
						</AlertDescription>
					</Alert>
				)}
			</CardContent>
		</Card>
	);
}

/* --------------------------- Encryptor (generate) ------------------------- */

function EncryptorSource({
	onPublished,
	onUseKey,
}: {
	onPublished: (outcome: PublishOutcome, label: string) => void;
	onUseKey: (config: PrivateKeyConfig) => void;
}) {
	const [name, setName] = useState("");
	const [email, setEmail] = useState("");
	const [passphrase, setPassphrase] = useState("");
	const [showPassphrase, setShowPassphrase] = useState(false);
	const [expiry, setExpiry] = useState("0");
	const [generating, setGenerating] = useState(false);
	const [generated, setGenerated] = useState<{
		label: string;
		publicKey: string;
		privateKey: string;
		info: AnyKeyInfo;
	} | null>(null);
	const [escrow, setEscrow] = useState(false);
	const [publishing, setPublishing] = useState(false);
	const [error, setError] = useState<string | null>(null);
	const [tsToken, setTsToken] = useState<string | null>(null);
	const [tsAttempt, setTsAttempt] = useState(0);

	const passphaseTooWeak = passphrase.length > 0 && passphrase.length < 8;
	const canGenerate =
		name.trim().length > 0 && EMAIL_RE.test(email) && passphrase.length >= 8 && !generating;

	const handleGenerate = useCallback(async () => {
		setError(null);
		setGenerating(true);
		setGenerated(null);
		try {
			const seconds = Number(expiry) * 365 * 24 * 3600;
			const pair = await generateKeyPair({
				name: name.trim(),
				email: email.trim().toLowerCase(),
				passphrase,
				type: "ecc",
				expirationSeconds: seconds > 0 ? seconds : undefined,
			});
			setGenerated({
				label: `${name.trim()} <${email.trim().toLowerCase()}>`,
				publicKey: pair.publicKey,
				privateKey: pair.privateKey,
				info: pair.info,
			});
		} catch (e) {
			setError((e as Error).message);
		} finally {
			setGenerating(false);
		}
	}, [email, expiry, name, passphrase]);

	const handlePublish = useCallback(async () => {
		if (!generated) return;
		setError(null);
		setPublishing(true);
		try {
			const result = await registryPublish({
				turnstileToken: tsToken ?? undefined,
				armored: generated.publicKey,
				encryptedPrivate: escrow ? generated.privateKey : undefined,
			});
			onPublished(
				{
					fingerprint: result.fingerprint,
					keyId: result.keyId,
					emails: result.emails,
					replaced: result.replaced,
					revocationToken: result.revocationToken,
					escrowed: escrow,
					algo: prettyAlgorithm(generated.info.algorithm, generated.info.curve ?? null),
				},
				generated.label,
			);
			onUseKey({
				source: "generated",
				label: generated.label,
				encryptedArmored: generated.privateKey,
				info: generated.info,
			});
		} catch (e) {
			setError(formatRegistryError(e, (e as Error).message));
			// Turnstile tokens are single-use — mint a fresh challenge.
			setTsToken(null);
			setTsAttempt((a) => a + 1);
		} finally {
			setPublishing(false);
		}
	}, [escrow, generated, onPublished, onUseKey, tsToken]);

	return (
		<Card>
			<CardContent className="space-y-4 p-4">
				<div className="grid gap-3 sm:grid-cols-2">
					<div className="space-y-1.5">
						<Label htmlFor="keys-name">Name</Label>
						<Input
							id="keys-name"
							value={name}
							onChange={(e) => setName(e.target.value)}
							placeholder="Alice Example"
							autoComplete="off"
						/>
					</div>
					<div className="space-y-1.5">
						<Label htmlFor="keys-email">Email</Label>
						<Input
							id="keys-email"
							type="email"
							value={email}
							onChange={(e) => setEmail(e.target.value)}
							placeholder="alice@example.com"
							autoComplete="off"
						/>
					</div>
					<div className="space-y-1.5">
						<Label htmlFor="keys-pass">Passphrase</Label>
						<div className="flex gap-1.5">
							<Input
								id="keys-pass"
								type={showPassphrase ? "text" : "password"}
								value={passphrase}
								onChange={(e) => setPassphrase(e.target.value)}
								placeholder="Encrypts the private key"
								autoComplete="new-password"
								className="min-w-0 flex-1"
							/>
							<Button
								type="button"
								variant="outline"
								size="icon"
								aria-label={showPassphrase ? "Hide passphrase" : "Show passphrase"}
								onClick={() => setShowPassphrase((v) => !v)}
								className="size-11 shrink-0 sm:size-9"
							>
								{showPassphrase ? (
									<EyeOff aria-hidden="true" className="size-4" />
								) : (
									<Eye aria-hidden="true" className="size-4" />
								)}
							</Button>
						</div>
						<PassphraseStrengthMeter passphrase={passphrase} idPrefix="keys-pass" />
						{passphaseTooWeak && (
							<p className="text-[11px] text-amber-600 dark:text-amber-400">
								Use at least 8 characters — this passphrase protects your escrowed key.
							</p>
						)}
					</div>
					<div className="space-y-1.5">
						<Label htmlFor="keys-expiry">Expiration</Label>
						<select
							id="keys-expiry"
							value={expiry}
							onChange={(e) => setExpiry(e.target.value)}
							className="h-11 w-full rounded-md border border-input bg-background px-3 text-sm sm:h-9"
						>
							<option value="0">Never expires</option>
							<option value="1">In 1 year</option>
							<option value="2">In 2 years</option>
							<option value="5">In 5 years</option>
						</select>
					</div>
				</div>

				<div className="flex flex-wrap items-center gap-2">
					<Button
						type="button"
						onClick={handleGenerate}
						disabled={!canGenerate}
						className="h-11 gap-1.5 sm:h-9"
					>
						{generating ? (
							<Loader2 aria-hidden="true" className="size-4 animate-spin" />
						) : (
							<KeyRound aria-hidden="true" className="size-4" />
						)}
						{generating ? "Generating…" : "Generate key pair"}
					</Button>
				</div>

				{generated && (
					<div className="animate-scale-in space-y-3 rounded-lg border border-[#0055dc]/25 bg-muted/30 p-3 shadow-sm dark:border-[#5e94ff]/20">
						<div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs">
							<span className="font-medium">{generated.label}</span>
							<span className="font-mono text-muted-foreground">
								{formatFingerprint(generated.info.fingerprint)}
							</span>
							<Badge variant="outline" className="font-mono text-[10px]">
								{generated.info.algorithm}
							</Badge>
						</div>
						<label className="flex items-start gap-2 text-xs leading-snug">
							<Checkbox
								checked={escrow}
								onCheckedChange={(v) => setEscrow(v === true)}
								className="mt-0.5"
								aria-label="Back up the encrypted private key in the registry"
							/>
							<span>
								<span className="font-medium">Back up encrypted private key in the registry.</span>{" "}
								<span className="text-muted-foreground">
									Stores the passphrase-encrypted private key so you can restore it on any device.
									The server never accepts unencrypted keys; your passphrase is the only way to
									decrypt it.
								</span>
							</span>
						</label>
						<TurnstileWidget key={tsAttempt} id="turnstile-encryptor" onToken={setTsToken} />
						<div className="flex flex-wrap items-center gap-2">
							<Button
								type="button"
								onClick={handlePublish}
								disabled={publishing || (turnstileSiteKeyConfigured() && !tsToken)}
								className="h-11 gap-1.5 bg-[#0055dc] text-white hover:bg-[#0047b8] sm:h-9"
							>
								{publishing ? (
									<Loader2 aria-hidden="true" className="size-4 animate-spin" />
								) : (
									<Globe aria-hidden="true" className="size-4" />
								)}
								{publishing ? "Publishing…" : "Publish to registry"}
							</Button>
							<CopyButton text={generated.publicKey} label="Copy public" />
							<CopyButton text={generated.privateKey} label="Copy private" />
							<Button
								type="button"
								variant="outline"
								size="sm"
								className="h-11 gap-1.5 px-3 text-xs sm:h-8"
								onClick={() => downloadText("public-key.asc", generated.publicKey)}
							>
								<Download aria-hidden="true" className="size-3.5" />
								public .asc
							</Button>
							<Button
								type="button"
								variant="outline"
								size="sm"
								className="h-11 gap-1.5 px-3 text-xs sm:h-8"
								onClick={() => downloadText("private-key.asc", generated.privateKey)}
							>
								<Download aria-hidden="true" className="size-3.5" />
								private .asc
							</Button>
						</div>
					</div>
				)}

				{error && (
					<Alert variant="destructive">
						<TriangleAlert aria-hidden="true" className="size-4" />
						<AlertDescription className="text-xs">{error}</AlertDescription>
					</Alert>
				)}
			</CardContent>
		</Card>
	);
}

/* ------------------------------- Keybase --------------------------------- */

function KeybaseSource({
	onPublished,
}: {
	onPublished: (outcome: PublishOutcome, label: string) => void;
}) {
	const [username, setUsername] = useState("");
	const [looking, setLooking] = useState(false);
	const [found, setFound] = useState<{
		username: string;
		armored: string;
		fingerprint: string;
		algorithm: string;
	} | null>(null);
	const [publishing, setPublishing] = useState(false);
	const [error, setError] = useState<string | null>(null);
	const [tsToken, setTsToken] = useState<string | null>(null);
	const [tsAttempt, setTsAttempt] = useState(0);

	const handleLookup = useCallback(async () => {
		const clean = username.trim().toLowerCase();
		if (!KEYBASE_USERNAME_RE.test(clean)) {
			setError("Keybase usernames are 2–15 chars: a-z, 0-9, _");
			return;
		}
		setError(null);
		setFound(null);
		setLooking(true);
		try {
			const result = await lookupKeybaseUsersClient([clean]);
			const hit = result.found[0];
			if (!hit) {
				setError(result.errors[0]?.error ?? `No public key found for keybase.io/${clean}`);
				return;
			}
			setFound({
				username: hit.username,
				armored: hit.armored,
				fingerprint: hit.fingerprint,
				algorithm: hit.algorithm,
			});
		} catch (e) {
			setError((e as Error).message);
		} finally {
			setLooking(false);
		}
	}, [username]);

	const handlePublish = useCallback(async () => {
		if (!found) return;
		setError(null);
		setPublishing(true);
		try {
			const result = await registryPublish({
				armored: found.armored,
				turnstileToken: tsToken ?? undefined,
			});
			onPublished(
				{
					fingerprint: result.fingerprint,
					keyId: result.keyId,
					emails: result.emails,
					replaced: result.replaced,
					revocationToken: result.revocationToken,
					escrowed: false,
					algo: found.algorithm,
				},
				`keybase.io/${found.username}`,
			);
		} catch (e) {
			setError(formatRegistryError(e, (e as Error).message));
			// Turnstile tokens are single-use — mint a fresh challenge.
			setTsToken(null);
			setTsAttempt((a) => a + 1);
		} finally {
			setPublishing(false);
		}
	}, [found, onPublished, tsToken]);

	return (
		<Card>
			<CardContent className="space-y-4 p-4">
				<div className="space-y-1.5">
					<Label htmlFor="keys-keybase">Keybase username</Label>
					<div className="flex gap-1.5">
						<div className="relative min-w-0 flex-1">
							<span className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-xs text-muted-foreground">
								keybase.io/
							</span>
							<Input
								id="keys-keybase"
								value={username}
								onChange={(e) => setUsername(e.target.value)}
								placeholder="username"
								autoComplete="off"
								className="pl-[76px]"
								onKeyDown={(e) => {
									if (e.key === "Enter") handleLookup();
								}}
							/>
						</div>
						<Button
							type="button"
							variant="outline"
							onClick={handleLookup}
							disabled={looking}
							className="h-11 shrink-0 gap-1.5 sm:h-9"
						>
							{looking ? (
								<Loader2 aria-hidden="true" className="size-4 animate-spin" />
							) : (
								<Search aria-hidden="true" className="size-4" />
							)}
							Look up
						</Button>
					</div>
				</div>

				{found && (
					<div className="space-y-3 rounded-lg border bg-muted/30 p-3">
						<div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs">
							<span className="font-medium">keybase.io/{found.username}</span>
							<span className="font-mono text-muted-foreground">
								{formatFingerprint(found.fingerprint)}
							</span>
							<Badge variant="outline" className="font-mono text-[10px]">
								{found.algorithm}
							</Badge>
						</div>
						<p className="text-[11px] leading-snug text-muted-foreground">
							Publishing the PUBLIC key only — Keybase keys are fetched through the Keybase service
							and never include private material.
						</p>
						<TurnstileWidget key={tsAttempt} id="turnstile-keybase" onToken={setTsToken} />
						<Button
							type="button"
							onClick={handlePublish}
							disabled={publishing || (turnstileSiteKeyConfigured() && !tsToken)}
							className="h-11 gap-1.5 bg-[#0055dc] text-white hover:bg-[#0047b8] sm:h-9"
						>
							{publishing ? (
								<Loader2 aria-hidden="true" className="size-4 animate-spin" />
							) : (
								<Globe aria-hidden="true" className="size-4" />
							)}
							{publishing ? "Publishing…" : "Publish to registry"}
						</Button>
					</div>
				)}

				{error && (
					<Alert variant="destructive">
						<TriangleAlert aria-hidden="true" className="size-4" />
						<AlertDescription className="text-xs">{error}</AlertDescription>
					</Alert>
				)}
			</CardContent>
		</Card>
	);
}

/* --------------------------------- Local ---------------------------------- */

function LocalSource({
	onPublished,
	onUseKey,
}: {
	onPublished: (outcome: PublishOutcome, label: string) => void;
	onUseKey: (config: PrivateKeyConfig) => void;
}) {
	const [armored, setArmored] = useState("");
	const [authPass, setAuthPass] = useState("");
	const [plainPrivate, setPlainPrivate] = useState<string | null>(null);
	const [checking, setChecking] = useState(false);
	const [publishing, setPublishing] = useState(false);
	const [escrow, setEscrow] = useState(false);
	const [parsed, setParsed] = useState<{
		info: AnyKeyInfo;
		label: string;
		isPrivate: boolean;
		isDecrypted: boolean;
	} | null>(null);
	const [error, setError] = useState<string | null>(null);
	const [tsToken, setTsToken] = useState<string | null>(null);
	const [tsAttempt, setTsAttempt] = useState(0);

	const handleParse = useCallback(async () => {
		setError(null);
		setParsed(null);
		setPlainPrivate(null);
		setChecking(true);
		try {
			const key = armored.trim();
			if (!key) return;
			const result = await validateArmoredKey(key);
			if (!result.ok || !result.info) {
				setError(result.error ?? "Not a parseable OpenPGP key");
				return;
			}
			const summary = keyInfoSummary(result.info);
			if (summary.isPrivate && summary.isDecrypted) setPlainPrivate(key);
			setParsed({ info: result.info, ...summary });
		} catch (e) {
			setError((e as Error).message);
		} finally {
			setChecking(false);
		}
	}, [armored]);

	const handleEncryptPrivate = useCallback(async () => {
		if (!plainPrivate) return;
		if (authPass.length < 8) {
			setError("Choose a passphrase of at least 8 characters to encrypt the key.");
			return;
		}
		setError(null);
		setChecking(true);
		try {
			const openpgp = await import("openpgp");
			const key = await openpgp.readKey({ armoredKey: plainPrivate });
			const encrypted = await openpgp.encryptKey({
				privateKey: key as OpenPGP.PrivateKey,
				passphrase: authPass,
			});
			const reArmored = encrypted.armor();
			setArmored(reArmored);
			setPlainPrivate(null);
			const result = await validateArmoredKey(reArmored);
			if (result.ok && result.info) {
				setParsed({ info: result.info, ...keyInfoSummary(result.info) });
			}
		} catch (e) {
			setError((e as Error).message);
		} finally {
			setChecking(false);
		}
	}, [authPass, plainPrivate]);

	const handlePublish = useCallback(async () => {
		if (!parsed) return;
		setError(null);
		setPublishing(true);
		try {
			let publicArmored = armored.trim();
			let escrowBlob: string | undefined;
			if (parsed.isPrivate) {
				publicArmored = await publicFromPrivate(armored.trim());
				escrowBlob = escrow ? armored.trim() : undefined;
			}
			const result = await registryPublish({
				armored: publicArmored,
				turnstileToken: tsToken ?? undefined,
				encryptedPrivate: escrowBlob,
			});
			onPublished(
				{
					fingerprint: result.fingerprint,
					keyId: result.keyId,
					emails: result.emails,
					replaced: result.replaced,
					revocationToken: result.revocationToken,
					escrowed: Boolean(escrowBlob),
					algo: parsed.info
						? prettyAlgorithm(parsed.info.algorithm, parsed.info.curve ?? null)
						: undefined,
				},
				parsed.label,
			);
			if (parsed.isPrivate) {
				onUseKey({
					source: "manual",
					label: parsed.label,
					encryptedArmored: armored.trim(),
					info: parsed.info,
				});
			}
		} catch (e) {
			setError(formatRegistryError(e, (e as Error).message));
			// Turnstile tokens are single-use — mint a fresh challenge.
			setTsToken(null);
			setTsAttempt((a) => a + 1);
		} finally {
			setPublishing(false);
		}
	}, [armored, escrow, onPublished, onUseKey, parsed, tsToken]);

	const canPublish =
		parsed &&
		(!parsed.isPrivate || parsed.isDecrypted === false) &&
		(!escrow || parsed.isPrivate) &&
		!publishing &&
		(!turnstileSiteKeyConfigured() || !!tsToken);

	return (
		<Card>
			<CardContent className="space-y-4 p-4">
				<div className="space-y-1.5">
					<Label htmlFor="keys-local-armored">Armored key (public or private)</Label>
					<Textarea
						id="keys-local-armored"
						value={armored}
						onChange={(e) => setArmored(e.target.value)}
						placeholder={
							"-----BEGIN PGP PUBLIC KEY BLOCK-----\n…\n-----END PGP PUBLIC KEY BLOCK-----"
						}
						rows={6}
						className="max-h-64 overflow-y-auto font-mono text-[11px]"
					/>
				</div>

				{plainPrivate && (
					<Alert className="border-amber-300/70 bg-amber-50 dark:border-amber-900/50 dark:bg-amber-950/30">
						<TriangleAlert
							aria-hidden="true"
							className="size-4 text-amber-700 dark:text-amber-400"
						/>
						<AlertDescription className="space-y-2 text-xs text-amber-900 dark:text-amber-200">
							<p>
								This private key is NOT passphrase-encrypted. Choose a passphrase — Encryptor will
								encrypt it locally before anything leaves the browser.
							</p>
							<div className="flex flex-wrap items-center gap-2">
								<Input
									type="password"
									value={authPass}
									onChange={(e) => setAuthPass(e.target.value)}
									placeholder="New passphrase"
									autoComplete="new-password"
									className="h-11 min-w-0 flex-1 sm:h-9"
								/>
								<Button
									type="button"
									variant="outline"
									size="sm"
									onClick={handleEncryptPrivate}
									disabled={checking}
									className="h-11 gap-1.5 px-3 text-xs sm:h-8"
								>
									{checking ? (
										<Loader2 aria-hidden="true" className="size-3.5 animate-spin" />
									) : (
										<ShieldCheck aria-hidden="true" className="size-3.5" />
									)}
									Encrypt locally
								</Button>
							</div>
							<PassphraseStrengthMeter passphrase={authPass} idPrefix="keys-local-pass" />
						</AlertDescription>
					</Alert>
				)}

				<div className="flex flex-wrap items-center gap-2">
					<Button
						type="button"
						variant="outline"
						onClick={handleParse}
						disabled={checking || armored.trim().length === 0}
						className="h-11 gap-1.5 sm:h-9"
					>
						{checking ? (
							<Loader2 aria-hidden="true" className="size-4 animate-spin" />
						) : (
							<Search aria-hidden="true" className="size-4" />
						)}
						Validate
					</Button>
				</div>

				{parsed && (
					<div className="space-y-3 rounded-lg border bg-muted/30 p-3">
						<div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs">
							<Badge variant="outline" className="font-mono text-[10px]">
								{parsed.isPrivate ? "private key" : "public key"}
							</Badge>
							<span className="font-mono text-muted-foreground">
								{formatFingerprint(parsed.info.fingerprint)}
							</span>
							{parsed.info.algorithm && (
								<Badge variant="outline" className="font-mono text-[10px]">
									{parsed.info.algorithm}
								</Badge>
							)}
						</div>
						{parsed.isPrivate && (
							<label className="flex items-start gap-2 text-xs leading-snug">
								<Checkbox
									checked={escrow}
									onCheckedChange={(v) => setEscrow(v === true)}
									className="mt-0.5"
									aria-label="Also store the encrypted private key"
								/>
								<span>
									<span className="font-medium">Also store the encrypted private key.</span>{" "}
									<span className="text-muted-foreground">
										Requires a passphrase-protected key; enables restore on any device with your
										passphrase.
									</span>
								</span>
							</label>
						)}
						<TurnstileWidget key={tsAttempt} id="turnstile-local" onToken={setTsToken} />
						<Button
							type="button"
							onClick={handlePublish}
							disabled={!canPublish}
							className="h-11 gap-1.5 bg-[#0055dc] text-white hover:bg-[#0047b8] sm:h-9"
						>
							{publishing ? (
								<Loader2 aria-hidden="true" className="size-4 animate-spin" />
							) : (
								<Globe aria-hidden="true" className="size-4" />
							)}
							{publishing ? "Publishing…" : "Publish to registry"}
						</Button>
					</div>
				)}

				{error && (
					<Alert variant="destructive">
						<TriangleAlert aria-hidden="true" className="size-4" />
						<AlertDescription className="text-xs">{error}</AlertDescription>
					</Alert>
				)}
			</CardContent>
		</Card>
	);
}

/* ------------------------------- lookup ---------------------------------- */

function detectQueryKind(raw: string): "fingerprint" | "keyId" | "email" | null {
	const clean = raw.trim().replace(/\s+/g, "").replace(/^0x/i, "").toUpperCase();
	if (/^[0-9A-F]{40}$/.test(clean)) return "fingerprint";
	if (/^[0-9A-F]{16}$/.test(clean)) return "keyId";
	const email = raw.trim().toLowerCase();
	if (EMAIL_RE.test(email)) return "email";
	return null;
}

/** Human names for openpgp algorithm ids (see openpgp.enums.publicKey). */
function prettyAlgorithm(algorithm: string, curve: string | null): string {
	const algoNames: Record<string, string> = {
		rsaEncryptSign: "RSA",
		rsaEncrypt: "RSA",
		rsaSign: "RSA",
		eddsaLegacy: "EdDSA",
		ecdsa: "ECDSA",
		ecdh: "ECDH",
		elgamal: "ElGamal",
		dsa: "DSA",
		ed25519: "Ed25519",
		x25519: "X25519",
		x448: "X448",
	};
	const curveNames: Record<string, string> = {
		ed25519Legacy: "Ed25519",
		ed25519: "Ed25519",
		curve25519Legacy: "Curve25519",
		curve25519: "Curve25519",
		nistP256: "NIST P-256",
		nistP384: "NIST P-384",
		nistP521: "NIST P-521",
		brainpoolP256r1: "Brainpool P-256",
		brainpoolP384r1: "Brainpool P-384",
		brainpoolP512r1: "Brainpool P-512",
		secp256k1: "secp256k1",
	};
	const a = algoNames[algorithm] ?? algorithm;
	const c = curve ? (curveNames[curve] ?? curve) : null;
	// "EdDSA · Ed25519" is redundant — the curve alone is the conventional name.
	if (c && a === "EdDSA" && c === "Ed25519") return c;
	return c ? `${a} \u00b7 ${c}` : a;
}

interface LookupKeyMeta {
	algoLabel: string;
	bits: number | null;
	created: Date | null;
	expires: Date | null;
	identities: number;
	subkeys: number;
}

/** Best-effort client-side key parse; one malformed row never blocks results. */
async function describeKeyMeta(armored: string): Promise<LookupKeyMeta | null> {
	try {
		const info = await describePublicKey(armored);
		const subkeys = (info as { subkeyDetails?: unknown[] }).subkeyDetails?.length ?? 0;
		return {
			algoLabel: prettyAlgorithm(info.algorithm, info.curve ?? null),
			bits: info.bitSize ?? null,
			created:
				info.creationTime instanceof Date && !Number.isNaN(info.creationTime.getTime())
					? info.creationTime
					: null,
			expires: info.expirationTime,
			identities: info.userIDs.length,
			subkeys,
		};
	} catch {
		return null;
	}
}

const EXPIRY_SOON_MS = 30 * 24 * 60 * 60 * 1000;

function KeyMetaBadges({ meta }: { meta: LookupKeyMeta }) {
	const now = Date.now();
	const expiresSoon = meta.expires != null && meta.expires.getTime() - now < EXPIRY_SOON_MS;
	const expired = meta.expires != null && meta.expires.getTime() <= now;
	return (
		<div className="flex flex-wrap items-center gap-1.5">
			<Badge
				variant="outline"
				className="border-violet-500/40 bg-violet-500/5 text-[10px] font-medium text-violet-700 dark:border-violet-400/30 dark:text-violet-300"
				title="Primary key algorithm"
			>
				<KeyRound aria-hidden="true" className="mr-1 inline size-3" />
				{meta.algoLabel}
				{meta.bits ? ` \u00b7 ${meta.bits}-bit` : ""}
			</Badge>
			{expired ? (
				<Badge
					variant="destructive"
					className="text-[10px]"
					title="This key expired — treat it as untrusted"
				>
					<Clock aria-hidden="true" className="mr-1 inline size-3" />
					expired {meta.expires ? formatKeyDate(meta.expires) : ""}
				</Badge>
			) : expiresSoon ? (
				<Badge
					variant="outline"
					className="border-amber-500/50 bg-amber-500/5 text-[10px] text-amber-700 dark:border-amber-400/30 dark:text-amber-300"
					title="This key expires within 30 days"
				>
					<Clock aria-hidden="true" className="mr-1 inline size-3" />
					expires {meta.expires ? formatKeyDate(meta.expires) : ""}
				</Badge>
			) : meta.expires ? (
				<Badge variant="outline" className="text-[10px] text-muted-foreground">
					<Clock aria-hidden="true" className="mr-1 inline size-3" />
					expires {meta.expires ? formatKeyDate(meta.expires) : ""}
				</Badge>
			) : null}
			<Badge
				variant="outline"
				className="text-[10px] text-muted-foreground"
				title="User identities bound to this key"
			>
				<UserRound aria-hidden="true" className="mr-1 inline size-3" />
				{meta.identities} identit{meta.identities === 1 ? "y" : "ies"}
			</Badge>
			<Badge
				variant="outline"
				className="text-[10px] text-muted-foreground"
				title="Encryption subkeys"
			>
				<Layers aria-hidden="true" className="mr-1 inline size-3" />
				{meta.subkeys} subke{meta.subkeys === 1 ? "y" : "ys"}
			</Badge>
		</div>
	);
}

function PgpWordsPanel({ fingerprint }: { fingerprint: string }) {
	let words: string[] | null = null;
	try {
		words = fingerprintToPgpWords(fingerprint);
	} catch {
		return null;
	}
	const spoken = words; // canonical case comes straight from the tables
	return (
		<details className="group/words mt-2">
			<summary className="flex cursor-pointer list-none items-center gap-1.5 select-none text-[11px] text-[#0055dc] hover:underline dark:text-[#5e94ff]">
				<AudioLines
					aria-hidden="true"
					className="size-3.5 transition-transform group-open/words:rotate-90"
				/>
				Verify aloud (PGP words)
			</summary>
			<div className="mt-1.5 space-y-1.5 rounded-lg border border-dashed bg-gradient-to-br from-background to-muted/40 p-2.5">
				<p className="text-[10px] leading-snug text-muted-foreground">
					Read these 20 words to the key owner over a call — the alternating even/odd lists expose
					transposed, duplicated, or skipped words, defeating MITM key swaps.
				</p>
				<div className="grid grid-cols-2 gap-1 sm:grid-cols-4" data-testid="pgp-words-grid">
					{spoken.map((w, i) => (
						<span
							key={`${w}-${i}`}
							data-testid="pgp-word"
							data-word-index={i + 1}
							className={
								i % 2 === 0
									? "rounded border border-violet-500/25 bg-violet-500/5 px-1.5 py-0.5 text-center font-mono text-[10px] text-violet-700 dark:text-violet-300"
									: "rounded border border-teal-500/25 bg-teal-500/5 px-1.5 py-0.5 text-center font-mono text-[10px] text-teal-700 dark:text-teal-300"
							}
						>
							<span className="mr-1 text-muted-foreground/70">{i + 1}</span>
							{w}
						</span>
					))}
				</div>
				<div className="flex justify-end">
					<CopyButton
						text={spoken.join(" ")}
						label="Copy words"
						ariaLabel={`Copy PGP words for fingerprint ${fingerprint}`}
					/>
				</div>
			</div>
		</details>
	);
}

/**
 * Amber/red callout for registry-watch findings: the key's material changed
 * or it was revoked since THIS DEVICE last looked at it. Deliberately noisy
 * — replacement is exactly what a MitM attack looks like in the registry.
 */
function WatchCallout({
	watch,
}: {
	watch: { changed: boolean; nowRevoked: boolean; since: number | null };
}) {
	if (!watch.changed && !watch.nowRevoked) return null;
	const sinceLabel = watch.since ? ` (last seen ${new Date(watch.since).toLocaleString()})` : "";
	const revoked = watch.nowRevoked;
	return (
		<div
			data-testid={revoked ? "watch-revoked" : "watch-changed"}
			role="status"
			className={
				revoked
					? "mt-2 flex items-start gap-2 rounded-lg border border-red-500/40 bg-red-500/5 px-2.5 py-2 text-[11px] text-red-700 dark:border-red-400/30 dark:text-red-300"
					: "mt-2 flex items-start gap-2 rounded-lg border border-amber-500/40 bg-amber-500/5 px-2.5 py-2 text-[11px] text-amber-700 dark:border-amber-400/30 dark:text-amber-300"
			}
		>
			<TriangleAlert aria-hidden="true" className="mt-0.5 size-3.5 shrink-0" />
			<span>
				{revoked
					? `Revoked since your last lookup${sinceLabel} — stop trusting this key.`
					: `Key material changed since your last lookup${sinceLabel} — re-verify out of band (PGP words or QR) before trusting it.`}
			</span>
		</div>
	);
}

function RegistryLookup({
	onEncryptTo,
	myKeys,
	onMyKeysChanged,
}: {
	onEncryptTo?: (recipient: Recipient) => void;
	/** Local list — rows whose fingerprint is saved here get a “yours” badge. */
	myKeys: MyRegistryKey[];
	/** Called after "Refresh saved copy" updates local bookkeeping. */
	onMyKeysChanged?: () => void;
}) {
	const [query, setQuery] = useState("");
	const [loading, setLoading] = useState(false);
	const [results, setResults] = useState<
		| {
				fingerprint: string;
				armored: string;
				revoked: boolean;
				revokedAt: number | null;
				revokeReason: string | null;
				createdAt: number;
				updatedAt: number;
				meta: LookupKeyMeta | null;
				watch: {
					changed: boolean;
					nowRevoked: boolean;
					since: number | null;
				};
		  }[]
		| null
	>(null);
	const [error, setError] = useState<string | null>(null);
	// Rows whose fingerprint exists in the local my-keys list get a “yours”
	// badge; a registry row NEWER than the saved copy gets a refresh
	// affordance so multi-device drift can be healed in one click.
	const mineMap = useMemo(
		() => new Map(myKeys.map((k) => [k.fingerprint.toLowerCase(), k])),
		[myKeys],
	);
	const [refreshingFpr, setRefreshingFpr] = useState<string | null>(null);

	const runSearch = useCallback(async (raw: string) => {
		const kind = detectQueryKind(raw);
		if (!kind) {
			setError("Enter a 40-hex fingerprint, a 16-hex key ID, or an email address.");
			return;
		}
		setError(null);
		setLoading(true);
		try {
			const clean = raw.trim().replace(/\s+/g, "").replace(/^0x/i, "").toUpperCase();
			const keys = await registryLookup(
				kind === "email"
					? { email: raw.trim().toLowerCase() }
					: kind === "fingerprint"
						? { fingerprint: clean }
						: { keyId: clean },
			);
			// Enrich rows with a client-side parse of the armored key (algorithm,
			// expiry, identities, subkeys). Promise.all keeps result order stable.
			const rows = await Promise.all(
				keys.map(async (k) => ({ ...k, meta: await describeKeyMeta(k.armored) })),
			);
			// Registry watch: compare each row against its LAST LOCAL SIGHTING so
			// keys replaced or revoked since this device last saw them are flagged
			// (the server only knows the current state — noticing "different from
			// before" needs memory). Comparison runs BEFORE the sighting refresh.
			const watched = rows.map((k) => {
				const prior = getKeySighting(k.fingerprint);
				return {
					...k,
					watch: {
						changed: Boolean(prior && k.updatedAt > prior.updatedAt),
						nowRevoked: Boolean(prior && !prior.revoked && k.revoked),
						since: prior?.seenAt ?? null,
					},
				};
			});
			for (const k of watched) {
				noteKeySighted(k.fingerprint, { updatedAt: k.updatedAt, revoked: k.revoked });
			}
			setResults(watched);
		} catch (e) {
			setError(formatRegistryError(e, "Lookup failed"));
		} finally {
			setLoading(false);
		}
	}, []);

	const handleSearch = useCallback(async () => {
		await runSearch(query);
	}, [query, runSearch]);

	// Camera scan: fill the query and search the scanned fingerprint.
	const handleScanDetected = useCallback(
		(fpr: string) => {
			setQuery(fpr);
			void runSearch(fpr);
		},
		[runSearch],
	);

	// Row action: parse the armored public key and hand a Recipient to the
	// app (PgpApp dedups + jumps to Encrypt). Parse failures toast here;
	// success feedback comes from the app-level toast.
	const handleEncryptToKey = useCallback(
		async (k: { armored: string; fingerprint: string }) => {
			if (!onEncryptTo) return;
			try {
				const info = await describePublicKey(k.armored);
				onEncryptTo({
					source: "local",
					label: info.userIDs[0]?.email ?? info.userIDs[0]?.name ?? info.keyID,
					armored: k.armored,
					fingerprint: k.fingerprint,
					keyID: info.keyID,
					algorithm: info.algorithm,
					expiresAt: info.expirationTime ? info.expirationTime.getTime() : null,
				});
			} catch (e) {
				toast({
					title: "Could not use this key",
					description: (e as Error).message,
					variant: "destructive",
				});
			}
		},
		[onEncryptTo],
	);
	// Row action: the saved copy of this key predates the registry version
	// (old backup, or replaced from another device). Pull emails/algo/keyId
	// from the CURRENT armored key and refresh the local record — label and
	// revocation token stay untouched.
	const handleRefreshCopy = useCallback(
		async (k: { armored: string; fingerprint: string; updatedAt: number }) => {
			if (!onMyKeysChanged) return;
			setRefreshingFpr(k.fingerprint);
			try {
				const info = await describePublicKey(k.armored);
				const emails = info.userIDs
					.map((u) => u.email ?? u.name)
					.filter((v): v is string => Boolean(v))
					.slice(0, 10);
				updateMyKey(k.fingerprint, {
					keyId: info.keyID,
					...(emails.length > 0 ? { emails } : {}),
					...(info.algorithm ? { algo: prettyAlgorithm(info.algorithm, info.curve ?? null) } : {}),
					updatedAt: k.updatedAt * 1000,
				});
				onMyKeysChanged();
				toast({
					title: "Saved copy refreshed",
					description:
						"Local record now matches the registry version — label and revocation token untouched.",
				});
			} catch (e) {
				toast({
					title: "Could not refresh this copy",
					description: (e as Error).message,
					variant: "destructive",
				});
			} finally {
				setRefreshingFpr(null);
			}
		},
		[onMyKeysChanged],
	);

	return (
		<Card>
			<CardContent className="space-y-4 p-4">
				<div className="space-y-1.5">
					<Label htmlFor="keys-lookup">Look up a published key</Label>
					<div className="flex gap-1.5">
						<Input
							id="keys-lookup"
							value={query}
							onChange={(e) => setQuery(e.target.value)}
							placeholder="Fingerprint, key ID, or email"
							autoComplete="off"
							className="min-w-0 flex-1 font-mono text-xs"
							onKeyDown={(e) => {
								if (e.key === "Enter") handleSearch();
							}}
						/>
						<ScanQrButton onDetect={handleScanDetected} />
						<Button
							type="button"
							variant="outline"
							onClick={handleSearch}
							disabled={loading}
							className="h-11 shrink-0 gap-1.5 sm:h-9"
						>
							{loading ? (
								<Loader2 aria-hidden="true" className="size-4 animate-spin" />
							) : (
								<Search aria-hidden="true" className="size-4" />
							)}
							Search
						</Button>
					</div>
				</div>

				{results && results.length === 0 && (
					<div className="flex items-center justify-center gap-2 rounded-lg border border-dashed py-6 text-xs text-muted-foreground">
						<Fingerprint aria-hidden="true" className="size-3.5" />
						No keys found for that query — check the fingerprint or email spelling.
					</div>
				)}
				{results && results.length > 0 && (
					<div className="space-y-1.5">
						<p className="text-[11px] text-muted-foreground" aria-live="polite">
							{results.length.toLocaleString()} key{results.length === 1 ? "" : "s"} found
						</p>
						<ul className="scrollbar-thin max-h-96 space-y-2 overflow-y-auto pr-1">
							{results.map((k) => {
								const mine = mineMap.get(k.fingerprint.toLowerCase());
								const mineStamp = mine ? (mine.updatedAt ?? mine.publishedAt) : 0;
								const mineStale = Boolean(mine && mineStamp < k.updatedAt * 1000 - 500);
								return (
									<li
										key={k.fingerprint}
										className="rounded-lg border bg-muted/30 p-3 text-xs transition-all duration-150 hover:border-[#0055dc]/35 hover:bg-muted/50 hover:shadow-sm dark:hover:border-[#5e94ff]/25"
									>
										<div className="flex flex-wrap items-center gap-x-3 gap-y-1">
											<span className="font-mono">{formatFingerprint(k.fingerprint)}</span>
											{k.revoked ? (
												<Badge variant="destructive" className="text-[10px]">
													revoked{k.revokeReason ? `: ${k.revokeReason}` : ""}
												</Badge>
											) : (
												<Badge
													variant="outline"
													className="border-emerald-500/40 text-[10px] text-emerald-700 dark:text-emerald-400"
												>
													active
												</Badge>
											)}
											{mine && (
												<Badge
													variant="outline"
													className="border-emerald-500/40 bg-emerald-500/5 text-[10px] font-medium text-emerald-700 dark:border-emerald-400/30 dark:text-emerald-300"
													title={`Saved in your keys list as “${mine.label}”`}
													data-testid="keys-yours"
												>
													<UserCheck aria-hidden="true" className="mr-1 inline size-3" />
													yours
												</Badge>
											)}
											{mine && mineStale && (
												<Badge
													variant="outline"
													className="border-amber-500/50 bg-amber-500/10 text-[10px] text-amber-700 dark:border-amber-400/30 dark:text-amber-300"
													title="The registry has a newer version than your saved copy"
													data-testid="keys-yours-stale"
												>
													newer on registry
												</Badge>
											)}
											<span className="ml-auto text-muted-foreground">
												published {new Date(k.createdAt * 1000).toLocaleDateString()}
											</span>
											<Button
												type="button"
												variant="outline"
												size="sm"
												className="h-9 gap-1.5 px-2.5 text-[11px] sm:h-7"
												onClick={() => void handleEncryptToKey(k)}
												disabled={k.revoked}
												aria-label={`Encrypt to key ${k.fingerprint}`}
												data-testid="keys-encrypt-to"
												title={
													k.revoked
														? "Revoked keys must not be used"
														: "Add as encryption recipient and open the Encrypt tab"
												}
											>
												<Send aria-hidden="true" className="size-3" />
												Encrypt
											</Button>
											{mine && mineStale && !k.revoked && (
												<Button
													type="button"
													variant="outline"
													size="sm"
													className="h-9 gap-1.5 px-2.5 text-[11px] sm:h-7"
													onClick={() => void handleRefreshCopy(k)}
													disabled={refreshingFpr === k.fingerprint}
													aria-label={`Refresh the locally saved copy of ${k.fingerprint}`}
													data-testid="keys-refresh-copy"
													title="Update your saved copy to the registry version — label and revocation token stay"
												>
													{refreshingFpr === k.fingerprint ? (
														<Loader2 aria-hidden="true" className="size-3 animate-spin" />
													) : (
														<RefreshCw aria-hidden="true" className="size-3" />
													)}
													Refresh copy
												</Button>
											)}
											<FingerprintQrButton fingerprint={k.fingerprint} />
											<CopyButton
												text={k.fingerprint}
												label="Copy fpr"
												ariaLabel={`Copy fingerprint ${k.fingerprint}`}
											/>
										</div>
										{k.meta && (
											<div className="mt-2">
												<KeyMetaBadges meta={k.meta} />
											</div>
										)}
										<WatchCallout watch={k.watch} />
										<PgpWordsPanel fingerprint={k.fingerprint} />
										<details className="mt-2">
											<summary className="cursor-pointer select-none text-[11px] text-[#0055dc] hover:underline dark:text-[#5e94ff]">
												Show armored public key
											</summary>
											<pre className="mt-1.5 max-h-40 overflow-auto rounded bg-background/80 p-2 font-mono text-[10px] leading-relaxed">
												{k.armored}
											</pre>
										</details>
									</li>
								);
							})}
						</ul>
					</div>
				)}

				{error && (
					<Alert variant="destructive">
						<TriangleAlert aria-hidden="true" className="size-4" />
						<AlertDescription className="text-xs">{error}</AlertDescription>
					</Alert>
				)}
			</CardContent>
		</Card>
	);
}

/* --------------------------- escrow restore ------------------------------- */

function RestoreEscrow({ onUseKey }: { onUseKey: (config: PrivateKeyConfig) => void }) {
	const [fingerprint, setFingerprint] = useState("");
	const [passphrase, setPassphrase] = useState("");
	const [busy, setBusy] = useState(false);
	const [status, setStatus] = useState<string | null>(null);
	const [error, setError] = useState<string | null>(null);

	const handleRestore = useCallback(async () => {
		const fpr = fingerprint.trim().replace(/\s+/g, "").replace(/^0x/i, "").toUpperCase();
		if (!/^[0-9A-F]{40}$/.test(fpr)) {
			setError("Enter the 40-hex fingerprint of the key to restore.");
			return;
		}
		if (!passphrase) {
			setError("Enter the passphrase that protects the escrowed key.");
			return;
		}
		setError(null);
		setStatus(null);
		setBusy(true);
		try {
			const escrow = await registryFetchEscrow(fpr);
			if (!escrow.encryptedPrivate) {
				setStatus("No encrypted private key is escrowed for this fingerprint.");
				return;
			}
			// Decrypt locally — the passphrase never leaves the browser.
			const openpgp = await import("openpgp");
			const key = await openpgp.readKey({ armoredKey: escrow.encryptedPrivate });
			const unlocked = await openpgp.decryptKey({
				privateKey: key as OpenPGP.PrivateKey,
				passphrase,
			});
			if (!unlocked.isPrivate()) throw new Error("Escrowed blob is not a private key");
			const info = await validateArmoredKey(escrow.encryptedPrivate);
			if (!info.ok || !info.info) throw new Error("Escrowed key failed local validation");
			const summary = keyInfoSummary(info.info);
			onUseKey({
				source: "manual",
				label: summary.label,
				encryptedArmored: escrow.encryptedPrivate,
				info: info.info,
			});
			setStatus("Key decrypted and configured — it is ready to use on the other tabs.");
			setPassphrase("");
		} catch (e) {
			const message = (e as Error).message ?? "";
			setError(
				message.includes("checksum") || message.includes("passphrase")
					? "Wrong passphrase for this escrowed key."
					: message.includes("Wrong passphrase")
						? message
						: formatRegistryError(e, message),
			);
		} finally {
			setBusy(false);
		}
	}, [fingerprint, onUseKey, passphrase]);

	return (
		<Card>
			<CardContent className="space-y-4 p-4">
				<div className="space-y-1">
					<h3 className="text-sm font-medium">Restore an escrowed key</h3>
					<p className="text-[11px] leading-snug text-muted-foreground">
						Fetch the encrypted private key backup from the registry and decrypt it locally with
						your passphrase.
					</p>
				</div>
				<div className="grid gap-3 sm:grid-cols-2">
					<div className="space-y-1.5">
						<Label htmlFor="keys-restore-fpr">Fingerprint</Label>
						<Input
							id="keys-restore-fpr"
							value={fingerprint}
							onChange={(e) => setFingerprint(e.target.value)}
							placeholder="40 hex characters"
							autoComplete="off"
							className="font-mono text-xs"
						/>
					</div>
					<div className="space-y-1.5">
						<Label htmlFor="keys-restore-pass">Passphrase</Label>
						<Input
							id="keys-restore-pass"
							type="password"
							value={passphrase}
							onChange={(e) => setPassphrase(e.target.value)}
							placeholder="Protects the escrowed key"
							autoComplete="off"
						/>
					</div>
				</div>
				<Button
					type="button"
					onClick={handleRestore}
					disabled={busy}
					className="h-11 gap-1.5 sm:h-9"
				>
					{busy ? (
						<Loader2 aria-hidden="true" className="size-4 animate-spin" />
					) : (
						<RefreshCw aria-hidden="true" className="size-4" />
					)}
					{busy ? "Restoring…" : "Fetch and restore"}
				</Button>
				{status && (
					<Alert className="border-emerald-300/60 bg-emerald-50/60 dark:border-emerald-900/50 dark:bg-emerald-950/20">
						<ShieldCheck
							aria-hidden="true"
							className="size-4 text-emerald-600 dark:text-emerald-400"
						/>
						<AlertDescription className="text-xs">{status}</AlertDescription>
					</Alert>
				)}
				{error && (
					<Alert variant="destructive">
						<TriangleAlert aria-hidden="true" className="size-4" />
						<AlertDescription className="text-xs">{error}</AlertDescription>
					</Alert>
				)}
			</CardContent>
		</Card>
	);
}

/* ------------------------------- my keys ---------------------------------- */

/** Shared badge styling for the per-key status audit outcomes. */
function auditBadgeProps(outcome: MyKeyAuditOutcome): { label: string; className: string } {
	switch (outcome) {
		case "ok":
			return {
				label: "unchanged",
				className:
					"border-emerald-500/40 bg-emerald-500/5 text-emerald-700 dark:border-emerald-400/30 dark:text-emerald-300",
			};
		case "changed":
			return {
				label: "changed on registry",
				className:
					"border-amber-500/50 bg-amber-500/10 text-amber-700 dark:border-amber-400/30 dark:text-amber-300",
			};
		case "revoked":
			return {
				label: "revoked",
				className:
					"border-red-400/50 bg-red-500/10 text-red-700 dark:border-red-400/30 dark:text-red-300",
			};
		case "missing":
			return {
				label: "not on registry",
				className: "text-muted-foreground",
			};
		default:
			return {
				label: "check failed",
				className: "border-dashed text-muted-foreground",
			};
	}
}

function MyKeysList({ keys, onChanged }: { keys: MyRegistryKey[]; onChanged: () => void }) {
	const [revealed, setRevealed] = useState<string | null>(null);
	const [revokeTarget, setRevokeTarget] = useState<MyRegistryKey | null>(null);
	const [busy, setBusy] = useState(false);
	const [error, setError] = useState<string | null>(null);
	// Backup restore: parse first, show a preview dialog, merge on confirm.
	const fileRef = useRef<HTMLInputElement>(null);
	const [restoreOpen, setRestoreOpen] = useState(false);
	const [restorePreview, setRestorePreview] = useState<{
		fileName: string;
		parsed: ParsedBackup;
		counts: RestoreReport;
	} | null>(null);
	// Status audit: per-fingerprint outcome of the last "Check on registry".
	const [audit, setAudit] = useState<Record<string, MyKeyAudit>>({});
	const [auditing, setAuditing] = useState(false);
	const [auditNote, setAuditNote] = useState<string | null>(null);
	// Encrypted backup: same JSON payload sealed with a passphrase
	// (PBKDF2-SHA256 → AES-256-GCM) so a stray file can't hand out
	// revocation power.
	const [exportOpen, setExportOpen] = useState(false);
	const [exportPass, setExportPass] = useState("");
	const [exportPass2, setExportPass2] = useState("");
	const [showExportPass, setShowExportPass] = useState(false);
	const [exportBusy, setExportBusy] = useState(false);
	// Encrypted restore: a v2 envelope must be UNLOCKED before its
	// contents can be previewed — one dialog, two stages.
	const [restoreStage, setRestoreStage] = useState<"passphrase" | "preview">("preview");
	const [restoreLocked, setRestoreLocked] = useState<{
		fileName: string;
		text: string;
	} | null>(null);
	const [restorePass, setRestorePass] = useState("");
	const [restorePassError, setRestorePassError] = useState<string | null>(null);

	const exportStrength = useMemo(() => estimatePassphraseStrength(exportPass), [exportPass]);
	const exportReady =
		exportPass.length > 0 && exportPass === exportPass2 && exportStrength.score >= 2 && !exportBusy;

	// Offline safety net: revocation tokens exist ONLY here (the registry
	// keeps hashes), so a one-click JSON export is the cheapest insurance
	// against a wiped browser profile.
	const downloadKeysBackup = useCallback(() => {
		const blob = new Blob([exportMyKeys()], { type: "application/json" });
		const url = URL.createObjectURL(blob);
		const a = document.createElement("a");
		a.href = url;
		a.download = `encryptor-keys-backup-${new Date().toISOString().slice(0, 10)}.json`;
		a.click();
		setTimeout(() => URL.revokeObjectURL(url), 1000);
		toast({
			title: "Backup downloaded",
			description:
				"Unencrypted file — anyone who gets it can revoke your keys. Prefer the encrypted backup.",
		});
	}, []);

	const closeRestore = useCallback(() => {
		setRestoreOpen(false);
		setRestorePreview(null);
		setRestoreLocked(null);
		setRestorePass("");
		setRestorePassError(null);
		setRestoreStage("preview");
	}, []);

	// Read + validate the chosen file, then show what WOULD change before
	// touching anything — a restore must never surprise.
	// Read + validate the chosen file. Encrypted envelopes (v2) go to a
	// passphrase stage first — contents stay sealed until decrypt — while
	// plaintext files go straight to the what-would-change preview. A
	// restore must never surprise.
	const handleBackupFile = useCallback(async (file: File) => {
		const text = await file.text();
		if (isEncryptedBackupText(text)) {
			setRestoreLocked({ fileName: file.name, text });
			setRestorePass("");
			setRestorePassError(null);
			setRestoreStage("passphrase");
			setRestoreOpen(true);
			return;
		}
		try {
			const parsed = parseKeysBackup(text);
			if (parsed.keys.length === 0) {
				toast({
					title: "Nothing restorable in that file",
					description:
						parsed.invalid > 0
							? `${parsed.invalid} unusable entr${parsed.invalid === 1 ? "y" : "ies"} and no valid keys.`
							: "The backup contains no keys.",
					variant: "destructive",
				});
				return;
			}
			setRestorePreview({
				fileName: file.name,
				parsed,
				counts: previewRestore(parsed.keys),
			});
			setRestoreStage("preview");
			setRestoreOpen(true);
		} catch (e) {
			toast({
				title: "Restore failed",
				description: e instanceof Error ? e.message : "Could not read that file.",
				variant: "destructive",
			});
		}
	}, []);

	// Stage 1 → 2: derive the key, open the envelope, and only then show
	// the preview. Wrong passphrases keep the dialog open with an inline
	// error — the file never leaves the browser either way.
	const handleUnlockRestore = useCallback(async () => {
		if (!restoreLocked) return;
		setRestorePassError(null);
		try {
			const plain = await decryptKeysBackup(restoreLocked.text, restorePass);
			const parsed = parseKeysBackup(plain);
			if (parsed.keys.length === 0) {
				setRestorePassError("That backup unlocked but holds no restorable keys.");
				return;
			}
			setRestorePreview({
				fileName: restoreLocked.fileName,
				parsed,
				counts: previewRestore(parsed.keys),
			});
			setRestoreStage("preview");
			setRestoreLocked(null);
			setRestorePass("");
		} catch (e) {
			if (e instanceof BackupDecryptFailure && e.reason === "wrong-passphrase") {
				setRestorePassError(e.message);
			} else {
				closeRestore();
				toast({
					title: "Restore failed",
					description: e instanceof Error ? e.message : "Could not unlock that backup.",
					variant: "destructive",
				});
			}
		}
	}, [closeRestore, restoreLocked, restorePass]);

	const openEncryptedExport = useCallback(() => {
		setExportPass("");
		setExportPass2("");
		setShowExportPass(false);
		setExportOpen(true);
	}, []);

	const closeExport = useCallback(() => {
		setExportOpen(false);
		setExportPass("");
		setExportPass2("");
		setShowExportPass(false);
		setExportBusy(false);
	}, []);

	const handleEncryptedExport = useCallback(async () => {
		if (exportPass !== exportPass2 || exportStrength.score < 2) return;
		setExportBusy(true);
		try {
			const sealed = await encryptKeysBackup(exportMyKeys(), exportPass);
			const blob = new Blob([sealed], { type: "application/json" });
			const url = URL.createObjectURL(blob);
			const a = document.createElement("a");
			a.href = url;
			a.download = `encryptor-keys-backup-encrypted-${new Date().toISOString().slice(0, 10)}.json`;
			a.click();
			setTimeout(() => URL.revokeObjectURL(url), 1000);
			closeExport();
			toast({
				title: "Encrypted backup downloaded",
				description:
					"Sealed with AES-256-GCM. Keep the passphrase safe — without it the tokens are unrecoverable.",
			});
		} catch (e) {
			toast({
				title: "Encryption failed",
				description: e instanceof Error ? e.message : "Could not seal the backup.",
				variant: "destructive",
			});
		} finally {
			setExportBusy(false);
		}
	}, [closeExport, exportPass, exportPass2, exportStrength.score]);

	const confirmRestore = useCallback(() => {
		if (!restorePreview) return;
		const rep = mergeMyKeys(restorePreview.parsed.keys);
		closeRestore();
		onChanged();
		setAudit({});
		setAuditNote(null);
		toast({
			title: `Restored ${rep.added + rep.updated} key${rep.added + rep.updated === 1 ? "" : "s"}`,
			description: `${rep.added} new · ${rep.updated} updated · ${rep.skipped} already current.${restorePreview.parsed.invalid > 0 ? ` ${restorePreview.parsed.invalid} unusable ${restorePreview.parsed.invalid === 1 ? "entry" : "entries"} ignored.` : ""}`,
		});
	}, [closeRestore, onChanged, restorePreview]);

	// One-click health sweep: re-fetch every known fingerprint and compare
	// against the watch layer's sightings. Bounded (12) and sequential so a
	// big list can't hammer the shared rate bucket.
	const runAudit = useCallback(async () => {
		if (auditing || keys.length === 0) return;
		setAuditing(true);
		setAudit({});
		setAuditNote(null);
		const results = await auditMyKeysOnRegistry(keys, {
			onResult: (a) => setAudit((prev) => ({ ...prev, [a.fingerprint]: a })),
		});
		const attention = results.filter(
			(a) => a.outcome === "changed" || a.outcome === "revoked",
		).length;
		const head =
			results.length < keys.length
				? `${results.length} of ${keys.length} checked`
				: `${results.length} checked`;
		setAuditNote(
			attention > 0
				? `${head} · ${attention} need${attention === 1 ? "s" : ""} attention`
				: `${head} · no changes or revocations detected`,
		);
		setAuditing(false);
	}, [auditing, keys]);

	const handleRevoke = useCallback(async () => {
		if (!revokeTarget?.revocationToken) return;
		setBusy(true);
		setError(null);
		try {
			await registryRevokeByToken(revokeTarget.fingerprint, revokeTarget.revocationToken);
			updateMyKey(revokeTarget.fingerprint, { escrowed: false });
			setRevokeTarget(null);
			onChanged();
		} catch (e) {
			setError(formatRegistryError(e, (e as Error).message));
		} finally {
			setBusy(false);
		}
	}, [onChanged, revokeTarget]);

	return (
		<Card>
			<CardContent className="space-y-3 p-4">
				<div className="flex flex-wrap items-center justify-between gap-2">
					<div className="flex items-center gap-2">
						<h3 className="text-sm font-medium">Keys published from this device</h3>
						{keys.length > 0 && (
							<Badge variant="outline" className="font-mono text-[10px]">
								{keys.length}
							</Badge>
						)}
					</div>
					<div className="flex flex-wrap items-center gap-1.5">
						{keys.length > 0 && (
							<Button
								type="button"
								variant="outline"
								size="sm"
								className="h-7 gap-1.5 px-2.5 text-[11px]"
								onClick={() => void runAudit()}
								disabled={auditing}
								aria-label="Re-fetch each key from the registry and compare with the last sighting"
								data-testid="keys-audit"
								title="Re-fetch each key from the registry and flag changes or revocations since your last check"
							>
								{auditing ? (
									<Loader2 aria-hidden="true" className="size-3 animate-spin" />
								) : (
									<ShieldCheck aria-hidden="true" className="size-3" />
								)}
								Check on registry
							</Button>
						)}
						<Button
							type="button"
							variant="outline"
							size="sm"
							className="h-7 gap-1.5 px-2.5 text-[11px]"
							onClick={() => fileRef.current?.click()}
							aria-label="Restore keys from an offline JSON backup file"
							data-testid="keys-backup-restore"
							title="Bring back the keys from an offline backup — e.g. when migrating to a new device"
						>
							<Upload aria-hidden="true" className="size-3" />
							Restore
						</Button>
						{keys.length > 0 && (
							<Button
								type="button"
								variant="outline"
								size="sm"
								className="h-7 gap-1.5 px-2.5 text-[11px]"
								onClick={openEncryptedExport}
								aria-label="Download a passphrase-encrypted backup of your keys and revocation tokens"
								data-testid="keys-backup-encrypted"
								title="Seal the backup with a passphrase (PBKDF2 + AES-256-GCM) — safe to keep anywhere"
							>
								<Lock aria-hidden="true" className="size-3" />
								Encrypted backup
							</Button>
						)}
						{keys.length > 0 && (
							<Button
								type="button"
								variant="outline"
								size="sm"
								className="h-7 gap-1.5 px-2.5 text-[11px]"
								onClick={() => downloadKeysBackup()}
								aria-label="Download an unencrypted JSON backup of your keys and revocation tokens"
								data-testid="keys-backup"
								title="Unencrypted JSON — anyone with this file can revoke your keys. Prefer the encrypted backup"
							>
								<Download aria-hidden="true" className="size-3" />
								Backup
							</Button>
						)}
					</div>
					<input
						ref={fileRef}
						type="file"
						accept=".json,application/json"
						className="hidden"
						aria-label="Keys backup file"
						data-testid="keys-restore-file"
						onChange={(e) => {
							const f = e.target.files?.[0];
							if (f) void handleBackupFile(f);
							e.target.value = "";
						}}
					/>
				</div>
				{auditNote && (
					<p
						className="text-[11px] text-muted-foreground"
						role="status"
						data-testid="keys-audit-note"
					>
						{auditNote}
					</p>
				)}
				{keys.length === 0 && (
					<div
						data-testid="keys-empty"
						className="flex flex-col items-center gap-2 rounded-xl border border-dashed px-6 py-8 text-center"
					>
						<span className="flex size-10 items-center justify-center rounded-full bg-[#0055dc]/10 text-[#0055dc] dark:bg-[#5e94ff]/15 dark:text-[#5e94ff]">
							<KeyRound aria-hidden="true" className="size-5" />
						</span>
						<p className="text-sm font-medium">No keys from this device yet</p>
						<p className="max-w-xs text-xs text-muted-foreground">
							Publish a key above and it will be listed here with its revocation token — or restore
							an offline backup to bring a previous device's list back.
						</p>
					</div>
				)}
				{error && (
					<Alert variant="destructive">
						<TriangleAlert aria-hidden="true" className="size-4" />
						<AlertDescription className="text-xs">{error}</AlertDescription>
					</Alert>
				)}
				<ul className="scrollbar-thin max-h-72 space-y-2 overflow-y-auto pr-1">
					{keys.map((k) => (
						<li
							key={k.fingerprint}
							className="rounded-lg border bg-muted/30 p-3 text-xs transition-all duration-150 hover:border-[#0055dc]/35 hover:bg-muted/50 hover:shadow-sm dark:hover:border-[#5e94ff]/25"
						>
							<div className="flex flex-wrap items-center gap-x-3 gap-y-1">
								<span className="max-w-full truncate font-medium">{k.label}</span>
								{k.algo && (
									<Badge
										variant="outline"
										className="border-violet-500/40 bg-violet-500/5 text-[10px] font-medium text-violet-700 dark:border-violet-400/30 dark:text-violet-300"
										title="Primary key algorithm"
									>
										<KeyRound aria-hidden="true" className="mr-1 inline size-3" />
										{k.algo}
									</Badge>
								)}
								{k.escrowed && (
									<Badge
										variant="outline"
										className="border-[#0055dc]/40 text-[10px] text-[#0055dc] dark:border-[#5e94ff]/40 dark:text-[#5e94ff]"
									>
										escrowed
									</Badge>
								)}
								{audit[k.fingerprint] && (
									<Badge
										variant="outline"
										className={auditBadgeProps(audit[k.fingerprint].outcome).className}
										title={audit[k.fingerprint].detail}
										data-testid="keys-audit-badge"
									>
										{auditBadgeProps(audit[k.fingerprint].outcome).label}
									</Badge>
								)}
								{audit[k.fingerprint]?.escrowDrift && (
									<Badge
										variant="outline"
										className="border-amber-500/50 bg-amber-500/10 text-[10px] text-amber-700 dark:border-amber-400/30 dark:text-amber-300"
										title={
											audit[k.fingerprint].escrowDrift === "outdated"
												? "The escrowed private-key backup predates the current key version — restoring it would return an old key. Replace the key WITH escrow to refresh the backup."
												: "The registry no longer holds the escrowed private-key backup for this key."
										}
										data-testid="keys-escrow-drift"
									>
										{audit[k.fingerprint].escrowDrift === "outdated"
											? "escrow outdated"
											: "escrow missing"}
									</Badge>
								)}
								<span className="ml-auto text-muted-foreground">
									published {new Date(k.publishedAt).toLocaleDateString()}
									{k.updatedAt && k.updatedAt - k.publishedAt > 60_000
										? ` · updated ${new Date(k.updatedAt).toLocaleDateString()}`
										: ""}
								</span>
							</div>
							<p className="mt-1 font-mono text-[11px] text-muted-foreground">
								{formatFingerprint(k.fingerprint)}
							</p>
							<div className="mt-2 flex flex-wrap items-center gap-1.5">
								<CopyButton
									text={k.fingerprint}
									label="Copy fpr"
									ariaLabel={`Copy fingerprint ${k.fingerprint}`}
								/>
								<FingerprintQrButton fingerprint={k.fingerprint} />
								{k.revocationToken && (
									<>
										<Button
											type="button"
											variant="outline"
											size="sm"
											className="h-9 gap-1.5 px-2.5 text-[11px] sm:h-7"
											onClick={() => setRevealed(revealed === k.fingerprint ? null : k.fingerprint)}
										>
											{revealed === k.fingerprint ? (
												<EyeOff aria-hidden="true" className="size-3" />
											) : (
												<Eye aria-hidden="true" className="size-3" />
											)}
											{revealed === k.fingerprint ? "Hide token" : "Show token"}
										</Button>
										<CopyButton
											text={k.revocationToken}
											label="Copy token"
											ariaLabel={`Copy revocation token for ${k.fingerprint}`}
										/>
										<Button
											type="button"
											variant="outline"
											size="sm"
											className="h-9 gap-1.5 border-red-300/70 px-2.5 text-[11px] text-red-700 hover:bg-red-50 sm:h-7 dark:border-red-900/60 dark:text-red-400 dark:hover:bg-red-950/30"
											onClick={() => setRevokeTarget(k)}
										>
											<Trash2 aria-hidden="true" className="size-3" />
											Revoke
										</Button>
									</>
								)}
								<Button
									type="button"
									variant="ghost"
									size="sm"
									className="h-9 px-2.5 text-[11px] text-muted-foreground sm:h-7"
									onClick={() => {
										forgetMyKey(k.fingerprint);
										onChanged();
									}}
								>
									Forget
								</Button>
							</div>
							{revealed === k.fingerprint && k.revocationToken && (
								<code className="mt-2 block break-all rounded bg-background/80 px-2 py-1.5 font-mono text-[10px]">
									{k.revocationToken}
								</code>
							)}
						</li>
					))}
				</ul>

				<Dialog
					open={restoreOpen}
					onOpenChange={(open) => {
						if (!open) closeRestore();
					}}
				>
					<DialogContent className="max-w-md">
						{restoreStage === "passphrase" ? (
							<>
								<DialogHeader>
									<DialogTitle className="flex items-center gap-2 text-base">
										<span className="flex size-7 items-center justify-center rounded-lg bg-amber-500/10 text-amber-600 dark:bg-amber-400/10 dark:text-amber-300">
											<Lock aria-hidden="true" className="size-3.5" />
										</span>
										Encrypted backup
									</DialogTitle>
									<DialogDescription className="break-all text-xs">
										{restoreLocked?.fileName} — sealed with a passphrase. Unlock to preview what a
										restore would change; nothing leaves this browser.
									</DialogDescription>
								</DialogHeader>
								<div className="space-y-1.5">
									<Label htmlFor="keys-restore-pass">Backup passphrase</Label>
									<Input
										id="keys-restore-pass"
										type="password"
										value={restorePass}
										onChange={(e) => setRestorePass(e.target.value)}
										autoComplete="off"
										className="font-mono text-xs"
										data-testid="keys-restore-pass"
										onKeyDown={(e) => {
											if (e.key === "Enter" && restorePass) void handleUnlockRestore();
										}}
									/>
									{restorePassError && (
										<p
											className="text-[11px] text-red-600 dark:text-red-400"
											role="alert"
											data-testid="keys-restore-pass-error"
										>
											{restorePassError}
										</p>
									)}
									<p className="font-mono text-[10px] text-muted-foreground">
										PBKDF2-SHA256 · AES-256-GCM — verified locally
									</p>
								</div>
								<DialogFooter className="gap-2">
									<Button type="button" variant="outline" size="sm" onClick={closeRestore}>
										Cancel
									</Button>
									<Button
										type="button"
										size="sm"
										onClick={() => void handleUnlockRestore()}
										disabled={!restorePass}
										className="gap-1.5"
										data-testid="keys-restore-unlock"
									>
										<Lock aria-hidden="true" className="size-3.5" />
										Unlock
									</Button>
								</DialogFooter>
							</>
						) : (
							<>
								<DialogHeader>
									<DialogTitle className="text-base">Restore this backup?</DialogTitle>
									<DialogDescription className="break-all text-xs">
										{restorePreview &&
											`${restorePreview.fileName}${restorePreview.parsed.exportedAt ? ` · exported ${new Date(restorePreview.parsed.exportedAt).toLocaleString()}` : ""}`}
									</DialogDescription>
								</DialogHeader>
								{restorePreview && (
									<div className="space-y-2.5">
										<div className="flex flex-wrap gap-1.5">
											<Badge
												variant="outline"
												data-testid="keys-restore-added"
												className="border-emerald-500/40 bg-emerald-500/10 text-[10px] text-emerald-700 dark:border-emerald-400/30 dark:text-emerald-300"
											>
												+{restorePreview.counts.added} new
											</Badge>
											<Badge
												variant="outline"
												data-testid="keys-restore-updated"
												className="border-amber-500/50 bg-amber-500/10 text-[10px] text-amber-700 dark:border-amber-400/30 dark:text-amber-300"
											>
												~{restorePreview.counts.updated} newer
											</Badge>
											<Badge
												variant="outline"
												data-testid="keys-restore-skipped"
												className="text-[10px] text-muted-foreground"
											>
												={restorePreview.counts.skipped} already current
											</Badge>
											{restorePreview.parsed.invalid > 0 && (
												<Badge
													variant="outline"
													data-testid="keys-restore-invalid"
													className="border-red-400/50 bg-red-500/10 text-[10px] text-red-700 dark:border-red-400/30 dark:text-red-300"
												>
													!{restorePreview.parsed.invalid} unusable
												</Badge>
											)}
										</div>
										<ul
											className="scrollbar-thin max-h-40 space-y-1 overflow-y-auto rounded-lg border bg-muted/30 p-2"
											data-testid="keys-restore-preview-list"
										>
											{restorePreview.parsed.keys.slice(0, 6).map((k) => (
												<li key={k.fingerprint} className="flex items-center gap-2 text-[11px]">
													<span className="truncate font-medium">{k.label}</span>
													<span className="ml-auto font-mono text-muted-foreground">
														{k.fingerprint.slice(0, 12)}…
													</span>
													{k.revocationToken && (
														<Badge variant="outline" className="text-[9px] text-muted-foreground">
															token
														</Badge>
													)}
												</li>
											))}
											{restorePreview.parsed.keys.length > 6 && (
												<li className="text-[11px] text-muted-foreground">
													+ {restorePreview.parsed.keys.length - 6} more…
												</li>
											)}
										</ul>
										<p className="text-[11px] text-muted-foreground">
											Newest records win per fingerprint; a revocation token your list lost is
											rescued from the file. Tokens stay on this device — the registry only stores
											their hashes.
										</p>
									</div>
								)}
								<DialogFooter className="gap-2">
									<Button type="button" variant="outline" size="sm" onClick={closeRestore}>
										Cancel
									</Button>
									<Button
										type="button"
										size="sm"
										onClick={confirmRestore}
										data-testid="keys-restore-confirm"
										className="gap-1.5"
										disabled={!restorePreview}
									>
										<Upload aria-hidden="true" className="size-3.5" />
										Restore {restorePreview ? restorePreview.parsed.keys.length : 0} key
										{restorePreview && restorePreview.parsed.keys.length === 1 ? "" : "s"}
									</Button>
								</DialogFooter>
							</>
						)}
					</DialogContent>
				</Dialog>

				<Dialog
					open={exportOpen}
					onOpenChange={(open) => {
						if (!open) closeExport();
					}}
				>
					<DialogContent className="max-w-md">
						<DialogHeader>
							<DialogTitle className="flex items-center gap-2 text-base">
								<span className="flex size-7 items-center justify-center rounded-lg bg-amber-500/10 text-amber-600 dark:bg-amber-400/10 dark:text-amber-300">
									<Lock aria-hidden="true" className="size-3.5" />
								</span>
								Encrypted backup
							</DialogTitle>
							<DialogDescription className="text-xs">
								Seals all {keys.length} key{keys.length === 1 ? "" : "s"} — labels, emails, escrow
								flags and revocation tokens — behind a passphrase only you know.
							</DialogDescription>
						</DialogHeader>
						<div className="space-y-3">
							<div className="space-y-1.5">
								<Label htmlFor="keys-export-pass">Backup passphrase</Label>
								<div className="relative">
									<Input
										id="keys-export-pass"
										type={showExportPass ? "text" : "password"}
										value={exportPass}
										onChange={(e) => setExportPass(e.target.value)}
										autoComplete="new-password"
										className="pr-9 font-mono text-xs"
										data-testid="keys-export-pass"
									/>
									<button
										type="button"
										onClick={() => setShowExportPass((v) => !v)}
										aria-label={showExportPass ? "Hide passphrase" : "Show passphrase"}
										className="absolute right-2 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
										data-testid="keys-export-toggle"
									>
										{showExportPass ? (
											<EyeOff aria-hidden="true" className="size-3.5" />
										) : (
											<Eye aria-hidden="true" className="size-3.5" />
										)}
									</button>
								</div>
								<PassphraseStrengthMeter passphrase={exportPass} idPrefix="keys-export-pass" />
							</div>
							<div className="space-y-1.5">
								<Label htmlFor="keys-export-pass2">Confirm passphrase</Label>
								<Input
									id="keys-export-pass2"
									type={showExportPass ? "text" : "password"}
									value={exportPass2}
									onChange={(e) => setExportPass2(e.target.value)}
									autoComplete="new-password"
									className="font-mono text-xs"
									data-testid="keys-export-pass2"
									onKeyDown={(e) => {
										if (e.key === "Enter" && exportReady) void handleEncryptedExport();
									}}
								/>
								{exportPass2 && exportPass !== exportPass2 && (
									<p
										className="text-[11px] text-red-600 dark:text-red-400"
										data-testid="keys-export-mismatch"
									>
										Passphrases don&apos;t match yet.
									</p>
								)}
								{exportPass && exportStrength.score < 2 && (
									<p
										className="text-[11px] text-amber-600 dark:text-amber-400"
										data-testid="keys-export-weak"
									>
										Too weak for revocation tokens — go longer or less predictable.
									</p>
								)}
							</div>
							<p className="rounded-lg border bg-muted/30 px-2.5 py-2 font-mono text-[10px] leading-relaxed text-muted-foreground">
								PBKDF2-SHA256 · 600,000 iterations → AES-256-GCM · fresh salt + IV every export ·
								unsealed only in this browser
							</p>
						</div>
						<DialogFooter className="gap-2">
							<Button type="button" variant="outline" size="sm" onClick={closeExport}>
								Cancel
							</Button>
							<Button
								type="button"
								size="sm"
								onClick={() => void handleEncryptedExport()}
								disabled={!exportReady}
								className="gap-1.5"
								data-testid="keys-export-confirm"
							>
								{exportBusy ? (
									<Loader2 aria-hidden="true" className="size-3.5 animate-spin" />
								) : (
									<Download aria-hidden="true" className="size-3.5" />
								)}
								Download encrypted backup
							</Button>
						</DialogFooter>
					</DialogContent>
				</Dialog>

				<Dialog
					open={revokeTarget !== null}
					onOpenChange={(open) => !open && setRevokeTarget(null)}
				>
					<DialogContent className="max-w-md">
						<DialogHeader>
							<DialogTitle className="text-base">Revoke this key?</DialogTitle>
							<DialogDescription className="text-xs">
								Revocation is permanent: the fingerprint can never be re-published, and any escrowed
								private key is purged. The public record stays visible with a revoked marker so
								others learn to stop trusting it.
							</DialogDescription>
						</DialogHeader>
						<p className="break-all font-mono text-[11px] text-muted-foreground">
							{revokeTarget && formatFingerprint(revokeTarget.fingerprint)}
						</p>
						<DialogFooter className="gap-2">
							<Button
								type="button"
								variant="outline"
								size="sm"
								onClick={() => setRevokeTarget(null)}
							>
								Cancel
							</Button>
							<Button
								type="button"
								variant="destructive"
								size="sm"
								onClick={handleRevoke}
								disabled={busy}
								className="gap-1.5"
							>
								{busy && <Loader2 aria-hidden="true" className="size-3.5 animate-spin" />}
								Revoke permanently
							</Button>
						</DialogFooter>
					</DialogContent>
				</Dialog>
			</CardContent>
		</Card>
	);
}

/* --------------------------- registry admin console ----------------------- */

const ADMIN_FPR_RE = /^[0-9a-fA-F]{40}$/;

/**
 * Owner-only emergency console for the registry's ADMIN_REVOKE_TOKEN path
 * (service compromise / abuse response). The token is kept in component
 * state ONLY — never persisted, never logged — and is sent once per
 * revocation call. Collapsed by default so regular users never meet it.
 * # Mr. AI Acting on s183173's Behalf
 */
function AdminConsole() {
	const [open, setOpen] = useState(false);
	const [token, setToken] = useState("");
	const [fpr, setFpr] = useState("");
	const [reason, setReason] = useState("");
	const [busy, setBusy] = useState(false);
	const [confirmOpen, setConfirmOpen] = useState(false);
	const [status, setStatus] = useState<{ kind: "ok" | "info" | "error"; text: string } | null>(
		null,
	);

	const fprClean = fpr.trim().replace(/\s+/g, "");
	const fprValid = ADMIN_FPR_RE.test(fprClean);
	const canSubmit = token.length > 0 && fprValid && !busy;

	const handleSubmit = useCallback(async () => {
		if (!canSubmit) return;
		setBusy(true);
		try {
			const r = await registryAdminRevoke(fprClean, token, reason.trim() || undefined);
			setStatus(
				r.alreadyRevoked
					? { kind: "info", text: "That key was already revoked." }
					: { kind: "ok", text: `Key ${formatFingerprint(fprClean)} revoked.` },
			);
			setFpr("");
			setReason("");
		} catch (e) {
			setStatus({ kind: "error", text: formatRegistryError(e, "Admin revocation failed") });
		} finally {
			setBusy(false);
		}
	}, [canSubmit, fprClean, reason, token]);

	return (
		<Card className={open ? "border-red-300/60 dark:border-red-900/50" : "border-dashed"}>
			<CardContent className="space-y-3 p-4">
				<button
					type="button"
					onClick={() => setOpen((v) => !v)}
					aria-expanded={open}
					className="flex w-full items-center gap-2 text-left"
					data-testid="admin-toggle"
				>
					<ShieldAlert
						aria-hidden="true"
						className={`size-4 ${open ? "text-red-600 dark:text-red-400" : "text-muted-foreground"}`}
					/>
					<span className="text-sm font-medium">Registry admin</span>
					{open ? (
						<ChevronUp aria-hidden="true" className="ml-auto size-4 text-muted-foreground" />
					) : (
						<ChevronDown aria-hidden="true" className="ml-auto size-4 text-muted-foreground" />
					)}
				</button>
				{open && (
					<div className="space-y-3" data-testid="admin-panel">
						<p className="text-[11px] leading-relaxed text-muted-foreground">
							Owner-only emergency override backed by the deployment&apos;s ADMIN_REVOKE_TOKEN
							secret: permanently revoke any published key (service compromise, abuse response). The
							token is kept in memory for this session only — never stored, never logged.
						</p>
						<div className="grid gap-3 sm:grid-cols-2">
							<div className="space-y-1.5">
								<Label htmlFor="admin-token">Admin token</Label>
								<Input
									id="admin-token"
									type="password"
									value={token}
									onChange={(e) => setToken(e.target.value)}
									autoComplete="off"
									className="font-mono text-xs"
									data-testid="admin-token"
								/>
							</div>
							<div className="space-y-1.5">
								<Label htmlFor="admin-fpr">Fingerprint</Label>
								<Input
									id="admin-fpr"
									value={fpr}
									onChange={(e) => setFpr(e.target.value)}
									placeholder="40 hex characters"
									autoComplete="off"
									className="font-mono text-xs"
									data-testid="admin-fpr"
								/>
							</div>
						</div>
						<div className="space-y-1.5">
							<Label htmlFor="admin-reason">Reason (optional, shown on the revoked record)</Label>
							<Input
								id="admin-reason"
								value={reason}
								onChange={(e) => setReason(e.target.value)}
								maxLength={200}
								autoComplete="off"
								className="text-xs"
								data-testid="admin-reason"
							/>
						</div>
						<div className="flex flex-wrap items-center gap-2">
							<Button
								type="button"
								variant="destructive"
								size="sm"
								className="h-8 gap-1.5 px-3 text-xs"
								onClick={() => setConfirmOpen(true)}
								disabled={!canSubmit}
								data-testid="admin-submit"
							>
								<Trash2 aria-hidden="true" className="size-3.5" />
								Revoke key
							</Button>
							{status && (
								<p
									role="status"
									data-testid="admin-status"
									className={
										status.kind === "error"
											? "text-[11px] text-red-600 dark:text-red-400"
											: status.kind === "ok"
												? "text-[11px] text-emerald-700 dark:text-emerald-400"
												: "text-[11px] text-muted-foreground"
									}
								>
									{status.text}
								</p>
							)}
						</div>
					</div>
				)}
				<Dialog open={confirmOpen} onOpenChange={(o) => !o && setConfirmOpen(false)}>
					<DialogContent className="max-w-md">
						<DialogHeader>
							<DialogTitle className="text-base">Admin-revoke this key?</DialogTitle>
							<DialogDescription className="break-all text-xs">
								{formatFingerprint(fprClean)} — revocation is PERMANENT: the fingerprint can never
								be re-published, any escrowed private key is purged, and the record stays visible
								with a revoked marker. This action is attributed to the registry administrator.
							</DialogDescription>
						</DialogHeader>
						<DialogFooter className="gap-2">
							<Button
								type="button"
								variant="outline"
								size="sm"
								onClick={() => setConfirmOpen(false)}
							>
								Cancel
							</Button>
							<Button
								type="button"
								variant="destructive"
								size="sm"
								onClick={() => {
									setConfirmOpen(false);
									void handleSubmit();
								}}
								disabled={busy}
								className="gap-1.5"
								data-testid="admin-confirm"
							>
								{busy && <Loader2 aria-hidden="true" className="size-3.5 animate-spin" />}
								Revoke permanently
							</Button>
						</DialogFooter>
					</DialogContent>
				</Dialog>
			</CardContent>
		</Card>
	);
}
