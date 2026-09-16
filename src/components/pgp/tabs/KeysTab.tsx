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
import { useCallback, useState } from "react";
import {
	Download,
	Eye,
	EyeOff,
	Fingerprint,
	Globe,
	HardDrive,
	KeyRound,
	Loader2,
	RefreshCw,
	Search,
	ShieldCheck,
	Trash2,
	TriangleAlert,
} from "lucide-react";

import { Alert, AlertDescription } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Checkbox } from "@/components/ui/checkbox";
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
	type MyRegistryKey,
	RegistryClientError,
	forgetMyKey,
	listMyKeys,
	registryFetchEscrow,
	registryLookup,
	registryPublish,
	registryRevokeByToken,
	rememberMyKey,
	updateMyKey,
} from "@/lib/registry/client";
import { KEYBASE_USERNAME_RE } from "@/lib/constants";
import { lookupKeybaseUsersClient } from "@/lib/pgp/keybase";
import {
	formatFingerprint,
	generateKeyPair,
	validateArmoredKey,
	type AnyKeyInfo,
} from "@/lib/pgp/pgp";
import type { PrivateKeyConfig } from "@/components/pgp/contracts";
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
}

export function KeysTab({ onUseKey }: { onUseKey: (config: PrivateKeyConfig) => void }) {
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
			});
			refreshMyKeys();
		},
		[refreshMyKeys],
	);

	return (
		<div className="space-y-6" aria-label="Key registry">
			<div className="space-y-1.5">
				<h2 className="text-base font-semibold">Key registry</h2>
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
			<RegistryLookup />

			<MyKeysList keys={myKeys} onChanged={refreshMyKeys} />
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
			setError(e instanceof RegistryClientError ? e.message : (e as Error).message);
		} finally {
			setPublishing(false);
		}
	}, [escrow, generated, onPublished, onUseKey]);

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
					<div className="space-y-3 rounded-lg border bg-muted/30 p-3">
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
						<div className="flex flex-wrap items-center gap-2">
							<Button
								type="button"
								onClick={handlePublish}
								disabled={publishing}
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
			const result = await registryPublish({ armored: found.armored });
			onPublished(
				{
					fingerprint: result.fingerprint,
					keyId: result.keyId,
					emails: result.emails,
					replaced: result.replaced,
					revocationToken: result.revocationToken,
					escrowed: false,
				},
				`keybase.io/${found.username}`,
			);
		} catch (e) {
			setError(e instanceof RegistryClientError ? e.message : (e as Error).message);
		} finally {
			setPublishing(false);
		}
	}, [found, onPublished]);

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
						<Button
							type="button"
							onClick={handlePublish}
							disabled={publishing}
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
			setError(e instanceof RegistryClientError ? e.message : (e as Error).message);
		} finally {
			setPublishing(false);
		}
	}, [armored, escrow, onPublished, onUseKey, parsed]);

	const canPublish =
		parsed &&
		(!parsed.isPrivate || parsed.isDecrypted === false) &&
		(!escrow || parsed.isPrivate) &&
		!publishing;

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

function RegistryLookup() {
	const [query, setQuery] = useState("");
	const [loading, setLoading] = useState(false);
	const [results, setResults] = useState<
		| {
				fingerprint: string;
				armored: string;
				revoked: boolean;
				revokeReason: string | null;
				createdAt: number;
		  }[]
		| null
	>(null);
	const [error, setError] = useState<string | null>(null);

	const handleSearch = useCallback(async () => {
		const kind = detectQueryKind(query);
		if (!kind) {
			setError("Enter a 40-hex fingerprint, a 16-hex key ID, or an email address.");
			return;
		}
		setError(null);
		setLoading(true);
		try {
			const clean = query.trim().replace(/\s+/g, "").replace(/^0x/i, "").toUpperCase();
			const keys = await registryLookup(
				kind === "email"
					? { email: query.trim().toLowerCase() }
					: kind === "fingerprint"
						? { fingerprint: clean }
						: { keyId: clean },
			);
			setResults(keys);
		} catch (e) {
			setError(e instanceof RegistryClientError ? e.message : (e as Error).message);
		} finally {
			setLoading(false);
		}
	}, [query]);

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
					<p className="text-xs text-muted-foreground">No keys found for that query.</p>
				)}
				{results && results.length > 0 && (
					<ul className="max-h-64 space-y-2 overflow-y-auto pr-1">
						{results.map((k) => (
							<li key={k.fingerprint} className="rounded-lg border bg-muted/30 p-3 text-xs">
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
									<span className="ml-auto text-muted-foreground">
										{new Date(k.createdAt * 1000).toLocaleDateString()}
									</span>
								</div>
								<details className="mt-2">
									<summary className="cursor-pointer select-none text-[11px] text-[#0055dc] hover:underline dark:text-[#5e94ff]">
										Show armored public key
									</summary>
									<pre className="mt-1.5 max-h-40 overflow-auto rounded bg-background/80 p-2 font-mono text-[10px] leading-relaxed">
										{k.armored}
									</pre>
								</details>
							</li>
						))}
					</ul>
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
					: e instanceof RegistryClientError
						? e.message
						: message,
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

function MyKeysList({ keys, onChanged }: { keys: MyRegistryKey[]; onChanged: () => void }) {
	const [revealed, setRevealed] = useState<string | null>(null);
	const [revokeTarget, setRevokeTarget] = useState<MyRegistryKey | null>(null);
	const [busy, setBusy] = useState(false);
	const [error, setError] = useState<string | null>(null);

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
			setError(e instanceof RegistryClientError ? e.message : (e as Error).message);
		} finally {
			setBusy(false);
		}
	}, [onChanged, revokeTarget]);

	return (
		<Card>
			<CardContent className="space-y-3 p-4">
				<div className="flex items-center justify-between gap-2">
					<h3 className="text-sm font-medium">Keys published from this device</h3>
					{keys.length > 0 && (
						<Badge variant="outline" className="font-mono text-[10px]">
							{keys.length}
						</Badge>
					)}
				</div>
				{keys.length === 0 && (
					<p className="text-xs text-muted-foreground">
						Nothing yet — publish a key above and it will be listed here with its revocation token.
					</p>
				)}
				{error && (
					<Alert variant="destructive">
						<TriangleAlert aria-hidden="true" className="size-4" />
						<AlertDescription className="text-xs">{error}</AlertDescription>
					</Alert>
				)}
				<ul className="max-h-72 space-y-2 overflow-y-auto pr-1">
					{keys.map((k) => (
						<li key={k.fingerprint} className="rounded-lg border bg-muted/30 p-3 text-xs">
							<div className="flex flex-wrap items-center gap-x-3 gap-y-1">
								<span className="max-w-full truncate font-medium">{k.label}</span>
								{k.escrowed && (
									<Badge
										variant="outline"
										className="border-[#0055dc]/40 text-[10px] text-[#0055dc] dark:border-[#5e94ff]/40 dark:text-[#5e94ff]"
									>
										escrowed
									</Badge>
								)}
								<span className="ml-auto text-muted-foreground">
									{new Date(k.publishedAt).toLocaleDateString()}
								</span>
							</div>
							<p className="mt-1 font-mono text-[11px] text-muted-foreground">
								{formatFingerprint(k.fingerprint)}
							</p>
							<div className="mt-2 flex flex-wrap items-center gap-1.5">
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
