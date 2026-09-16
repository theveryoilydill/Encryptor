"use client";

/**
 * "Your key" modal — the key/auth half of the old combined dialog.
 *
 * Three ways to get a private key, ported verbatim from the original app
 * (ConfigureModal + KeybaseLoginForm + ManualKeyForm + GenerateKeyForm in
 * PgpApp.tsx): Keybase password login, manual armored-key paste, and local
 * key generation. Only styling is modernized (shadcn Dialog + #0055dc accent).
 * APP preferences (editor, compression, auto sign, auto-lock, backups) live
 * in the dedicated SettingsDialog since round 11.
 *
 * SECURITY (unchanged): only key METADATA and the ENCRYPTED armored private
 * key are handed to onSave. The decrypted key and the passphrase are never
 * persisted.
 */
import { useCallback, useEffect, useRef, useState } from "react";
import { QRCodeSVG } from "qrcode.react";
import {
	ChevronDown,
	Dice5,
	Download,
	History,
	Loader2,
	QrCode,
	ShieldHalf,
	TriangleAlert,
	X,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import {
	formatFingerprint,
	generateKeyPair,
	validateArmoredKey,
	type GeneratedKeyPair,
} from "@/lib/pgp/pgp";
import { PROXIES, type PrivateKeyConfig } from "@/components/pgp/contracts";
import { CopyButton } from "@/components/pgp/shared";
import { estimateStrength, generatePassphrase } from "@/lib/pgp/passphrase";
import {
	describeKeyDetails,
	describeSubkeyDetails,
	downloadKeyName,
	getKeyExpiryStatus,
} from "@/lib/pgp/key-details";
import {
	generateSealKeyPair,
	wrapSealSecret,
	wrapSealSecretAuto,
	type QuantumSealConfig,
} from "@/lib/pgp/pq";
import { downloadBlob } from "@/lib/pgp/zip-bundle";
import { toast } from "@/hooks/use-toast";

/** Local destructive-tinted error panel (same markup as shared ErrorBanner;
 *  kept local so this file only imports from the pinned allow-list). */
function FormError({ message }: { message: string | null }) {
	if (!message) return null;
	return (
		<div
			role="alert"
			className="rounded-lg border border-destructive/30 bg-destructive/10 px-3 py-2 text-xs text-destructive"
		>
			{message}
		</div>
	);
}

export function ConfigureModal({
	open,
	onOpenChange,
	privateKey,
	keyHistory,
	onRestoreKey,
	onForgetKey,
	onSave,
	onClear,
	requestDecryptedKey,
}: {
	open: boolean;
	onOpenChange: (open: boolean) => void;
	privateKey: PrivateKeyConfig | null;
	/** Previously configured keys (newest first) — one click switches back
	 *  without a fresh Keybase login / armor re-paste. */
	keyHistory: PrivateKeyConfig[];
	onRestoreKey: (cfg: PrivateKeyConfig) => void;
	onForgetKey: (fingerprint: string) => void;
	onSave: (cfg: PrivateKeyConfig) => void;
	onClear: () => void;
	/** On-demand key unlock — used ONLY by the "enable quantum seal" flow,
	 *  which wraps the new ML-KEM secret under the app passphrase. */
	requestDecryptedKey: () => Promise<{ key: OpenPGP.PrivateKey; passphrase: string | null }>;
}) {
	// Key-share QR (additive): toggles the inline QR block inside the Key
	// details disclosure. No state-reset effect on dialog close — the block
	// only exists while a key is configured AND the disclosure is expanded.
	const [showKeyQr, setShowKeyQr] = useState(false);
	// R8: QR payload mode. "keyserver" (default — behavior unchanged since the
	// QR shipped) encodes the keys.openpgp.org lookup URL; "fingerprint"
	// encodes the de-facto openpgp4fpr: fingerprint URI that OpenKeychain /
	// GPG Sync / aegir recognize as an import-and-verify target.
	const [qrMode, setQrMode] = useState<"keyserver" | "fingerprint">("keyserver");

	// Pure + cheap: rows for the "Key details" disclosure ([] → render nothing).
	const keyDetailRows = privateKey?.info ? describeKeyDetails(privateKey.info) : [];

	// Pure + cheap (R11): per-subkey rows for the Key details panel. [] for
	// configs stored before R11 (no runtime subkeyDetails field) → the legacy
	// "Subkeys: N" count row (inside describeKeyDetails) still renders for
	// them; when rows exist the list replaces the count row instead.
	const keySubkeyRows = privateKey?.info ? describeSubkeyDetails(privateKey.info) : [];

	// Key expiry awareness (additive): drives the Expired / Expiring badge next
	// to the "Currently configured" header. Null when there is no expiration —
	// the badge never renders for the "none" status.
	const keyExpiry = privateKey?.info ? getKeyExpiryStatus(privateKey.info.expirationTime) : null;

	// Share URL for the QR code: keys.openpgp.org public lookup by FULL
	// uppercase fingerprint (no spaces). null (missing fingerprint — should
	// not happen) → the Share affordance is hidden entirely.
	const keyShareUrl = privateKey?.info?.fingerprint
		? `https://keys.openpgp.org/search?q=0x${privateKey.info.fingerprint
				.replace(/\s+/g, "")
				.toUpperCase()}`
		: null;

	// R8: fingerprint URI for the QR's second payload mode. Both payloads are
	// derived from the same fingerprint, so fingerprintUri is non-null exactly
	// when keyShareUrl is; the render guard on keyShareUrl makes the `?? ""`
	// fallbacks unreachable, but QRCodeSVG/CopyButton want a plain string.
	const fingerprintUri = privateKey?.info?.fingerprint
		? `openpgp4fpr:${privateKey.info.fingerprint.replace(/\s+/g, "").toUpperCase()}`
		: null;
	const qrValue =
		qrMode === "keyserver" ? (keyShareUrl ?? "") : (fingerprintUri ?? keyShareUrl ?? "");

	// Additive backups: share the key's armored public part (info.armored) /
	// encrypted private part (encryptedArmored) without touching save/clear
	// logic. Same failure-toast pattern as CopyButton / DownloadButton.
	const handleDownloadPublic = () => {
		const armored = privateKey?.info?.armored;
		if (!armored || !privateKey) return;
		try {
			downloadBlob(
				new Blob([armored], { type: "text/plain;charset=utf-8" }),
				downloadKeyName("public", privateKey.label),
			);
			toast({ title: "Public key downloaded" });
		} catch (e) {
			toast({
				title: "Download failed",
				description: (e as Error)?.message || "Download unavailable",
				variant: "destructive",
			});
		}
	};

	const handleDownloadPrivate = () => {
		const armored = privateKey?.encryptedArmored;
		if (!armored || !privateKey) return;
		try {
			downloadBlob(
				new Blob([armored], { type: "text/plain;charset=utf-8" }),
				downloadKeyName("private", privateKey.label),
			);
			toast({ title: "Private key downloaded" });
		} catch (e) {
			toast({
				title: "Download failed",
				description: (e as Error)?.message || "Download unavailable",
				variant: "destructive",
			});
		}
	};

	// Quantum-seal onboarding for existing (pre-feature) keys: unlock the key
	// once — the prompt returns the passphrase — generate the ML-KEM pair,
	// wrap the secret half under that passphrase, and save. Keybase-sourced
	// configs never enter this flow (see the render guard above).
	const [sealBusy, setSealBusy] = useState(false);
	const handleEnableQuantumSeal = async () => {
		if (!privateKey?.encryptedArmored || sealBusy) return;
		setSealBusy(true);
		try {
			const { passphrase } = await requestDecryptedKey();
			if (!passphrase) {
				toast({
					title: "Passphrase required",
					description:
						"The quantum-seal secret is protected by your passphrase — enter it in the prompt and try again.",
					variant: "destructive",
				});
				return;
			}
			const sealPair = generateSealKeyPair();
			const pq = await wrapSealSecret(sealPair.publicKey, sealPair.secretKey, passphrase);
			onSave({ ...privateKey, pq });
			toast({
				title: "Quantum seal enabled",
				description: "ML-KEM-768 key pair attached to this identity.",
			});
		} catch {
			// Cancelled prompt or wrap failure — stay unsealed, no error spam.
		} finally {
			setSealBusy(false);
		}
	};

	return (
		<Dialog open={open} onOpenChange={onOpenChange}>
			<DialogContent
				className="max-h-[90vh] gap-0 overflow-hidden p-0 sm:max-w-lg"
				aria-describedby={undefined}
			>
				<DialogHeader className="border-b px-5 py-3.5">
					<DialogTitle className="text-base font-semibold">Your key</DialogTitle>
				</DialogHeader>

				<div className="scrollbar-thin max-h-[75vh] overflow-y-auto px-5 py-4">
					{privateKey && (
						<div className="mb-4 rounded-xl border border-emerald-200 bg-emerald-50 px-3 py-2.5 dark:border-emerald-900/60 dark:bg-emerald-950/30">
							<div className="mb-1 flex flex-wrap items-center gap-1.5 text-xs font-medium text-emerald-800 dark:text-emerald-300">
								Currently configured
								{/* Additive expiry badges: red when expired (with an explainer
                    tooltip), amber when < 30 days out. Never for "none". */}
								{keyExpiry?.status === "expired" && (
									<span
										title="This key has expired — you can still decrypt old messages but correspondents should not encrypt to it."
										className="inline-flex items-center gap-1 rounded-full bg-red-100 px-2 py-0.5 text-[11px] font-medium text-red-800 dark:bg-red-950/50 dark:text-red-300"
									>
										<TriangleAlert aria-hidden className="size-3" />
										Expired
									</span>
								)}
								{keyExpiry?.status === "expiring" && (
									<span className="inline-flex items-center gap-1 rounded-full bg-amber-100 px-2 py-0.5 text-[11px] font-medium text-amber-800 dark:bg-amber-950/50 dark:text-amber-300">
										<TriangleAlert aria-hidden className="size-3" />
										{keyExpiry.label}
									</span>
								)}
							</div>
							<div className="text-sm text-emerald-900 dark:text-emerald-200">
								{privateKey.source === "keybase"
									? `@${privateKey.username} (via Keybase login)`
									: privateKey.label}
							</div>
							{privateKey.info && (
								<div className="mt-1 break-all font-mono text-[11px] text-emerald-700 dark:text-emerald-400">
									{formatFingerprint(privateKey.info.fingerprint)}
								</div>
							)}
							{/* Additive: collapsible metadata grid fed by describeKeyDetails
                  (pure helper in lib/pgp/key-details.ts). Renders nothing when
                  there is no info / no rows. */}
							{keyDetailRows.length > 0 && (
								<details className="group mt-2">
									<summary className="inline-flex cursor-pointer select-none items-center gap-1 text-xs font-medium text-emerald-800 dark:text-emerald-300">
										Key details
										<ChevronDown
											aria-hidden
											className="size-3.5 transition-transform group-open:rotate-180"
										/>
									</summary>
									<dl className="mt-2 space-y-1.5">
										{keyDetailRows.map((row) => (
											<div
												key={row.label}
												className="flex items-baseline justify-between gap-3 text-[11px]"
											>
												<dt className="uppercase tracking-wide text-emerald-800/70 dark:text-emerald-300/70">
													{row.label}
												</dt>
												<dd
													className={`text-emerald-900 dark:text-emerald-200${
														row.mono ? " font-mono text-[11px]" : ""
													}${row.label === "Fingerprint" ? " break-all" : ""}`}
												>
													{row.value}
												</dd>
											</div>
										))}
									</dl>
									{/* R11: per-subkey list, below the metadata rows. Rendered
                      only when describeSubkeyDetails yields rows (fresh
                      describes attach subkeyDetails; pre-R11 configs don't
                      → silently absent, count row keeps back-compat). Same
                      spacing/text scale as the dl above; expiry coloring:
                      amber when expiring, red when expired, muted when the
                      subkey never expires. */}
									{keySubkeyRows.length > 0 && (
										<div className="mt-2">
											<div className="text-[11px] uppercase tracking-wide text-emerald-800/70 dark:text-emerald-300/70">
												Subkeys
											</div>
											<ul className="mt-1 space-y-1">
												{keySubkeyRows.map((s) => (
													<li
														key={s.keyID}
														className="flex items-baseline justify-between gap-3 text-[11px]"
													>
														<span
															className="shrink-0 font-mono text-emerald-900 dark:text-emerald-200"
															title={s.keyID}
														>
															{s.keyID}
														</span>
														<span className="flex flex-wrap items-baseline justify-end gap-x-2 text-right text-emerald-800/80 dark:text-emerald-300/80">
															<span>{s.algorithm}</span>
															<span>{s.created}</span>
															{s.expired ? (
																<span className="text-[11px] text-red-600 dark:text-red-400">
																	Expired
																</span>
															) : s.expiring ? (
																<span className="text-[11px] text-amber-600 dark:text-amber-400">
																	Expires {s.expires}
																</span>
															) : s.expires ? (
																<span>{s.expires}</span>
															) : (
																<span className="text-[11px] text-muted-foreground">
																	Never expires
																</span>
															)}
														</span>
													</li>
												))}
											</ul>
										</div>
									)}
									{/* Additive key-share QR: encodes the keys.openpgp.org
                      lookup URL (default) or the openpgp4fpr: fingerprint
                      URI (R8 mode toggle). Hidden entirely when no
                      fingerprint is available. White tile keeps the QR
                      scannable in dark mode; the payload is repeated as
                      text for screen readers / no-scan fallback. */}
									{keyShareUrl && (
										<>
											<button
												type="button"
												onClick={() => setShowKeyQr((v) => !v)}
												aria-expanded={showKeyQr}
												aria-controls="key-share-qr"
												className="mt-2 inline-flex min-h-11 items-center gap-1 text-[11px] font-medium text-emerald-800 transition-colors hover:underline sm:min-h-0 dark:text-emerald-300"
											>
												<QrCode aria-hidden className="size-3.5" />
												{showKeyQr ? "Hide QR code" : "Show QR code"}
											</button>
											{showKeyQr && (
												<div
													id="key-share-qr"
													className="mt-2 rounded-lg border border-border bg-white p-3"
												>
													{/* R8: payload mode switch — segmented pair on the
                              white tile; the active side gets the emerald
                              tint already used by the QR affordance. */}
													<div
														role="group"
														aria-label="QR code payload"
														className="mb-2 inline-flex gap-0.5 rounded-md border border-border bg-muted/40 p-0.5"
													>
														{(
															[
																["keyserver", "Keyserver link"],
																["fingerprint", "Fingerprint URI"],
															] as const
														).map(([mode, label]) => (
															<button
																key={mode}
																type="button"
																onClick={() => setQrMode(mode)}
																aria-pressed={qrMode === mode}
																className={`rounded px-2 py-1 text-[10px] font-medium transition-colors ${
																	qrMode === mode
																		? "bg-emerald-100 text-emerald-900"
																		: "text-muted-foreground hover:text-foreground"
																}`}
															>
																{label}
															</button>
														))}
													</div>
													<QRCodeSVG
														value={qrValue}
														size={140}
														bgColor="#FFFFFF"
														fgColor="#000000"
														level="M"
														aria-hidden="true"
													/>
													<div className="mt-2 flex items-center justify-between gap-2">
														<p className="text-[11px] leading-snug text-muted-foreground">
															{qrMode === "keyserver"
																? "Scan to look up this key on keys.openpgp.org"
																: "Scan to import + verify by fingerprint (OpenKeychain & friends)"}
															<span className="mt-0.5 block break-all font-mono text-[10px]">
																{qrValue}
															</span>
														</p>
														{/* R9: copy the lookup URL — reuses the shared
                                CopyButton (Copied! feedback + success/failure
                                toasts), same as "Copy public key" below.
                                R8: copies whichever payload is active. */}
														<CopyButton
															text={qrValue}
															label="Copy link"
															ariaLabel="Copy key lookup link"
														/>
													</div>
												</div>
											)}
										</>
									)}
								</details>
							)}
							<div className="mt-2 flex flex-wrap items-center gap-2">
								<button
									type="button"
									onClick={onClear}
									className="inline-flex min-h-11 items-center text-[11px] font-medium text-red-600 transition-colors hover:underline sm:min-h-0 dark:text-red-400"
								>
									Clear / log out
								</button>
								{/* Additive convenience: share the key's armored public part
                    (info.armored) without touching save/clear logic. Rendered
                    only when an armored representation is available. */}
								{privateKey.info?.armored && (
									<CopyButton
										text={privateKey.info.armored}
										label="Copy public key"
										ariaLabel="Copy public key to clipboard"
									/>
								)}
								{/* Additive backups (same outline-sm visual pattern as
                    CopyButton); rendered only when the source block exists. */}
								{privateKey.info?.armored && (
									<Button
										type="button"
										variant="outline"
										size="sm"
										onClick={handleDownloadPublic}
										className="h-11 gap-1.5 px-3 text-xs transition-colors sm:h-8"
										title="Download public key as .asc file"
										aria-label="Download public key as .asc file"
									>
										<Download className="size-3.5" aria-hidden />
										Download public key
									</Button>
								)}
								{privateKey.encryptedArmored && (
									<Button
										type="button"
										variant="outline"
										size="sm"
										onClick={handleDownloadPrivate}
										className="h-11 gap-1.5 px-3 text-xs transition-colors sm:h-8"
										title="Download encrypted private key as .asc file"
										aria-label="Download encrypted private key as .asc file"
									>
										<Download className="size-3.5" aria-hidden />
										Download private key
									</Button>
								)}
							</div>

							{/* Quantum seal (ML-KEM-768): offered for keys imported or
                configured before this feature (in-app generated keys already
                carry the pair). Unlocking the key yields the passphrase needed
                to wrap the new ML-KEM secret — the same prompt used by
                encrypt/decrypt, cache included. Keybase-sourced keys are
                excluded: their passphrase never stays in the app, so the
                sealed copy could never be opened later. */}
							{privateKey.encryptedArmored && !privateKey.pq && (
								<div className="mt-3 rounded-xl border border-violet-300/60 bg-violet-50/60 p-3 dark:border-violet-900/50 dark:bg-violet-950/20">
									<div className="flex flex-col justify-between gap-2 sm:flex-row sm:items-center">
										<div className="min-w-0">
											<p className="flex items-center gap-1.5 text-xs font-medium text-violet-900 dark:text-violet-300">
												<ShieldHalf aria-hidden className="size-3.5" />
												Quantum seal not configured
											</p>
											<p className="mt-0.5 text-[11px] leading-snug text-muted-foreground">
												Add an ML-KEM-768 (post-quantum) key to this identity so your archive copies
												get quantum-resistant protection.
											</p>
										</div>
										<Button
											type="button"
											variant="outline"
											size="sm"
											onClick={handleEnableQuantumSeal}
											disabled={sealBusy}
											className="h-11 shrink-0 gap-1.5 px-3 text-xs transition-colors sm:h-8"
											title="Generate an ML-KEM-768 key pair and protect it with your passphrase"
										>
											{sealBusy ? (
												<>
													<Loader2
														aria-hidden
														className="size-3.5 animate-spin motion-reduce:animate-none"
													/>
													Generating…
												</>
											) : (
												"Enable quantum seal"
											)}
										</Button>
									</div>
								</div>
							)}
							{privateKey.pq && (
								<p className="mt-2 flex items-center gap-1.5 text-[11px] text-muted-foreground">
									<ShieldHalf
										aria-hidden
										className="size-3.5 text-violet-600 dark:text-violet-400"
									/>
									Quantum seal: ML-KEM-768 pair attached (secret key wrapped under your passphrase).
								</p>
							)}
						</div>
					)}

					{keyHistory.length > 0 && (
						<div className="mb-4">
							<p className="mb-1 flex items-center gap-1.5 text-sm font-semibold">
								<History aria-hidden className="size-4 text-muted-foreground" />
								Previously configured keys
							</p>
							<p className="mb-2 text-[11px] leading-snug text-muted-foreground">
								Switch back with one click — no re-login, no re-pasting. Passphrases are still asked
								when needed and are never stored.
							</p>
							<ul className="space-y-1.5">
								{keyHistory.map((cfg) => {
									const fp = cfg.info?.fingerprint;
									return (
										<li
											key={fp ?? cfg.label}
											className="flex items-center justify-between gap-2 rounded-lg border border-border px-2.5 py-2"
										>
											<div className="min-w-0">
												<div className="flex items-center gap-1.5">
													<span
														className={`inline-flex shrink-0 items-center rounded-full px-1.5 py-0.5 text-[10px] font-medium ${
															cfg.source === "keybase"
																? "bg-[#0055dc]/10 text-[#0055dc] dark:bg-[#5e94ff]/15 dark:text-[#5e94ff]"
																: "bg-emerald-100 text-emerald-800 dark:bg-emerald-950/50 dark:text-emerald-300"
														}`}
													>
														{cfg.source === "keybase" ? "Keybase" : cfg.source}
													</span>
													<span className="truncate text-xs font-medium">{cfg.label}</span>
												</div>
												{fp && (
													<div className="mt-0.5 truncate font-mono text-[10px] text-muted-foreground">
														{formatFingerprint(fp)}
													</div>
												)}
											</div>
											<div className="flex shrink-0 items-center gap-1">
												<Button
													type="button"
													variant="outline"
													size="sm"
													onClick={() => onRestoreKey(cfg)}
													className="h-11 gap-1 px-3 text-xs transition-colors sm:h-8"
													title="Make this the active key"
												>
													Use this key
												</Button>
												<Button
													type="button"
													variant="ghost"
													size="icon"
													onClick={() => fp && onForgetKey(fp)}
													aria-label={`Forget ${cfg.label}`}
													title="Forget this key"
													className="size-11 text-muted-foreground transition-colors hover:text-foreground sm:size-8"
												>
													<X aria-hidden className="size-4" />
												</Button>
											</div>
										</li>
									);
								})}
							</ul>
						</div>
					)}

					<KeybaseLoginForm onLoaded={(cfg) => onSave(cfg)} />

					<hr className="my-4 border-border" />

					<ManualKeyForm onLoaded={(cfg) => onSave(cfg)} />

					<hr className="my-4 border-border" />

					<GenerateKeyForm onLoaded={(cfg) => onSave(cfg)} autoOpen={!privateKey} />
				</div>
			</DialogContent>
		</Dialog>
	);
}

/* ----------------------------- Keybase login form --------------------------- */

function KeybaseLoginForm({ onLoaded }: { onLoaded: (cfg: PrivateKeyConfig) => void }) {
	const [username, setUsername] = useState("");
	const [password, setPassword] = useState("");
	const [busy, setBusy] = useState(false);
	const [error, setError] = useState<string | null>(null);

	const handleLogin = useCallback(async () => {
		setError(null);
		if (!username.trim() || !password) {
			setError("Enter your Keybase username and password.");
			return;
		}
		setBusy(true);
		try {
			// Dynamically import keybase-auth (which in turn dynamically imports
			// kbpgp + keybase-proofs) only when the user actually clicks login.
			// The startup prewarm (PgpApp) usually has this chunk ready by now.
			const { loginWithPassword } = await import("@/lib/pgp/keybase-auth");
			// Same lazily-loaded chunk already exposes the armor helper
			// (keeps kbpgp/triplesec out of the initial bundle).
			const { privateKeyToArmored } = await import("@/lib/pgp/keybase-auth");

			// Yield to the browser so the spinner paints before the
			// synchronous scrypt + PDPKA signing work blocks the main thread.
			await new Promise((r) => setTimeout(r, 50));

			const { me, privateKey: decrypted } = await loginWithPassword(username, password, {
				getsaltUrl: PROXIES.getsaltProxy,
				loginUrl: PROXIES.loginProxy,
			});

			if (!me.private_key_bundle) {
				throw new Error(
					"Your Keybase account has no private key bundle. Generate one in the Keybase app first.",
				);
			}

			// Store the key ENCRYPTED under the Keybase password (the password
			// itself is never persisted). Previously only the username +
			// metadata were kept, which forced a full network re-login for
			// EVERY operation and made switching back from a local key to
			// Keybase painful. With the encrypted armor on board, the config
			// unlocks locally at operation time — same at-rest security as
			// manual/generated keys, offline-friendly, and the passphrase
			// prompt's session cache works too.
			const armoredEncrypted = await privateKeyToArmored(decrypted, password);
			const info = await validateArmoredKey(armoredEncrypted);
			if (!info.ok || !info.info) {
				throw new Error(info.error ?? "Decrypted key could not be parsed.");
			}

			onLoaded({
				source: "keybase",
				label: `@${me.username}`,
				username: me.username,
				encryptedArmored: armoredEncrypted,
				info: info.info,
			});
		} catch (e) {
			setError((e as Error).message);
		} finally {
			setBusy(false);
		}
	}, [username, password, onLoaded]);

	return (
		<div>
			<div className="mb-1 text-sm font-semibold">Log in with Keybase</div>
			<p className="mb-3 text-[11px] text-muted-foreground">
				Your password unlocks your Keybase key right here in the browser — it is never sent
				anywhere.
			</p>
			<div className="space-y-2">
				<Input
					type="text"
					value={username}
					onChange={(e) => setUsername(e.target.value)}
					placeholder="Keybase username"
					autoComplete="username"
					aria-label="Keybase username"
					className="min-h-11 sm:min-h-9"
					disabled={busy}
				/>
				<Input
					type="password"
					value={password}
					onChange={(e) => setPassword(e.target.value)}
					placeholder="Password"
					autoComplete="current-password"
					aria-label="Keybase password"
					className="min-h-11 sm:min-h-9"
					disabled={busy}
				/>
				<FormError message={error} />
				{busy && (
					<p
						role="status"
						className="inline-flex items-center gap-1.5 text-[11px] text-muted-foreground"
					>
						<Loader2
							aria-hidden="true"
							className="size-3 animate-spin motion-reduce:animate-none"
						/>
						Signing in…
					</p>
				)}
				<Button
					type="button"
					onClick={handleLogin}
					disabled={busy}
					className="h-11 w-full bg-[#0055dc] text-white transition-colors hover:bg-[#0046b8] sm:h-9"
				>
					{busy ? (
						<>
							<Loader2
								aria-hidden="true"
								className="size-4 animate-spin motion-reduce:animate-none"
							/>
							Working…
						</>
					) : (
						"Log in & load private key"
					)}
				</Button>
			</div>
		</div>
	);
}

/* ------------------------------ Manual key form ----------------------------- */

function ManualKeyForm({ onLoaded }: { onLoaded: (cfg: PrivateKeyConfig) => void }) {
	const [armored, setArmored] = useState("");
	const [passphrase, setPassphrase] = useState("");
	const [busy, setBusy] = useState(false);
	const [error, setError] = useState<string | null>(null);
	// Drag & drop depth counter for the paste target (same flicker-free
	// pattern as EncryptTab — enter/leave pairs across child elements).
	const [dragDepth, setDragDepth] = useState(0);
	const isOver = dragDepth > 0;

	const handleLoad = useCallback(async () => {
		setError(null);
		if (!armored.trim()) {
			setError("Paste your armored private key.");
			return;
		}
		setBusy(true);
		try {
			const v = await validateArmoredKey(armored.trim());
			if (!v.ok || !v.info) {
				setError(v.error ?? "Invalid key.");
				return;
			}
			if (!("isPrivate" in v.info) || !v.info.isPrivate) {
				setError("That's a public key. Paste a private key.");
				return;
			}
			// Store ONLY the ENCRYPTED armored key. The passphrase is NOT stored.
			onLoaded({
				source: "manual",
				label: v.info.userIDs[0]?.name || v.info.userIDs[0]?.email || "Pasted private key",
				encryptedArmored: armored.trim(),
				info: v.info,
			});
		} catch (e) {
			setError((e as Error).message);
		} finally {
			setBusy(false);
		}
	}, [armored, passphrase, onLoaded]);

	return (
		<div>
			<div className="mb-1 text-sm font-semibold">Paste a private key</div>
			<p className="mb-3 text-[11px] text-muted-foreground">
				Use this if you already have an armored PGP private key block.
			</p>
			<div className="space-y-2">
				{/* Drop target for key files (.asc) — the drop lands in the SAME
            state the textarea's onChange writes, so the paste flow and the
            save/validation logic below are untouched. No click-to-open. */}
				<div
					className="relative"
					onDragEnter={(e) => {
						if (!e.dataTransfer.types.includes("Files")) return;
						e.preventDefault();
						setDragDepth((d) => d + 1);
					}}
					onDragOver={(e) => {
						if (!e.dataTransfer.types.includes("Files")) return;
						e.preventDefault();
					}}
					onDragLeave={(e) => {
						if (!e.dataTransfer.types.includes("Files")) return;
						setDragDepth((d) => Math.max(0, d - 1));
					}}
					onDrop={(e) => {
						if (!e.dataTransfer.types.includes("Files")) return;
						e.preventDefault();
						setDragDepth(0);
						// Exactly one dropped file (kind "file") → read as text into the
						// existing textarea state.
						const dt = e.dataTransfer;
						let file: File | null = null;
						let fileCount = 0;
						for (let i = 0; i < dt.items.length; i++) {
							const item = dt.items[i];
							if (item?.kind === "file") {
								fileCount += 1;
								if (!file) file = item.getAsFile();
							}
						}
						if (fileCount !== 1 || !file) return;
						void file
							.text()
							.then((text) => setArmored(text))
							.catch(() => {
								// Unreadable file — keyboard paste flow remains available.
							});
					}}
				>
					<Textarea
						value={armored}
						onChange={(e) => setArmored(e.target.value)}
						placeholder={
							"-----BEGIN PGP PRIVATE KEY BLOCK-----\n...\n-----END PGP PRIVATE KEY BLOCK-----"
						}
						rows={5}
						className="field-sizing-fixed font-mono text-xs"
						aria-label="Paste your armored private key"
						spellCheck={false}
					/>
					{isOver && (
						<div
							aria-hidden
							className="pointer-events-none absolute inset-0 z-10 flex animate-fade-up items-center justify-center rounded-xl border-2 border-dashed border-[#0055dc] bg-[#0055dc]/5 dark:border-[#5e94ff] dark:bg-[#5e94ff]/10"
						>
							<span className="rounded-lg bg-background/95 px-4 py-2 text-xs font-medium text-[#0055dc] shadow-sm dark:text-[#5e94ff]">
								Drop your key file (.asc)
							</span>
						</div>
					)}
				</div>
				<Input
					type="password"
					value={passphrase}
					onChange={(e) => setPassphrase(e.target.value)}
					placeholder="Passphrase (if encrypted)"
					autoComplete="off"
					aria-label="Passphrase (if encrypted) — collected but never stored"
					className="min-h-11 sm:min-h-9"
				/>
				<FormError message={error} />
				<Button
					type="button"
					variant="outline"
					onClick={handleLoad}
					disabled={busy}
					className="h-11 w-full text-sm sm:h-9"
				>
					{busy ? "Loading…" : "Load private key"}
				</Button>
			</div>
		</div>
	);
}

/* --------------------------- Passphrase strength bar ------------------------ */

/** Tiny 5-segment strength meter for the generate-key passphrase field.
 *  Emerald for score 4, amber for 3, red for 0–2; label is sr-only. */
function PassphraseStrength({ password }: { password: string }) {
	const { score, label } = estimateStrength(password);
	const filledColor =
		score >= 4
			? "bg-emerald-500 dark:bg-emerald-400"
			: score === 3
				? "bg-amber-500 dark:bg-amber-400"
				: "bg-red-500 dark:bg-red-400";
	return (
		<div className="flex items-center gap-1.5">
			<div aria-hidden="true" className="flex flex-1 gap-1">
				{Array.from({ length: 5 }, (_, i) => (
					<span
						key={i}
						className={`h-[3px] flex-1 rounded-full ${i <= score ? filledColor : "bg-muted"}`}
					/>
				))}
			</div>
			<span className="sr-only">{`Passphrase strength: ${label}`}</span>
		</div>
	);
}

/* --------------------------- Backup & restore ------------------------------- */

/* ----------------------------- Generate key form ---------------------------- */

function GenerateKeyForm({
	onLoaded,
	autoOpen = false,
}: {
	onLoaded: (cfg: PrivateKeyConfig) => void;
	/** Open the collapsed <details> section on mount — used when no key is
	 *  configured yet, so the primary setup path is one glance away. */
	autoOpen?: boolean;
}) {
	const detailsRef = useRef<HTMLDetailsElement>(null);
	// Mount-only effect (not the `open` prop — that would fight the user's
	// manual collapse on every re-render). Re-runs when autoOpen flips, which
	// only happens when the key is added or removed.
	useEffect(() => {
		if (autoOpen && detailsRef.current) detailsRef.current.open = true;
	}, [autoOpen]);
	const [name, setName] = useState("");
	const [email, setEmail] = useState("");
	const [pass, setPass] = useState("");
	const [type, setType] = useState<"ecc" | "rsa">("ecc");
	const [curve, setCurve] = useState("ed25519Legacy");
	const [bits, setBits] = useState<2048 | 3072 | 4096>(4096);
	// Key expiration (R11): 0 = Never (default), fixed options carry their
	// seconds (1y/2y/3y), -1 = Custom… which reveals a days input.
	const [expiration, setExpiration] = useState(0);
	const [customDays, setCustomDays] = useState("");
	const [busy, setBusy] = useState(false);
	const [error, setError] = useState<string | null>(null);

	const customExpirationSelected = expiration === -1;
	const customDaysInt = Number.parseInt(customDays, 10);
	const customDaysValid =
		Number.isInteger(customDaysInt) && customDaysInt >= 1 && customDaysInt <= 3650;
	// 0 for Never, seconds for the fixed presets, days*86400 for a valid
	// custom value; undefined while the custom input is empty/invalid (the
	// Generate button is disabled in that state — this only avoids a stale
	// value reaching openpgp).
	const expirationSeconds = customExpirationSelected
		? customDaysValid
			? customDaysInt * 86400
			: undefined
		: expiration;

	const handleGenerate = useCallback(async () => {
		setError(null);
		setBusy(true);
		try {
			const kp: GeneratedKeyPair = await generateKeyPair({
				name: name || undefined,
				email: email || undefined,
				passphrase: pass || undefined,
				type,
				curve: type === "ecc" ? (curve as never) : undefined,
				rsaBits: type === "rsa" ? bits : undefined,
				expirationSeconds,
			});
			const label = name || email || (type === "ecc" ? "ECC key" : "RSA key");
			// Quantum-seal pair (ML-KEM-768): generated alongside every
			// in-app key. The public half is stored in the clear; the secret
			// half is wrapped under the chosen passphrase — or, for
			// passphrase-less keys, under a random device key stored in the
			// config (wrapSealSecretAuto; WebCrypto PBKDF2 rejects empty key
			// material, so the passphrase path cannot exist there). Without
			// this, an empty passphrase used to THROW and the key silently
			// lost its PQ layer at creation. Failure is non-fatal — the
			// classical key works without the PQ layer.
			let pq: QuantumSealConfig | undefined;
			try {
				const sealPair = generateSealKeyPair();
				// # Mr. AI Acting on s183173's Behalf
				pq = await wrapSealSecretAuto(sealPair.publicKey, sealPair.secretKey, pass);
			} catch {
				pq = undefined;
			}
			// Store ONLY the ENCRYPTED armored private key. The passphrase is
			// NOT stored — it will be re-requested at operation time.
			onLoaded({
				source: "generated",
				label,
				encryptedArmored: kp.privateKey,
				info: kp.info,
				...(pq ? { pq } : {}),
			});
		} catch (e) {
			setError((e as Error).message);
		} finally {
			setBusy(false);
		}
	}, [name, email, pass, type, curve, bits, expirationSeconds, onLoaded]);

	const selectClasses =
		"h-11 w-full rounded-md border border-input bg-transparent px-2.5 text-xs shadow-xs outline-none transition-[color,box-shadow] focus-visible:border-ring focus-visible:ring-[3px] focus-visible:ring-ring/50 disabled:cursor-not-allowed disabled:opacity-50 sm:h-9 dark:bg-input/30";

	return (
		<details ref={detailsRef} className="group">
			<summary className="inline-flex min-h-11 cursor-pointer select-none items-center text-sm font-semibold sm:min-h-0">
				Generate a new local key{" "}
				<span className="text-[11px] font-normal text-muted-foreground">(advanced)</span>
			</summary>
			<div className="mt-3 space-y-2">
				<div className="grid grid-cols-2 gap-2">
					<Input
						type="text"
						value={name}
						onChange={(e) => setName(e.target.value)}
						placeholder="Full name"
						aria-label="Full name"
						className="min-h-11 py-1.5 text-xs sm:min-h-9"
					/>
					<Input
						type="email"
						value={email}
						onChange={(e) => setEmail(e.target.value)}
						placeholder="email@example.com"
						aria-label="Email address"
						className="min-h-11 py-1.5 text-xs sm:min-h-9"
					/>
				</div>
				<div className="flex items-center gap-2">
					<Input
						type="password"
						value={pass}
						onChange={(e) => setPass(e.target.value)}
						placeholder="Passphrase (optional)"
						autoComplete="off"
						aria-label="Passphrase (optional)"
						className="min-h-11 py-1.5 text-xs sm:min-h-9"
					/>
					{/* Additive convenience: fill the field via the existing state setter
              so nothing else in the form flow changes. */}
					<Button
						type="button"
						variant="ghost"
						size="sm"
						onClick={() => setPass(generatePassphrase())}
						aria-label="Generate a strong passphrase"
						title="Generate a strong passphrase"
						className="size-8 shrink-0 text-muted-foreground transition-colors hover:text-[#0055dc] dark:hover:text-[#5e94ff]"
					>
						<Dice5 className="size-4" aria-hidden />
					</Button>
				</div>
				{pass.trim() !== "" && <PassphraseStrength password={pass} />}
				{/* Live unencrypted-key hint (round-12 product pass): while the
				    passphrase is empty, the form says so — a key generated here
				    would be stored UNENCRYPTED on this device. The moment a
				    passphrase exists (typed or dice-generated) this swaps to the
				    strength meter. */}
				{pass.trim() === "" && (
					<p
						role="note"
						className="flex items-start gap-1.5 text-[11px] leading-relaxed text-amber-600 dark:text-amber-400"
					>
						<TriangleAlert aria-hidden="true" className="mt-0.5 size-3.5 shrink-0" />
						<span>
							<span className="font-medium">
								No passphrase — this key will be stored unencrypted on this device.
							</span>{" "}
							Anyone with access to this browser profile can read everything it decrypts.
						</span>
					</p>
				)}
				<div className="grid grid-cols-2 gap-2 text-[11px]">
					<select
						value={type}
						onChange={(e) => setType(e.target.value as "ecc" | "rsa")}
						className={selectClasses}
						aria-label="Key type"
					>
						<option value="ecc">ECC (recommended)</option>
						<option value="rsa">RSA</option>
					</select>
					{type === "ecc" ? (
						<select
							value={curve}
							onChange={(e) => setCurve(e.target.value)}
							className={selectClasses}
							aria-label="ECC curve"
						>
							<option value="ed25519Legacy">ed25519</option>
							<option value="nistP256">NIST P-256</option>
							<option value="nistP384">NIST P-384</option>
							<option value="nistP521">NIST P-521</option>
							<option value="secp256k1">secp256k1</option>
						</select>
					) : (
						<select
							value={bits}
							onChange={(e) => setBits(Number(e.target.value) as 2048 | 3072 | 4096)}
							className={selectClasses}
							aria-label="RSA key size in bits"
						>
							<option value={2048}>2048</option>
							<option value={3072}>3072</option>
							<option value={4096}>4096</option>
						</select>
					)}
				</div>
				{/* Key expiration (R11): full-width select normally; when Custom… is
            chosen the select shares the row with an integer days input
            (1–3650). Plain conditional render — no animation needed. */}
				<div className="grid grid-cols-2 gap-2 text-[11px]">
					<select
						value={expiration}
						onChange={(e) => setExpiration(Number(e.target.value))}
						className={`${selectClasses}${customExpirationSelected ? "" : " col-span-2"}`}
						aria-label="Key expiration"
					>
						<option value={0}>Never expires</option>
						<option value={31536000}>1 year</option>
						<option value={63072000}>2 years</option>
						<option value={94608000}>3 years</option>
						<option value={-1}>Custom…</option>
					</select>
					{customExpirationSelected && (
						<Input
							type="number"
							inputMode="numeric"
							min={1}
							max={3650}
							step={1}
							value={customDays}
							onChange={(e) => setCustomDays(e.target.value)}
							placeholder="Days"
							aria-label="Custom expiration in days"
							className="min-h-11 py-1.5 text-xs sm:min-h-9"
						/>
					)}
				</div>
				<FormError message={error} />
				<Button
					type="button"
					variant="outline"
					onClick={handleGenerate}
					disabled={busy || (customExpirationSelected && !customDaysValid)}
					className="h-11 w-full text-sm sm:h-9"
				>
					{busy ? "Generating…" : "Generate key pair"}
				</Button>
			</div>
		</details>
	);
}
