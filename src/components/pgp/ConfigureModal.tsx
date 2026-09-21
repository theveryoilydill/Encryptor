"use client";

/**
 * "Your key" modal — key management for the configured identity.
 *
 * Simplified for the login-gate round (PR #25 review): the three setup
 * forms (Keybase login, manual paste, generation) moved to the new
 * "Login/Get your keys" gate (src/components/pgp/login/LoginView.tsx), so
 * this dialog is pure MANAGEMENT: identity card, key details, share QR,
 * downloads, quantum seal, and sign-out. Reachable only while a key is
 * configured (the header hides it on the gate).
 *
 * SECURITY (unchanged): only key METADATA and the ENCRYPTED armored private
 * key live in state/localStorage. The decrypted key and the passphrase are
 * never persisted.
 */
import { useState } from "react";
import { QRCodeSVG } from "qrcode.react";
import {
	ChevronDown,
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
import { formatFingerprint } from "@/lib/pgp/pgp";
import { type PrivateKeyConfig } from "@/components/pgp/contracts";
import { CopyButton } from "@/components/pgp/shared";
import {
	describeKeyDetails,
	describeSubkeyDetails,
	downloadKeyName,
	getKeyExpiryStatus,
} from "@/lib/pgp/key-details";
import { generateSealKeyPair, wrapSealSecret } from "@/lib/pgp/pq";
import { downloadBlob } from "@/lib/pgp/zip-bundle";
import { toast } from "@/hooks/use-toast";

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
								<div className="mt-1 flex items-start justify-between gap-2">
									<div className="min-w-0 break-all font-mono text-[11px] text-emerald-700 dark:text-emerald-400">
										{formatFingerprint(privateKey.info.fingerprint)}
									</div>
									{/* Fingerprints are shared out-of-band for verification — a one-tap
	copy beats hand-selecting monospace text. */}
									<CopyButton
										text={privateKey.info.fingerprint}
										label="Copy fingerprint"
										ariaLabel="Copy key fingerprint to clipboard"
									/>
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

					<p className="mt-3 text-[11px] leading-relaxed text-muted-foreground">
						To switch identities, clear this key — you’ll land on the "Login/Get your keys" screen,
						which offers the Encryptor Registry, Keybase, OpenPGP and Ubuntu keyservers, and local
						keys.
					</p>
				</div>
			</DialogContent>
		</Dialog>
	);
}
