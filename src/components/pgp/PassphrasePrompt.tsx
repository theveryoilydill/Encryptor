"use client";

/**
 * On-demand private-key decryption prompt.
 *
 * Ported verbatim from the original app (PassphrasePrompt in PgpApp.tsx):
 * when a tab operation needs the decrypted private key it awaits a promise;
 * this modal collects the password/passphrase, derives the key, and resolves
 * the promise with the openpgp PrivateKey object. The decrypted key exists
 * only in the resolver's scope and is cleared after the operation.
 *
 * SECURITY (unchanged): the passphrase is never stored and is cleared as soon
 * as this component unmounts. Keybase logins re-fetch the private key bundle
 * from Keybase each time.
 */
import { useCallback, useRef, useState } from "react";
import { Eye, EyeOff, KeyRound } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
	Dialog,
	DialogContent,
	DialogDescription,
	DialogHeader,
	DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { readKey, unlockPrivateKey, validateArmoredKey } from "@/lib/pgp/pgp";
import { PROXIES, type KeyRequestState, type PrivateKeyConfig } from "@/components/pgp/contracts";

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

export function PassphrasePrompt({
	config,
	request,
	onKeyUpdated,
}: {
	config: PrivateKeyConfig;
	request: KeyRequestState;
	onKeyUpdated: (cfg: PrivateKeyConfig) => void;
}) {
	const [passphrase, setPassphrase] = useState("");
	// Additive UX affordance: reveal/hide the passphrase input. Default stays
	// hidden (type="password"), exactly as before.
	const [showPassphrase, setShowPassphrase] = useState(false);
	const [busy, setBusy] = useState(false);
	const [stage, setStage] = useState("");
	const [error, setError] = useState<string | null>(null);
	// Guard so resolve/reject happen exactly once even if Escape fires both the
	// input handler and the Radix dismiss handler.
	const settledRef = useRef(false);

	const isKeybase = config.source === "keybase";
	const promptLabel = isKeybase ? "Keybase password" : "Passphrase";
	const promptPlaceholder = isKeybase
		? "Your Keybase account password"
		: "Passphrase for the private key";

	const handleCancel = useCallback(() => {
		if (settledRef.current) return;
		settledRef.current = true;
		request.reject(new Error("Cancelled by user"));
	}, [request]);

	const handleSubmit = useCallback(async () => {
		if (settledRef.current) return;
		setError(null);
		if (!passphrase) {
			setError(`Enter your ${promptLabel.toLowerCase()}.`);
			return;
		}
		setBusy(true);
		try {
			if (isKeybase) {
				setStage("Loading crypto libraries…");
				const { loginWithPassword } = await import("@/lib/pgp/keybase-auth");
				setStage("Fetching salt + deriving keys…");
				await new Promise((r) => setTimeout(r, 50));
				setStage("Generating PDPKA signatures…");
				await new Promise((r) => setTimeout(r, 50));
				setStage("Logging in to Keybase…");
				const { privateKey: decrypted } = await loginWithPassword(config.username!, passphrase, {
					getsaltUrl: PROXIES.getsaltProxy,
					loginUrl: PROXIES.loginProxy,
				});
				setStage("Decrypting private key…");

				const armored = decrypted.armor();
				const info = await validateArmoredKey(armored);
				if (info.ok && info.info) {
					const oldInfo = config.info;
					const newInfo = info.info;
					if (oldInfo.fingerprint !== newInfo.fingerprint || oldInfo.keyID !== newInfo.keyID) {
						onKeyUpdated({ ...config, info: newInfo });
					}
				}
				settledRef.current = true;
				request.resolve(decrypted);
			} else {
				if (!config.encryptedArmored) {
					throw new Error("No encrypted key found in configuration.");
				}
				setStage("Decrypting private key…");
				const key = await readKey(config.encryptedArmored);
				if (!key.isPrivate()) {
					throw new Error("Stored key is not a private key.");
				}
				const decrypted = await unlockPrivateKey(key as OpenPGP.PrivateKey, passphrase);
				settledRef.current = true;
				request.resolve(decrypted);
			}
		} catch (e) {
			setError((e as Error).message);
		} finally {
			setBusy(false);
			setStage("");
		}
	}, [passphrase, isKeybase, config, request, onKeyUpdated, promptLabel]);

	return (
		<Dialog
			open
			onOpenChange={(o) => {
				if (!o) handleCancel();
			}}
		>
			{/* overflow-hidden clips the header border-b to the rounded corners,
          matching ConfigureModal / ShortcutsDialog DialogContent classes.
          R11-b: only `sm:max-w-md` is set here — an unprefixed `max-w-md`
          would (via tailwind-merge) drop DialogContent's responsive
          max-w-[calc(100%-2rem)] and leave the dialog edge-to-edge below
          ~448px; the sm: variant keeps the base margin rule on mobile. */}
			<DialogContent className="gap-0 overflow-hidden p-0 sm:max-w-md">
				<DialogHeader className="border-b px-5 py-3.5">
					<DialogTitle className="text-base font-semibold">
						{isKeybase ? "Enter Keybase password" : "Enter passphrase"}
					</DialogTitle>
				</DialogHeader>
				<div className="px-5 py-4">
					<DialogDescription className="mb-3 text-xs">
						{isKeybase
							? "Your password is used to re-fetch and decrypt your private key from Keybase. It is never stored — only kept in RAM for this operation."
							: "Your passphrase decrypts the private key in memory. It is never stored and is cleared immediately after the operation."}
					</DialogDescription>
					<div className="space-y-2">
						<div className="relative">
							{/* Decorative leading icon; pointer-events-none keeps clicks on
                  the input. Input gains pl-9; all other classes unchanged. */}
							<KeyRound
								aria-hidden="true"
								className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground"
							/>
							<Input
								type={showPassphrase ? "text" : "password"}
								value={passphrase}
								onChange={(e) => setPassphrase(e.target.value)}
								onKeyDown={(e) => {
									if (e.key === "Enter" && !busy) handleSubmit();
									if (e.key === "Escape") handleCancel();
								}}
								placeholder={promptPlaceholder}
								aria-label={promptLabel}
								autoFocus
								autoComplete="off"
								className="min-h-11 pl-9 pr-10 sm:min-h-9"
								disabled={busy}
							/>
							{/* type="button" so it can never submit the dialog. */}
							<Button
								type="button"
								variant="ghost"
								size="icon"
								onClick={() => setShowPassphrase((v) => !v)}
								aria-label={showPassphrase ? "Hide passphrase" : "Show passphrase"}
								title={showPassphrase ? "Hide passphrase" : "Show passphrase"}
								disabled={busy}
								className="absolute right-1 top-1/2 size-8 -translate-y-1/2 text-muted-foreground transition-colors hover:text-[#0055dc] dark:hover:text-[#5e94ff]"
							>
								{showPassphrase ? (
									<EyeOff className="size-4" aria-hidden />
								) : (
									<Eye className="size-4" aria-hidden />
								)}
							</Button>
						</div>
						<FormError message={error} />
						{busy && stage && <p className="text-[11px] text-muted-foreground">{stage}</p>}
						<div className="flex gap-2 pt-1">
							<Button
								type="button"
								onClick={handleSubmit}
								disabled={busy}
								className="h-11 min-w-0 flex-1 bg-[#0055dc] text-white transition-colors duration-150 hover:bg-[#0046b8] press-effect sm:h-9"
							>
								{busy ? "Working…" : "Decrypt & continue"}
							</Button>
							<Button
								type="button"
								variant="ghost"
								onClick={handleCancel}
								disabled={busy}
								className="h-11 text-sm sm:h-9"
							>
								Cancel
							</Button>
						</div>
					</div>
				</div>
			</DialogContent>
		</Dialog>
	);
}
