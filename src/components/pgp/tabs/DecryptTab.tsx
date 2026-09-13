"use client";

/**
 * Decrypt tab: paste an encrypted message and it decrypts as you type —
 * no Decrypt button. Signatures are verified automatically, and attached
 * files are extracted BELOW the decrypted message (images open in a
 * full-size viewer when clicking the file name or thumbnail). The armored
 * input is never echoed back as an output block.
 *
 * # Mr. AI Acting on s183173's Behalf
 */
import { useCallback, useEffect, useRef, useState } from "react";

import { Download, Loader2, Lock, LockKeyholeOpen, LockOpen, WandSparkles, X } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import {
	CopyButton,
	DecryptedMessageView,
	ErrorBanner,
	FileDownloadList,
	SignerBadges,
	ZipDownloadButton,
} from "@/components/pgp/shared";
import type { PrivateKeyConfig, SignatureInfo } from "@/components/pgp/contracts";
import { PROXIES } from "@/components/pgp/contracts";
import {
	decryptAndAutoVerify,
	describeEncryptedMessage,
	listPrivateKeyIds,
	type EncryptedMessageMeta,
} from "@/lib/pgp/pgp";
import { parseDecryptedPlaintext, type EnvelopeFile } from "@/lib/pgp/envelope";
import {
	isQuantumSealed,
	parseSealedArmor,
	unwrapSealSecret,
	unsealWithSecretKey,
} from "@/lib/pgp/pq";
import { fetchKeysFromAllSourcesWithLocal } from "@/lib/pgp/key-lookup";
import { InputHint, detectPgpBlock } from "@/components/pgp/InputHint";
import { describeFixes, findArmorIssues, repairArmor, type ArmorFix } from "@/lib/pgp/armor-repair";
import { AsciiDropOverlay, useAsciiTextDrop } from "@/components/pgp/ascii-drop";

/** Debounce before auto-decrypting a pasted/typed message (ms). */
const AUTO_DECRYPT_DEBOUNCE_MS = 600;

export function DecryptTab({
	privateKey,
	requestDecryptedKey,
}: {
	privateKey: PrivateKeyConfig | null;
	requestDecryptedKey: () => Promise<{ key: OpenPGP.PrivateKey; passphrase: string | null }>;
}) {
	const [armored, setArmored] = useState("");
	const [output, setOutput] = useState<{
		plaintext: string;
		files: EnvelopeFile[];
		signatures: SignatureInfo[];
	} | null>(null);
	const [busy, setBusy] = useState(false);
	const [error, setError] = useState<string | null>(null);
	// Hidden toggle: when true, shows the raw decrypted text (with markers)
	// instead of the rendered view. Defaults to false — an advanced toggle,
	// visually de-emphasized (small, muted text).
	const [showRaw, setShowRaw] = useState(false);
	// Smart-input hint dismissal, keyed to the exact input content: clearing
	// the textarea (or pasting different content) re-arms the hint without
	// needing a state-reset effect.
	const [hintDismissedFor, setHintDismissedFor] = useState<string | null>(null);
	// Staleness counter for auto-decrypt runs: only the run launched for the
	// CURRENT input may apply its result.
	const runIdRef = useRef(0);
	// Armor-repair banner state: what the last repair fixed (transient
	// notice, cleared as soon as the input changes again) + a dismissal
	// keyed to the input, mirroring the hint-dismissal pattern above.
	const [repairedWith, setRepairedWith] = useState<ArmorFix[] | null>(null);
	const [repairDismissedFor, setRepairDismissedFor] = useState<string | null>(null);

	// Drag & drop: load a .asc armor file onto the input card. Shared hook
	// (ascii-drop.tsx) sniffs for a PGP armor header; a successful load also
	// clears any stale error banner.
	const { dragDepth, dropProps } = useAsciiTextDrop({
		onText: (text) => {
			setArmored(text);
			setError(null);
		},
		onError: (message) => setError(message),
	});

	// Message metadata strip: how many recipient keys the pasted block is
	// encrypted to, and with which public-key algorithms — parsed WITHOUT any
	// secret material (PKESK packet headers only). Cached per input using the
	// repo's render-time state-adjustment pattern; gated by detectPgpBlock so
	// openpgp parsing only runs for plausible PGP MESSAGE blocks.
	const [metaState, setMetaState] = useState<{ for: string; meta: EncryptedMessageMeta | null }>(
		() => ({ for: "", meta: null }),
	);
	if (metaState.for !== armored) {
		setMetaState({ for: armored, meta: null });
		const metaInput = armored;
		if (detectPgpBlock(metaInput) === "encrypted") {
			void describeEncryptedMessage(metaInput)
				.then((meta) => {
					setMetaState((prev) => (prev.for === metaInput ? { ...prev, meta } : prev));
				})
				.catch(() => {
					// describeEncryptedMessage is null-on-error by contract.
				});
		}
	}
	const messageMeta = metaState.for === armored ? metaState.meta : null;

	// "Encrypted to me" pre-check (R10): collect every key ID of the user's
	// own key (primary + subkeys — the PKESK headers carry the encryption
	// SUBKEY's id, so the primary id alone never matches a modern key).
	// Reads the armored private key WITHOUT decrypting it; recomputed only
	// when the configured key changes. Best-effort: parse failure → empty
	// list → the chip simply never shows.
	const ownArmored = privateKey?.encryptedArmored ?? null;
	const [ownKeyIds, setOwnKeyIds] = useState<string[]>([]);
	useEffect(() => {
		let cancelled = false;
		if (!ownArmored) {
			setOwnKeyIds([]);
			return;
		}
		void listPrivateKeyIds(ownArmored).then((ids) => {
			if (!cancelled) setOwnKeyIds(ids ?? []);
		});
		return () => {
			cancelled = true;
		};
	}, [ownArmored]);
	// True when at least one PKESK recipient id is one of ours — shown as a
	// quiet emerald chip so the user knows decryption will work BEFORE the
	// passphrase prompt appears.
	const includesMine =
		messageMeta !== null &&
		ownKeyIds.length > 0 &&
		messageMeta.recipientKeyIDs.some((id) => ownKeyIds.includes(id));

	const runDecrypt = useCallback(
		async (input: string, myRunId: number) => {
			setError(null);
			setOutput(null);
			if (!input.trim()) return;
			if (!privateKey) {
				setError("Configure your private key first (top-right button).");
				return;
			}
			setBusy(true);
			try {
				// Request the decrypted key — shows the passphrase prompt. The key
				// exists only in this local variable and is cleared after. The
				// passphrase rides along for the quantum-seal unseal path.
				const { key: decryptedKey, passphrase } = await requestDecryptedKey();
				if (runIdRef.current !== myRunId) return; // superseded mid-prompt

				// Quantum-sealed input: strip the ML-KEM-768 outer layer first.
				// Needs the SAME passphrase (it unwraps the ML-KEM secret from the
				// key config) — a wrong passphrase surfaces as a friendly error.
				let classicalInput = input;
				if (isQuantumSealed(input)) {
					if (!privateKey?.pq) {
						throw new Error(
							"This message has a quantum-sealed copy, but your configured key has no quantum-seal key. Open it with the key that created it.",
						);
					}
					if (!passphrase) {
						throw new Error(
							"The quantum-sealed layer needs your passphrase (the one that protects this key), not just the key — enter it in the prompt and try again.",
						);
					}
					const sealSecret = await unwrapSealSecret(privateKey.pq, passphrase);
					if (runIdRef.current !== myRunId) return;
					classicalInput = await unsealWithSecretKey(parseSealedArmor(input), sealSecret);
					if (runIdRef.current !== myRunId) return;
				}

				// Pass the PrivateKey object directly to avoid re-armoring +
				// re-parsing, which can lose key material for Keybase P3SKB keys.
				const result = await decryptAndAutoVerify(
					{
						armoredMessage: classicalInput,
						decryptionPrivateKey: decryptedKey,
						verificationPublicKeys: [],
					},
					async (keyIDs) =>
						// Verification keys: remote keyserver lookup + local self-signer
						// recognition (shared one-liner with the Verify tab).
						fetchKeysFromAllSourcesWithLocal(
							keyIDs,
							PROXIES.fetchkeyProxy,
							PROXIES.fetchkeyOpgProxy,
							privateKey
								? {
										encryptedArmored: privateKey.encryptedArmored,
										label: privateKey.label,
									}
								: null,
						),
				);
				if (runIdRef.current !== myRunId) return; // input changed meanwhile

				// Detect whether the decrypted plaintext is an envelope (text +
				// files) or a plain-text message from an older client.
				const parsed = parseDecryptedPlaintext(result.plaintext);
				setOutput({
					plaintext: parsed.kind === "envelope" ? parsed.envelope.text : parsed.text,
					files: parsed.kind === "envelope" ? parsed.envelope.files : [],
					signatures: result.signatures,
				});
			} catch (e) {
				if (runIdRef.current !== myRunId) return;
				setError((e as Error).message);
			} finally {
				if (runIdRef.current === myRunId) setBusy(false);
			}
		},
		[privateKey, requestDecryptedKey],
	);

	// Auto-decrypt: when the text settles (debounce) and parses as an
	// encrypted message, decrypt it. Replaces the old Decrypt/Re-decrypt
	// button entirely. Quantum-sealed blocks (BEGIN ENCRYPTOR
	// QUANTUM-SEALED) trigger the same flow — runDecrypt strips the ML-KEM
	// layer before the classical decrypt.
	useEffect(() => {
		if (!armored.trim()) {
			runIdRef.current += 1; // invalidate any in-flight run
			setBusy(false);
			setOutput(null);
			setError(null);
			return;
		}
		if (detectPgpBlock(armored) !== "encrypted" && !isQuantumSealed(armored)) {
			// Not a (complete) encrypted message yet — wait for more input.
			runIdRef.current += 1;
			setBusy(false);
			return;
		}
		const myRunId = ++runIdRef.current;
		const timer = setTimeout(() => {
			void runDecrypt(armored, myRunId);
		}, AUTO_DECRYPT_DEBOUNCE_MS);
		return () => {
			clearTimeout(timer);
		};
	}, [armored, runDecrypt]);

	// Cheap substring detection computed during render (no effect needed).
	// Hints never appear for empty input, nor when the text already looks like
	// a normal encrypted message. Dismissal is keyed to the input text, so
	// clearing the field re-arms the hint.
	const detectedBlock = detectPgpBlock(armored);
	const showDecryptHint =
		armored.trim() !== "" &&
		detectedBlock !== null &&
		detectedBlock !== "encrypted" &&
		hintDismissedFor !== armored;

	// Armor damage detection (cheap, render-time, same pattern as
	// detectPgpBlock): offer the one-click repair only when the pasted
	// block shows real mangling. Dismissal is keyed to the input.
	const armorIssues = findArmorIssues(armored);
	const showRepairHint = armorIssues.length > 0 && repairDismissedFor !== armored && !busy;

	const applyRepair = useCallback(() => {
		const result = repairArmor(armored);
		if (!result) {
			setError(
				"Couldn't repair this block — it looks truncated (no END marker), so the ciphertext itself is incomplete.",
			);
			return;
		}
		setArmored(result.text);
		setRepairedWith(result.fixes);
		setError(null);
		// No success toast needed: the repaired text re-enters the normal
		// auto-decrypt flow, so the result speaks for itself.
	}, [armored]);

	const reset = useCallback(() => {
		runIdRef.current += 1;
		setArmored("");
		setOutput(null);
		setError(null);
		setBusy(false);
		setShowRaw(false);
	}, []);

	return (
		<section className="space-y-6">
			{/* Input card doubles as a .asc drop target: relative + drop props +
          overlay (aria-hidden, pointer-events-none) — the textarea and paste
          path are untouched. */}
			<div
				className="relative rounded-xl border border-border bg-card p-4 shadow-sm sm:p-6"
				{...dropProps}
			>
				<AsciiDropOverlay active={dragDepth > 0} label="Drop to load message" />
				<div className="mb-1.5 flex items-center gap-2">
					<span
						aria-hidden="true"
						className="h-3.5 w-[3px] shrink-0 rounded-full bg-[#0055dc] dark:bg-[#5e94ff]"
					/>
					<Label className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
						Encrypted message
					</Label>
					{/* Metadata strip: shown only while the input parses as an
              encrypted message; renders nothing otherwise. */}
					{messageMeta && (
						<span className="ml-auto inline-flex items-center gap-1 text-[11px] text-muted-foreground">
							<Lock aria-hidden="true" className="size-3.5" />
							Encrypted to {messageMeta.recipientKeyCount}{" "}
							{messageMeta.recipientKeyCount === 1 ? "key" : "keys"}
							{messageMeta.publicKeyAlgorithms.length > 0 && (
								<span> · {messageMeta.publicKeyAlgorithms.join(", ")}</span>
							)}
							{/* "Yours included" chip (R10): one of the PKESK recipient ids
                  matches this key — quiet emerald, same pill family as the
                  signer badges' "verified" tint. title + sr-only text keep
                  the meaning available to screen readers. */}
							{includesMine && (
								<span
									className="ml-0.5 inline-flex items-center gap-1 rounded-full border border-emerald-300/70 bg-emerald-50 px-1.5 py-px text-[10px] font-medium text-emerald-700 dark:border-emerald-900/60 dark:bg-emerald-950/40 dark:text-emerald-300"
									title="One of the recipient keys matches your configured key — decryption should succeed"
								>
									<LockOpen aria-hidden="true" className="size-3" />
									yours included
									<span className="sr-only">
										One of the recipient keys matches your configured key
									</span>
								</span>
							)}
						</span>
					)}
				</div>
				{!armored.trim() && (
					<div className="animate-fade-up mb-3 flex flex-col items-center justify-center rounded-xl border-2 border-dashed border-border bg-muted/30 p-6 text-center sm:p-8">
						<div className="grid size-12 place-items-center rounded-full bg-[#0055dc]/10 dark:bg-[#5e94ff]/10">
							<LockKeyholeOpen
								aria-hidden="true"
								className="size-7 text-[#0055dc] dark:text-[#5e94ff]"
							/>
						</div>
						<p className="mt-3 text-sm font-medium">
							Paste an encrypted message, or drop a .asc file
						</p>
					</div>
				)}
				<Textarea
					value={armored}
					onChange={(e) => {
						setRepairedWith(null);
						// Any new input invalidates everything from the previous input —
						// without this, a failed repair / stale decrypt error — WORSE, the
						// PREVIOUS MESSAGE'S plaintext — sticks around when the new text
						// never reaches the auto-decrypt path (unrecognized/partial input).
						setError(null);
						setOutput(null);
						setArmored(e.target.value);
					}}
					placeholder={"-----BEGIN PGP MESSAGE-----\n...\n-----END PGP MESSAGE-----"}
					rows={10}
					spellCheck={false}
					className="text-xs leading-relaxed field-sizing-fixed bg-background dark:bg-input/20"
				/>
				{busy && (
					<p className="mt-1.5 inline-flex items-center gap-1.5 text-[11px] text-muted-foreground">
						<Loader2 aria-hidden="true" className="size-3 animate-spin" />
						Decrypting…
					</p>
				)}
				{showDecryptHint && detectedBlock && (
					<InputHint
						tone={detectedBlock === "signed" ? "info" : "amber"}
						onDismiss={() => setHintDismissedFor(armored)}
					>
						{detectedBlock === "signed"
							? "This looks like a signed (not encrypted) message. The Verify tab is designed for that."
							: "This looks like a PGP key rather than an encrypted message. Keys are managed in the key configuration dialog."}
					</InputHint>
				)}
				{showRepairHint && (
					<div
						role="status"
						className="mt-2 flex animate-fade-up items-start gap-2 rounded-lg border border-amber-300/50 bg-amber-50 px-3 py-2 text-xs text-amber-800 dark:border-amber-500/30 dark:bg-amber-950/30 dark:text-amber-300"
					>
						<WandSparkles aria-hidden="true" className="mt-0.5 size-3.5 shrink-0" />
						<div className="flex-1">
							<p className="leading-relaxed">
								This message was mangled on its way here ({describeFixes(armorIssues)}) — common
								with email forwarding and copy/paste.
							</p>
							<Button
								type="button"
								size="sm"
								variant="outline"
								onClick={applyRepair}
								className="press-effect mt-1.5 h-7 gap-1.5 rounded-lg border-amber-400/60 bg-white/60 px-2 text-[11px] text-amber-900 hover:bg-amber-100/80 focus-visible:ring-2 focus-visible:ring-amber-500/40 dark:border-amber-500/40 dark:bg-amber-950/40 dark:text-amber-200 dark:hover:bg-amber-900/40"
							>
								<WandSparkles aria-hidden="true" className="size-3" />
								Repair armor
							</Button>
						</div>
						<button
							type="button"
							onClick={() => setRepairDismissedFor(armored)}
							aria-label="Dismiss repair suggestion"
							title="Dismiss hint"
							className="flex size-6 shrink-0 items-center justify-center rounded transition-colors hover:bg-black/5 dark:hover:bg-white/10"
						>
							<X aria-hidden="true" className="size-3.5" />
						</button>
					</div>
				)}
				{repairedWith && !showRepairHint && (
					<div
						role="status"
						className="mt-2 flex animate-fade-up items-start gap-2 rounded-lg border border-emerald-300/70 bg-emerald-50 px-3 py-2 text-xs text-emerald-800 dark:border-emerald-900/60 dark:bg-emerald-950/40 dark:text-emerald-300"
					>
						<WandSparkles aria-hidden="true" className="mt-0.5 size-3.5 shrink-0" />
						<div className="flex-1">
							<p>Armor repaired: {describeFixes(repairedWith)}.</p>
						</div>
					</div>
				)}
			</div>

			{error && <ErrorBanner message={error} />}

			{output && (
				<div className="space-y-6">
					{output.signatures.length > 0 && <SignerBadges signatures={output.signatures} />}

					{/* The decrypted message itself — files are listed BELOW it. */}
					{/* result-enter: one-time success ring when the panel first
              appears; reduced-motion gated in globals.css. */}
					<div className="result-enter">
						{/* R10: live-region cue mirroring OutputBlock's — the visual
                labels here are decorative/muted, so announce completion. */}
						<span role="status" className="sr-only">
							Message decrypted
							{output.signatures.length > 0 ? ", signature checked" : ""}
						</span>
						<div className="flex items-center justify-between mb-1">
							<div className="flex items-center gap-2">
								<span
									aria-hidden="true"
									className="h-3.5 w-[3px] shrink-0 rounded-full bg-[#0055dc] dark:bg-[#5e94ff]"
								/>
								<Label className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
									Decrypted message
								</Label>
							</div>
							<button
								type="button"
								onClick={() => setShowRaw((v) => !v)}
								className="text-[10px] text-muted-foreground hover:text-foreground underline-offset-2 hover:underline transition-colors duration-150"
								title="Toggle between rendered view and raw text (advanced)"
							>
								{showRaw ? "Show rendered" : "Show raw text"}
							</button>
						</div>
						{showRaw ? (
							<Textarea
								value={output.plaintext}
								readOnly
								rows={10}
								spellCheck={false}
								className="text-xs leading-relaxed field-sizing-fixed bg-muted/40"
							/>
						) : (
							<div className="rounded-xl border border-border bg-card p-4 shadow-sm min-h-[100px]">
								<DecryptedMessageView text={output.plaintext} files={output.files} />
							</div>
						)}
					</div>

					{/* Attached files — below the decrypted message, per the layout
              fix; images open the built-in viewer from their name/chip. */}
					{output.files.length > 0 && <FileDownloadList files={output.files} />}

					{/* Compact action row — the armored input is NOT echoed back as an
              output block anymore. */}
					<div className="flex flex-wrap gap-2">
						<CopyButton
							text={output.plaintext}
							label="Copy text"
							ariaLabel="Copy decrypted message text"
						/>
						<Button
							type="button"
							variant="outline"
							onClick={() => {
								// Save the decrypted message as a plain-text file (client-side
								// only — the blob never touches a server).
								const blob = new Blob([output.plaintext], {
									type: "text/plain;charset=utf-8",
								});
								const url = URL.createObjectURL(blob);
								const a = document.createElement("a");
								a.href = url;
								a.download = "decrypted-message.txt";
								a.click();
								URL.revokeObjectURL(url);
							}}
							className="h-11 gap-1.5 px-3 text-xs transition-colors sm:h-8"
							aria-label="Save decrypted message as a .txt file"
						>
							<Download className="size-3.5" aria-hidden />
							Save as .txt
						</Button>
						<ZipDownloadButton
							files={output.files}
							operation="decrypt"
							output={armored}
							signers={output.signatures}
						/>
						{armored && (
							<Button
								type="button"
								variant="outline"
								onClick={() => {
									// Nuke the encrypted input from memory, keep the result.
									setArmored("");
								}}
								className="h-11 px-3 text-xs transition-colors sm:h-8"
							>
								Nuke encrypted input
							</Button>
						)}
						<Button type="button" variant="ghost" onClick={reset} className="h-11 text-sm sm:h-9">
							Start over
						</Button>
					</div>
				</div>
			)}
		</section>
	);
}
