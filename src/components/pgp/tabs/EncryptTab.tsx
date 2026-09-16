"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { List, Maximize2, Minimize2, TriangleAlert } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { RecipientPicker } from "@/components/pgp/RecipientPicker";
import {
	AttachmentList,
	CopyButton,
	DownloadButton,
	ErrorBanner,
	InputSizeCounter,
	OutputBlock,
} from "@/components/pgp/shared";
import { MessageEditor } from "@/components/pgp/MessageEditor";
import type { PrivateKeyConfig, Recipient } from "@/components/pgp/contracts";
import { encryptAndSign, encryptMessage } from "@/lib/pgp/pgp";
import { sealForConfig } from "@/lib/pgp/pq";
import {
	buildPlaintextForEncryption,
	formatFileSize,
	readFileAsBase64,
	type EnvelopeFile,
} from "@/lib/pgp/envelope";
import { LIMITS } from "@/lib/constants";
import type { AppSettings } from "@/lib/pgp/settings";
import { InputHint, detectPgpBlock } from "@/components/pgp/InputHint";
import { getKeyExpiryStatus, parseLooseDate } from "@/lib/pgp/key-details";
import { useToast } from "@/hooks/use-toast";

/** GitHub-style anchor slug for a heading title: lowercase, strip every
 *  character that is not a letter, number, space or hyphen, then spaces
 *  become hyphens. Mirrors the anchors GitHub generates for its own
 *  headings, so TOC links keep working when the message is pasted into a
 *  GitHub issue, README or comment.
 *
 *  # Mr. AI Acting on s183173's Behalf
 */
function githubSlug(title: string): string {
	return title
		.toLowerCase()
		.replace(/[^\p{L}\p{N}\s-]/gu, "")
		.replace(/\s+/g, "-");
}

/** Build a GitHub-style table of contents from the composer's markdown:
 *  every ATX heading (`#` through `######`) becomes an indented
 *  `- [Title](#slug)` row (2 spaces of indent per level below h1).
 *  Returns "" when the message has no headings — the caller toasts
 *  instead of inserting an empty TOC. */
function buildTableOfContents(markdown: string): string {
	const rows: string[] = [];
	for (const line of markdown.split("\n")) {
		const match = /^(#{1,6})\s+(.*)$/.exec(line);
		if (!match) continue;
		const title = match[2].trim();
		rows.push(`${"  ".repeat(match[1].length - 1)}- [${title}](#${githubSlug(title)})`);
	}
	return rows.join("\n");
}

export function EncryptTab({
	privateKey,
	recipients,
	setRecipients,
	includeSelf,
	onIncludeSelfChange,
	requestDecryptedKey,
	settings,
}: {
	privateKey: PrivateKeyConfig | null;
	recipients: Recipient[];
	setRecipients: (updater: (prev: Recipient[]) => Recipient[]) => void;
	includeSelf: boolean;
	onIncludeSelfChange: (v: boolean) => void;
	requestDecryptedKey: () => Promise<{ key: OpenPGP.PrivateKey; passphrase: string | null }>;
	/** App preferences (compression + editor style) — owned by PgpApp so a
	 *  settings change re-renders the open tab immediately. */
	settings: AppSettings;
}) {
	const [plaintext, setPlaintext] = useState("");
	const [attachments, setAttachments] = useState<EnvelopeFile[]>([]);
	// Mirror of the attachment list for SYNCHRONOUS readers — the editor's
	// image-paste bridge must return the FINAL (deduped) filename in the same
	// tick it registers the file, but React state updates are async and the
	// updater function must stay pure. The ref is updated eagerly on every
	// mutation path and re-synced to the committed state after each render.
	const attachmentsRef = useRef<EnvelopeFile[]>(attachments);
	useEffect(() => {
		attachmentsRef.current = attachments;
	}, [attachments]);
	const [output, setOutput] = useState("");
	// Quantum-sealed copy of the LAST output (settings.pqSealedCopy + a key
	// with a quantum-seal pair): an ML-KEM-768 outer layer only the owner
	// can open. Empty string = no sealed copy for the current output.
	const [sealedCopy, setSealedCopy] = useState("");
	const [busy, setBusy] = useState(false);
	const [error, setError] = useState<string | null>(null);
	// Drag & drop depth counter (avoids flicker when crossing child elements).
	const [dragDepth, setDragDepth] = useState(0);
	// Smart-input hint dismissal, keyed to the exact message content: clearing
	// the textarea (or typing different content) re-arms the hint without
	// needing a state-reset effect.
	const [hintDismissedFor, setHintDismissedFor] = useState<string | null>(null);

	// Full-screen composer overlay ("blow up the editor"): when expanded, the
	// whole composer — editor + utility row — moves into a portal dialog
	// filling the viewport. The state lives HERE in the tab; the editor engine
	// simply re-mounts with the same value props, so text, files and
	// attachments survive expand AND collapse untouched.
	const [composerExpanded, setComposerExpanded] = useState(false);
	// Body scroll lock while the overlay is up; the previous inline value is
	// restored on cleanup (also fires if the tab unmounts mid-expanded).
	useEffect(() => {
		if (!composerExpanded) return;
		const prev = document.body.style.overflow;
		document.body.style.overflow = "hidden";
		return () => {
			document.body.style.overflow = prev;
		};
	}, [composerExpanded]);

	// Expiry pre-flight (R8): recipients whose key has an expired PRIMARY key.
	// Same detection the recipient chips' "Expired" badge uses
	// (getKeyExpiryStatus), so the banner and the badge can never disagree.
	// Deliberately NON-blocking: openpgp.js can still succeed when only the
	// primary is expired but a subkey remains valid — the banner warns, the
	// catch below maps the genuine failures to friendly guidance.
	const expiredRecipients = useMemo(
		() =>
			recipients.filter(
				(r) =>
					typeof r.expiresAt === "number" &&
					getKeyExpiryStatus(new Date(r.expiresAt))?.status === "expired",
			),
		[recipients],
	);

	// Derive the user's own public key from the configured private key.
	// Shown as a recipient chip when "Include me" is checked.
	const selfRecipient = useMemo<Recipient | null>(() => {
		if (!privateKey) return null;
		const info = privateKey.info;
		return {
			source: "local",
			label:
				privateKey.source === "keybase"
					? `@${privateKey.username} (you)`
					: `${privateKey.label} (you)`,
			armored: "", // not needed — we'll inject it directly in handleEncrypt
			fingerprint: info.fingerprint,
			keyID: info.keyID,
			algorithm: info.algorithm,
			expiresAt:
				// parseLooseDate (key-details.ts): the persisted config's
				// expirationTime is a Date right after configure but an ISO STRING
				// after a localStorage reload round-trip — calling .getTime()
				// directly on the string crashed the whole tab on load (R11 fix).
				// It also rejects non-Date/number garbage; a fresh Infinity (never
				// expiring) isn't a string/Date → null, matching the never-expires
				// posture of every other expiresAt consumer.
				parseLooseDate(info.expirationTime)?.getTime() ?? null,
		};
	}, [privateKey]);

	/** Read + store files, returning the stored entries (with unique names).
	 *  Shared by the add-files button/drop and the editor's image paste. */
	const addFilesReturning = useCallback(
		async (fileList: FileList | File[]): Promise<EnvelopeFile[]> => {
			const files = Array.from(fileList);
			const newOnes: EnvelopeFile[] = [];
			let sizeError: string | null = null;
			for (const f of files) {
				if (f.size > LIMITS.maxFileBytes) {
					sizeError = `"${f.name}" is ${formatFileSize(f.size)} — max ${LIMITS.maxFileLabel} per file.`;
					continue;
				}
				try {
					const data = await readFileAsBase64(f);
					newOnes.push({
						name: f.name || "unnamed",
						type: f.type || "application/octet-stream",
						data,
						size: f.size,
					});
				} catch (e) {
					sizeError = `Failed to read "${f.name}": ${(e as Error).message}`;
				}
			}
			if (newOnes.length > 0) {
				setAttachments((prev) => {
					// Deduplicate names so inline image markers always reference the
					// right attachment (same rule the old paste path used).
					const usedNames = new Set(prev.map((a) => a.name));
					for (const n of newOnes) {
						if (!usedNames.has(n.name)) {
							usedNames.add(n.name);
							continue;
						}
						const dot = n.name.lastIndexOf(".");
						let counter = 1;
						let unique = n.name;
						while (usedNames.has(unique)) {
							unique =
								dot > 0
									? `${n.name.slice(0, dot)}-${counter}${n.name.slice(dot)}`
									: `${n.name}-${counter}`;
							counter++;
						}
						usedNames.add(unique);
						n.name = unique;
					}
					return [...prev, ...newOnes];
				});
			}
			if (sizeError) setError(sizeError);
			return newOnes;
		},
		[],
	);

	const addFiles = useCallback(
		async (fileList: FileList | File[]) => {
			setError(null);
			if (Array.from(fileList).length === 0) return;
			await addFilesReturning(fileList);
		},
		[addFilesReturning],
	);

	/** Editor paste bridge: store a pasted image (as a data URL) as an
	 *  attachment and return the stored entry so the editor can reference it
	 *  with an envelope:// marker. Sync by contract — throws on read errors.
	 *
	 *  BUGFIX (was "VS Code is super broken"): this used to return the
	 *  PRE-dedupe name while the state updater stored the DEDUPED one, so
	 *  the second pasted image's marker pointed at the FIRST image's file —
	 *  recipients silently saw the wrong image (browser-verified). The
	 *  unique name is now computed against attachmentsRef BEFORE the state
	 *  update and the FINAL entry is returned. */
	const handleNewImageDataUrl = useCallback((dataUrl: string): EnvelopeFile => {
		// Parse "data:<mime>;base64,<data>".
		const match = /^data:([^;,]+);base64,([\s\S]*)$/.exec(dataUrl);
		if (!match) throw new Error("Unsupported image data URL.");
		const type = match[1];
		const data = match[2];
		const size = Math.floor(data.length * 0.75);
		if (size > LIMITS.maxFileBytes) {
			throw new Error(`Image is ${formatFileSize(size)} — max ${LIMITS.maxFileLabel}.`);
		}
		const ext = type.split("/")[1]?.replace("jpeg", "jpg") || "png";
		const baseName = `pasted-image.${ext}`;
		// Dedupe against the mirrored list (sync, no stale closure).
		const usedNames = new Set(attachmentsRef.current.map((a) => a.name));
		const dot = baseName.lastIndexOf(".");
		let unique = baseName;
		let counter = 1;
		while (usedNames.has(unique)) {
			unique =
				dot > 0
					? `${baseName.slice(0, dot)}-${counter}${baseName.slice(dot)}`
					: `${baseName}-${counter}`;
			counter++;
		}
		const stored: EnvelopeFile = { name: unique, type, data, size };
		// Eager mirror update so a same-tick follow-up paste sees this name.
		attachmentsRef.current = [...attachmentsRef.current, stored];
		// Guarded commit (idempotent under StrictMode double-invoke).
		setAttachments((prev) => (prev.some((a) => a.name === stored.name) ? prev : [...prev, stored]));
		return stored;
	}, []);

	// Orphan garbage collection (was "VS Code is super broken", part 2):
	// deleting an image out of the message used to leave its file attached —
	// it still got encrypted into the envelope (bloat + surprise files for
	// recipients, verified in the browser). Whenever the message text no
	// longer references an auto-named PASTED image, drop it. Files added via
	// "Add files" keep their original names and are NEVER touched here.
	useEffect(() => {
		const referenced = new Set<string>();
		const re = /!\[[^\]]*\]\(envelope:\/\/([^)\s]+)\)/g;
		for (const m of plaintext.matchAll(re)) {
			try {
				referenced.add(decodeURIComponent(m[1]));
			} catch {
				referenced.add(m[1]);
			}
		}
		setAttachments((prev) => {
			const kept = prev.filter(
				(a) => !/^pasted-image(-\d+)?\.[a-z0-9]+$/.test(a.name) || referenced.has(a.name),
			);
			return kept.length === prev.length ? prev : kept;
		});
	}, [plaintext]);

	const handleAddFiles = useCallback(
		(files: FileList | null) => {
			if (files) void addFiles(files);
		},
		[addFiles],
	);

	// "Insert table of contents" (round-12 editor pass): parse the CURRENT
	// composer markdown for ATX headings and PREPEND a GitHub-style TOC
	// (slug anchors, one blank line after). Heading-less messages get a
	// toast and are left completely untouched.
	const { toast } = useToast();
	const insertTableOfContents = useCallback(() => {
		const toc = buildTableOfContents(plaintext);
		if (!toc) {
			toast({ title: "No headings found — add some `#` headings first" });
			return;
		}
		setPlaintext(`${toc}\n\n${plaintext}`);
	}, [plaintext, toast]);

	const handleEncrypt = useCallback(async () => {
		setError(null);
		setOutput("");
		setSealedCopy("");
		if (!plaintext.trim() && attachments.length === 0) {
			setError("Enter a message to encrypt, or attach a file.");
			return;
		}
		const signing = settings.autoSign;
		const needsOwnKey = signing || includeSelf;
		if (needsOwnKey && !privateKey) {
			setError(
				signing
					? "Auto sign is on — configure your private key (top-right button) or turn signing off in Settings to encrypt without signing."
					: '"Include me" needs your configured key — configure it (top-right button) or untick "Include me".',
			);
			return;
		}
		// Recipient validation BEFORE the passphrase prompt (R10): openpgp would
		// surface this as a raw "no encryption keys" error mid-flight — catch it
		// early with actionable guidance instead.
		if (recipients.length === 0 && !(includeSelf && privateKey)) {
			setError(
				'No recipients — add at least one public key, or tick "Include me" so you can still decrypt what you send.',
			);
			return;
		}

		setBusy(true);
		try {
			// Request the decrypted key only when a signature or the self-copy
			// actually needs it (auto sign off + no include-me ⇒ no passphrase
			// prompt at all). The decrypted key exists only in this local
			// variable and is cleared when the function returns.
			let decryptedKey: OpenPGP.PrivateKey | null = null;
			if (needsOwnKey) {
				decryptedKey = (await requestDecryptedKey()).key;
			}

			// Build the recipient key list. If "include me" is checked, derive
			// the public key from the decrypted private key.
			const recipientKeys: string[] = recipients.map((r) => r.armored);
			if (includeSelf && decryptedKey) {
				try {
					const pubArmored = decryptedKey.toPublic().armor();
					recipientKeys.push(pubArmored);
				} catch {
					// skip self-inclusion on error
				}
			}

			// Wrap plaintext + attachments in the envelope wire format.
			const plaintextForEncryption = buildPlaintextForEncryption(plaintext, attachments);
			const compression = settings.compression === "off" ? "uncompressed" : settings.compression;

			let armored: string;
			if (signing && decryptedKey) {
				// Pass the PrivateKey object directly to avoid re-armoring +
				// re-parsing, which can lose key material for Keybase P3SKB keys.
				armored = await encryptAndSign({
					plaintext: plaintextForEncryption,
					recipientPublicKeys: recipientKeys,
					signerPrivateKey: decryptedKey,
					// User preference: compress by default, at maximum supported
					// compression; "off" maps to the explicit uncompressed preference.
					compression,
				});
			} else {
				armored = await encryptMessage({
					plaintext: plaintextForEncryption,
					recipientPublicKeys: recipientKeys,
					compression,
				});
			}

			// Quantum-sealed copy (opt-in): an ML-KEM-768 outer layer over the
			// armored output, sealed to the configured key's quantum-seal
			// public half. Needs no secret — sealing is passphrase-free.
			if (settings.pqSealedCopy && privateKey?.pq) {
				try {
					setSealedCopy(await sealForConfig(armored, privateKey.pq, privateKey.info.fingerprint));
				} catch {
					// The classical output stays usable even if the PQ layer fails.
				}
			}
			setOutput(armored);

			// The user can always decrypt their own copy (Include me) — so the
			// plaintext is deleted from the composer as soon as the ciphertext
			// exists. Only the output remains in memory.
			setPlaintext("");
			setAttachments([]);
			setHintDismissedFor(null);
		} catch (e) {
			const msg = (e as Error).message ?? String(e);
			// Expired-key failures surface as openpgp internals — translate to
			// actionable guidance (R8). Triggered e.g. when every encryption
			// subkey of a recipient is expired: "Could not find valid encryption
			// key packet in key <KEYID>: Subkey is expired".
			if (
				/could not find valid encryption key packet|subkey is expired|key is expired/i.test(msg)
			) {
				setError(
					"A recipient key is expired — OpenPGP refused to encrypt to it. Remove the expired recipient (or ask its owner for an updated public key) and encrypt again.",
				);
			} else {
				setError(msg);
			}
		} finally {
			setBusy(false);
		}
	}, [
		plaintext,
		attachments,
		recipients,
		privateKey,
		includeSelf,
		requestDecryptedKey,
		settings.autoSign,
		settings.compression,
		settings.pqSealedCopy,
	]);

	// Cheap substring detection on the MESSAGE textarea, computed during render
	// (no effect needed). Hints never appear for empty input; signed input is
	// not flagged here (signing already-encrypted input is a legitimate flow).
	// Dismissal is keyed to the message text, so clearing the field re-arms
	// the hint.
	const detectedBlock = detectPgpBlock(plaintext);
	const showEncryptHint =
		plaintext.trim() !== "" &&
		(detectedBlock === "encrypted" ||
			detectedBlock === "publickey" ||
			detectedBlock === "privatekey") &&
		hintDismissedFor !== plaintext;

	// Approximate input size for the output-block savings stat (R10): the
	// message bytes plus each attachment's original size — the same numbers
	// the envelope wire format wraps. Armor is ASCII so the output's string
	// length ≈ byte length; the comparison is an honest "did compression do
	// anything" signal, not an exact accounting (markers/base64 framing add
	// a small fixed overhead on the input side too).
	const inputBytes = useMemo(
		() =>
			new TextEncoder().encode(plaintext).length + attachments.reduce((sum, a) => sum + a.size, 0),
		[plaintext, attachments],
	);

	// The whole composer — utility row (TOC, Expand) + editor + counter +
	// smart-input hint — as one value, rendered EITHER inline OR inside the
	// full-screen portal overlay further down. Moving it in and out of the
	// overlay is therefore a pure re-mount: no state lives in the subtree.
	//
	// # Mr. AI Acting on s183173's Behalf
	const composerBody = (
		<>
			{/* Composer utility row: table-of-contents insert + full-screen
			    toggle, right-aligned. */}
			<div className="mb-1.5 flex items-center justify-end gap-2">
				<button
					type="button"
					aria-label="Insert table of contents"
					title="Insert table of contents"
					onClick={insertTableOfContents}
					className="flex size-7 shrink-0 items-center justify-center rounded-lg text-muted-foreground transition-colors hover:bg-black/5 hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#0055dc]/40 dark:hover:bg-white/10 dark:focus-visible:ring-[#5e94ff]/40"
				>
					<List aria-hidden="true" className="size-3.5" />
				</button>
				<button
					type="button"
					aria-label={composerExpanded ? "Collapse editor" : "Expand editor to full screen"}
					title={composerExpanded ? "Collapse editor" : "Expand editor to full screen"}
					onClick={() => setComposerExpanded((v) => !v)}
					className="flex size-7 shrink-0 items-center justify-center rounded-lg text-muted-foreground transition-colors hover:bg-black/5 hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#0055dc]/40 dark:hover:bg-white/10 dark:focus-visible:ring-[#5e94ff]/40"
				>
					{composerExpanded ? (
						<Minimize2 aria-hidden="true" className="size-3.5" />
					) : (
						<Maximize2 aria-hidden="true" className="size-3.5" />
					)}
				</button>
			</div>
			{/* flex-1 min-h-0 in the overlay lets the active editor engine fill
			    the viewport; plain block inline. */}
			<div className={composerExpanded ? "min-h-0 flex-1" : undefined}>
				<MessageEditor
					value={plaintext}
					onChange={setPlaintext}
					files={attachments}
					onNewImageDataUrl={handleNewImageDataUrl}
					editorKind={settings.markdownEditor}
					placeholder="Type the message you want to encrypt + sign…"
					expanded={composerExpanded}
				/>
			</div>
			{/* Char/word/size counter (visual feedback only). */}
			<InputSizeCounter text={plaintext} />
			{showEncryptHint && detectedBlock && (
				<InputHint
					tone={detectedBlock === "encrypted" ? "amber" : "info"}
					onDismiss={() => setHintDismissedFor(plaintext)}
				>
					{detectedBlock === "encrypted"
						? "This looks like an already-encrypted message. Encrypting it again is rarely what you want."
						: "This looks like a PGP key. Keys are imported in the key configuration dialog, not encrypted as messages."}
				</InputHint>
			)}
		</>
	);
	return (
		<section
			className="relative space-y-6"
			onKeyDown={(e) => {
				// Ctrl/Cmd+Enter runs the primary action from anywhere in the tab
				// (editor, attachment list, button). Skips while a run is in flight
				// — same guard as the button's disabled state.
				if ((e.ctrlKey || e.metaKey) && !e.altKey && !e.shiftKey && e.key === "Enter") {
					e.preventDefault();
					if (!busy) void handleEncrypt();
				}
			}}
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
				if (e.dataTransfer.files.length > 0) {
					void addFiles(e.dataTransfer.files);
				}
			}}
		>
			{dragDepth > 0 && (
				<div
					aria-hidden
					className="pointer-events-none absolute inset-0 z-10 flex items-center justify-center rounded-xl border-2 border-dashed border-[#0055dc] bg-[#0055dc]/5 dark:border-[#5e94ff] dark:bg-[#5e94ff]/10 animate-fade-up"
				>
					<span className="rounded-lg bg-background/95 px-4 py-2 text-sm font-medium text-[#0055dc] shadow-sm dark:text-[#5e94ff]">
						Drop files to attach
					</span>
				</div>
			)}
			<RecipientPicker
				recipients={recipients}
				setRecipients={setRecipients}
				selfRecipient={selfRecipient}
				includeSelf={includeSelf}
				onIncludeSelfChange={onIncludeSelfChange}
			/>

			{!composerExpanded && <div className="rounded-xl">{composerBody}</div>}
			{/* Full-screen composer overlay ("blow up the editor"): a portal
			    dialog filling the viewport. Escape collapses it — EXCEPT when a
			    Radix surface opened FROM the composer is on stage: those consume
			    Escape themselves and must never come back to a collapsed
			    composer. Most Radix layers portal OUTSIDE this overlay, so their
			    Escapes never even bubble through it; the target checks + the
			    defaultPrevented guard cover the paths that still do. */}
			{composerExpanded &&
				createPortal(
					<div
						data-composer-overlay
						role="dialog"
						aria-modal="true"
						aria-label="Composer, full screen"
						onKeyDownCapture={(e) => {
							if (e.key !== "Escape" || e.defaultPrevented) return;
							const target = e.target as HTMLElement | null;
							if (
								target?.closest(
									'[role="dialog"]:not([data-composer-overlay]), [data-radix-popper-content-wrapper], [role="menu"], [role="listbox"]',
								)
							) {
								return;
							}
							e.preventDefault();
							setComposerExpanded(false);
						}}
						onKeyDown={(e) => {
							// Mirror the tab's Ctrl/Cmd+Enter primary action — the
							// portal sits outside the <section> keydown handler.
							if ((e.ctrlKey || e.metaKey) && !e.altKey && !e.shiftKey && e.key === "Enter") {
								e.preventDefault();
								if (!busy) void handleEncrypt();
							}
						}}
						className="fixed inset-0 z-50 overflow-y-auto bg-background p-4 sm:p-6"
					>
						<div className="mx-auto flex h-full min-h-0 w-full max-w-4xl flex-col">
							{composerBody}
						</div>
					</div>,
					document.body,
				)}

			<AttachmentList
				attachments={attachments}
				onAddFiles={handleAddFiles}
				onRemove={(idx) => setAttachments((prev) => prev.filter((_, i) => i !== idx))}
			/>

			{/* Expiry pre-flight warning (R8): fires as soon as an expired key is
          on the recipient list — before any passphrase is requested. Amber,
          matching the own-key "expiring" banner family; non-blocking. */}
			{expiredRecipients.length > 0 && (
				<div
					role="status"
					className="animate-fade-up flex items-start gap-2.5 rounded-xl border border-amber-300/70 bg-amber-50 px-4 py-3 shadow-sm dark:border-amber-900/50 dark:bg-amber-950/30"
				>
					<TriangleAlert
						aria-hidden="true"
						className="mt-0.5 size-4 shrink-0 text-amber-600 dark:text-amber-400"
					/>
					<p className="text-xs leading-relaxed text-amber-900 dark:text-amber-200">
						<span className="font-medium">
							{expiredRecipients.length === 1
								? "A recipient key has expired."
								: `${expiredRecipients.length} recipient keys have expired.`}
						</span>{" "}
						{expiredRecipients
							.map(
								(r) => `“${r.label}” (expired ${new Date(r.expiresAt ?? 0).toLocaleDateString()})`,
							)
							.join(", ")}{" "}
						— encryption may fail. Ask the owner for an updated public key.
					</p>
				</div>
			)}

			{error && <ErrorBanner message={error} />}

			<div className="flex gap-2">
				<Button
					onClick={handleEncrypt}
					disabled={busy}
					className="bg-[#0055dc] text-white hover:bg-[#0046b8] transition-colors duration-150 press-effect"
				>
					{busy
						? "Encrypting…"
						: output
							? settings.autoSign
								? "Encrypt & sign again"
								: "Encrypt again"
							: settings.autoSign
								? "Encrypt & sign"
								: "Encrypt"}
				</Button>
			</div>

			{output && (
				<OutputBlock
					title={settings.autoSign ? "Encrypted + signed message" : "Encrypted message"}
					output={output}
					files={[]}
					// The plaintext was deleted from the composer on success —
					// only the ciphertext remains in memory, so there is no
					// preview and nothing to nuke. "Show raw text" IS the view.
					operation="encrypt"
					inputBytes={inputBytes}
					onReset={() => {
						setOutput("");
						setSealedCopy("");
						setError(null);
					}}
				/>
			)}

			{/* Quantum-sealed copy (opt-in): only produced when the key has a
            quantum-seal pair. Shown as a secondary output row with its own
            copy/download actions — it is an archive artifact, not the thing
            you send. */}
			{sealedCopy && (
				<section className="animate-fade-up space-y-2 rounded-xl border border-violet-300/60 bg-violet-50/60 p-4 shadow-sm dark:border-violet-900/50 dark:bg-violet-950/20">
					<div className="flex flex-wrap items-center justify-between gap-2">
						<div className="min-w-0">
							<p className="text-xs font-medium text-violet-900 dark:text-violet-300">
								Quantum-sealed copy (ML-KEM-768)
							</p>
							<p className="mt-0.5 text-[11px] text-muted-foreground">
								Post-quantum outer layer for your archive — even a future quantum computer
								can&apos;t open it without this device&apos;s key + passphrase.
							</p>
						</div>
						<div className="flex shrink-0 gap-2">
							<CopyButton text={sealedCopy} label="Copy" ariaLabel="Copy quantum-sealed copy" />
							<DownloadButton text={sealedCopy} title="quantum-sealed copy" />
						</div>
					</div>
					<Textarea
						readOnly
						rows={4}
						value={sealedCopy}
						className="field-sizing-fixed bg-muted/40 font-mono text-[11px]"
						aria-label="Quantum-sealed copy"
					/>
				</section>
			)}
		</section>
	);
}
