"use client";

/**
 * ScanQrButton — camera QR scanning feeding the registry lookup.
 *
 * Uses the Chromium/Android `BarcodeDetector` API (no JS decoder shipped —
 * keeping the bundle lean; Firefox/Safari users get an explicit note in the
 * dialog instead of a silent dead button). Detection accepts the standard
 * `openpgp4fpr:<FINGERPRINT>` URI (same payload the QR dialog encodes, so
 * Encryptor's own QRs round-trip) plus a bare 40-hex fingerprint.
 *
 * The camera stream is fully local: frames go to the browser's built-in
 * detector and are never uploaded. # Mr. AI Acting on s183173's Behalf
 */
import { useCallback, useEffect, useRef, useState } from "react";
import { Camera, Loader2, ScanLine, TriangleAlert } from "lucide-react";

import { Button } from "@/components/ui/button";
import {
	Dialog,
	DialogContent,
	DialogDescription,
	DialogHeader,
	DialogTitle,
} from "@/components/ui/dialog";

/* ---- minimal BarcodeDetector typing (not yet in TS lib.dom) ------------- */
interface DetectedBarcode {
	rawValue: string;
}
interface BarcodeDetectorLike {
	detect(source: HTMLVideoElement): Promise<DetectedBarcode[]>;
}
type BarcodeDetectorCtor = new (options?: { formats?: string[] }) => BarcodeDetectorLike;

function getDetectorCtor(): BarcodeDetectorCtor | null {
	if (typeof window === "undefined") return null;
	const ctor = (window as unknown as { BarcodeDetector?: BarcodeDetectorCtor }).BarcodeDetector;
	return typeof ctor === "function" ? ctor : null;
}

/** Extract a 40-hex fingerprint from a scanned QR payload. */
export function fingerprintFromQrValue(raw: string): string | null {
	const value = raw.trim();
	const fromUri = value.match(/^openpgp4fpr:([0-9a-fA-F]{40})$/i);
	if (fromUri) return fromUri[1].toUpperCase();
	const bare = value.replace(/[\s-]/g, "").replace(/^0x/i, "");
	return /^[0-9a-fA-F]{40}$/.test(bare) ? bare.toUpperCase() : null;
}

type ScanState =
	| { kind: "starting" }
	| { kind: "scanning" }
	| { kind: "unsupported" }
	| { kind: "camera-error"; message: string };

export function ScanQrButton({
	onDetect,
	ariaLabel,
}: {
	onDetect: (fingerprint: string) => void;
	ariaLabel?: string;
}) {
	const [open, setOpen] = useState(false);
	const [state, setState] = useState<ScanState>({ kind: "starting" });
	const videoRef = useRef<HTMLVideoElement | null>(null);
	const streamRef = useRef<MediaStream | null>(null);
	const timerRef = useRef<ReturnType<typeof setInterval> | null>(null);
	// Latest onDetect without re-arming the detection loop per render.
	const onDetectRef = useRef(onDetect);
	onDetectRef.current = onDetect;

	const stopCamera = useCallback(() => {
		if (timerRef.current) {
			clearInterval(timerRef.current);
			timerRef.current = null;
		}
		streamRef.current?.getTracks().forEach((t) => t.stop());
		streamRef.current = null;
		if (videoRef.current) videoRef.current.srcObject = null;
	}, []);

	useEffect(() => () => stopCamera(), [stopCamera]);
	// Close (X button / Escape) must also release the camera.
	useEffect(() => {
		if (!open) stopCamera();
	}, [open, stopCamera]);

	const startCamera = useCallback(async () => {
		const Ctor = getDetectorCtor();
		if (!Ctor) {
			setState({ kind: "unsupported" });
			return;
		}
		setState({ kind: "starting" });
		try {
			const stream = await navigator.mediaDevices.getUserMedia({
				video: { facingMode: "environment" },
			});
			streamRef.current = stream;
			const video = videoRef.current;
			if (!video) return;
			video.srcObject = stream;
			await video.play().catch(() => undefined);
			setState({ kind: "scanning" });
			const detector = new Ctor({ formats: ["qr_code"] });
			timerRef.current = setInterval(async () => {
				const el = videoRef.current;
				if (!el || el.readyState < 2) return;
				try {
					const codes = await detector.detect(el);
					for (const code of codes) {
						const fpr = fingerprintFromQrValue(code.rawValue ?? "");
						if (fpr) {
							stopCamera();
							setOpen(false);
							onDetectRef.current(fpr);
							return;
						}
					}
				} catch {
					/* transient decode hiccup — keep scanning */
				}
			}, 250);
		} catch (e) {
			const name = (e as { name?: string }).name ?? "";
			setState({
				kind: "camera-error",
				message:
					name === "NotAllowedError"
						? "Camera permission denied — allow camera access and try again."
						: name === "NotFoundError"
							? "No camera found on this device."
							: "Could not start the camera — try again.",
			});
		}
	}, [stopCamera]);

	const handleOpen = useCallback(() => {
		setOpen(true);
		void startCamera();
	}, [startCamera]);

	return (
		<>
			<Button
				type="button"
				variant="outline"
				size="sm"
				className="h-11 shrink-0 gap-1.5 sm:h-9"
				onClick={handleOpen}
				aria-label={ariaLabel ?? "Scan a QR code with your camera"}
				data-testid="keys-scan-open"
			>
				<Camera aria-hidden="true" className="size-4" />
				<span className="hidden sm:inline">Scan</span>
			</Button>
			<Dialog open={open} onOpenChange={setOpen}>
				<DialogContent className="max-w-sm">
					<DialogHeader>
						<DialogTitle className="text-base">Scan a key QR</DialogTitle>
						<DialogDescription className="text-xs">
							Point the camera at an <code>openpgp4fpr:</code> QR — the fingerprint is read locally
							and looked up. Frames never leave this device.
						</DialogDescription>
					</DialogHeader>
					<div
						className="overflow-hidden rounded-xl border bg-zinc-950"
						data-testid="keys-scan-dialog"
					>
						{state.kind === "unsupported" ? (
							<div className="flex flex-col items-center gap-2 px-4 py-8 text-center">
								<TriangleAlert aria-hidden="true" className="size-6 text-amber-400" />
								<p className="text-xs text-zinc-200">
									This browser doesn&apos;t expose the BarcodeDetector API. Chrome, Edge, or Android
									browsers can scan; otherwise type or paste the fingerprint manually.
								</p>
							</div>
						) : state.kind === "camera-error" ? (
							<div className="flex flex-col items-center gap-2 px-4 py-8 text-center">
								<TriangleAlert aria-hidden="true" className="size-6 text-red-400" />
								<p className="text-xs text-zinc-200" data-testid="keys-scan-error">
									{state.message}
								</p>
							</div>
						) : (
							<div className="relative">
								<video
									ref={videoRef}
									className="aspect-square w-full object-cover"
									muted
									playsInline
									autoPlay
									data-testid="keys-scan-video"
								/>
								{/* reticle: four corner brackets + laser line */}
								<div className="pointer-events-none absolute inset-6" aria-hidden="true">
									<div className="absolute left-0 top-0 size-8 rounded-tl-lg border-l-2 border-t-2 border-emerald-400/90" />
									<div className="absolute right-0 top-0 size-8 rounded-tr-lg border-r-2 border-t-2 border-emerald-400/90" />
									<div className="absolute bottom-0 left-0 size-8 rounded-bl-lg border-b-2 border-l-2 border-emerald-400/90" />
									<div className="absolute bottom-0 right-0 size-8 rounded-br-lg border-b-2 border-r-2 border-emerald-400/90" />
									<div
										className={
											"absolute inset-x-4 top-1/2 h-px bg-emerald-300/70 shadow-[0_0_8px_2px_rgba(52,211,153,0.45)] " +
											(state.kind === "scanning" ? "animate-pulse" : "")
										}
									/>
								</div>
								{state.kind === "starting" && (
									<div className="absolute inset-0 flex items-center justify-center bg-zinc-950/70">
										<Loader2 aria-hidden="true" className="size-6 animate-spin text-zinc-200" />
									</div>
								)}
							</div>
						)}
						<div className="flex items-center gap-2 border-t border-zinc-800 bg-zinc-900 px-3 py-2">
							<ScanLine aria-hidden="true" className="size-3.5 text-emerald-400" />
							<p className="text-[11px] text-zinc-300" data-testid="keys-scan-status">
								{state.kind === "scanning"
									? "Point at a QR code — detection is automatic."
									: state.kind === "starting"
										? "Starting camera…"
										: state.kind === "unsupported"
											? "Scanning unavailable in this browser."
											: "Camera unavailable."}
							</p>
						</div>
					</div>
				</DialogContent>
			</Dialog>
		</>
	);
}
