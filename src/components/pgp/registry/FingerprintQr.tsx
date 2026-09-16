"use client";

/**
 * Fingerprint QR sharing — encodes the standard `openpgp4fpr:` URI
 * (the OpenPGP fingerprint URI scheme understood by OpenKeychain, GnuPG
 * front-ends, Keybase and friends). Scanning a fingerprint QR is an
 * out-of-band verification channel: the fingerprint travels through the
 * camera path instead of the (possibly tampered) network path, so a MITM
 * who swaps keys in API responses cannot survive the comparison.
 *
 * The QR itself is rendered on a white panel with near-black modules
 * regardless of theme — scanners need contrast and a quiet zone, and a
 * dark-mode inverted QR confuses most readers. # Mr. AI Acting on
 * s183173's Behalf
 */
import { useState } from "react";
import { QRCodeSVG } from "qrcode.react";
import { QrCode } from "lucide-react";

import { Button } from "@/components/ui/button";
import {
	Dialog,
	DialogContent,
	DialogDescription,
	DialogHeader,
	DialogTitle,
} from "@/components/ui/dialog";
import { CopyButton } from "@/components/pgp/shared";
import { formatFingerprint } from "@/lib/pgp/pgp";

/** Canonical `openpgp4fpr:` URI for a 40-hex fingerprint. */
export function fingerprintUri(fingerprint: string): string {
	return `openpgp4fpr:${fingerprint.replace(/\s+/g, "").toUpperCase()}`;
}

/** Small outline button that opens the QR dialog for a fingerprint. */
export function FingerprintQrButton({
	fingerprint,
	ariaLabel,
}: {
	fingerprint: string;
	ariaLabel?: string;
}) {
	const [open, setOpen] = useState(false);
	const uri = fingerprintUri(fingerprint);
	return (
		<>
			<Button
				type="button"
				variant="outline"
				size="sm"
				className="h-9 gap-1.5 px-2.5 text-[11px] sm:h-7"
				onClick={() => setOpen(true)}
				aria-label={ariaLabel ?? `Show QR code for fingerprint ${fingerprint}`}
				data-testid="keys-qr-open"
			>
				<QrCode aria-hidden="true" className="size-3" />
				QR
			</Button>
			<Dialog open={open} onOpenChange={setOpen}>
				<DialogContent className="max-w-xs">
					<DialogHeader>
						<DialogTitle className="text-base">Scan to verify</DialogTitle>
						<DialogDescription className="text-xs">
							The QR encodes this fingerprint as an <code>openpgp4fpr:</code> URI — scan it with
							OpenKeychain, GnuPG, or another OpenPGP app to verify the key out-of-band.
						</DialogDescription>
					</DialogHeader>
					<div className="flex flex-col items-center gap-3" data-testid="keys-qr-dialog">
						<div
							className="rounded-xl border bg-white p-3 shadow-inner ring-1 ring-[#0055dc]/15 dark:ring-[#5e94ff]/20"
							data-testid="keys-qr-panel"
						>
							<QRCodeSVG value={uri} size={168} bgColor="#FFFFFF" fgColor="#0B1220" level="M" />
						</div>
						<p
							className="text-center font-mono text-[11px] leading-relaxed tracking-wide"
							data-testid="keys-qr-fpr"
						>
							{formatFingerprint(fingerprint)}
						</p>
						<CopyButton text={uri} label="Copy openpgp4fpr URI" ariaLabel={`Copy ${uri}`} />
					</div>
				</DialogContent>
			</Dialog>
		</>
	);
}
