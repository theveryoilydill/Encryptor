"use client";

import dynamic from "next/dynamic";

/**
 * PgpApp is loaded client-side only (openpgp requires browser APIs).
 * The default export is provided by the PgpApp orchestrator agent.
 */
const PgpApp = dynamic(() => import("@/components/pgp/PgpApp"), {
	ssr: false,
	loading: () => <LoadingScreen />,
});

function LoadingScreen() {
	return (
		<div className="flex min-h-[60vh] flex-col items-center justify-center">
			<img
				src="/logo.svg"
				alt="Encryptor logo"
				width={56}
				height={56}
				className="h-14 w-14 animate-pulse rounded-xl"
			/>
			<p className="mt-4 text-sm text-muted-foreground">Loading PGP toolkit&hellip;</p>
		</div>
	);
}

export default function Home() {
	return (
		<div className="animate-fade-up">
			<PgpApp />
		</div>
	);
}
