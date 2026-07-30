"use client";

import dynamic from "next/dynamic";

// openpgp.js requires `window`, so we render the PGP UI client-only.
const PgpApp = dynamic(() => import("@/components/pgp/PgpApp"), {
  ssr: false,
  loading: () => (
    <div className="min-h-screen flex items-center justify-center bg-neutral-950 text-neutral-500 text-sm">
      Loading PGP toolkit…
    </div>
  ),
});

export default function Home() {
  return <PgpApp />;
}
