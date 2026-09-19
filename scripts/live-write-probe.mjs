/**
 * One-off LIVE write probe against the branch preview of PR #25.
 * Proves the owner's "no writes to my database" complaint is fixed:
 *   publish (201) -> lookup (persisted) -> revoke (clean end state).
 * Leaves at most a single revoked probe record, disclosed in the PR comment.
 * # Mr. AI Acting on s183173's Behalf
 */
import * as openpgp from "openpgp";

const BASE =
	process.env.PROBE_BASE ??
	"https://ai-key-registry-private-keys-encryptor.theveryoilydill.workers.dev";
// NOTE: never send cf-* headers to a Cloudflare edge — reserved headers make
// the edge reject the request with 403 before it reaches the worker.

async function api(path, opts = {}) {
	const res = await fetch(`${BASE}${path}`, opts);
	let body = null;
	try {
		body = await res.json();
	} catch {}
	return { status: res.status, body };
}

const post = (path, payload) =>
	api(path, {
		method: "POST",
		headers: { "Content-Type": "application/json" },
		body: JSON.stringify(payload),
	});

let fails = 0;
const check = (name, cond, detail = "") => {
	if (cond) console.log(`  PASS ${name}`);
	else {
		fails++;
		console.log(`  FAIL ${name} ${detail}`);
	}
};

console.log(`probe target: ${BASE}`);
const email = `ai-probe.${Date.now().toString(36)}@ai-verify.local`;
console.log(`probe identity: ${email}`);

// The private half is generated but deliberately discarded — the probe only
// exercises the public-key publish path and never retains key material.
const { privateKey: _discarded, publicKey } = await openpgp.generateKey({
	type: "ecc",
	curve: "curve25519",
	userIDs: [{ name: "Mr AI Probe", email }],
	format: "object",
});
const fpr = publicKey.getFingerprint().toUpperCase();

const pub = await post("/api/registry/publish", { armored: publicKey.armor() });
check(
	"publish -> 201 (write to remote D1)",
	pub.status === 201,
	`got ${pub.status} ${JSON.stringify(pub.body)}`,
);
check("revocation token returned", typeof pub.body?.revocationToken === "string");
check("fingerprint echoed", pub.body?.fingerprint === fpr);

const look = await api(`/api/registry/lookup?email=${encodeURIComponent(email)}`);
check(
	"lookup finds the new record",
	look.status === 200 && look.body?.keys?.length === 1,
	`got ${look.status}`,
);
check("lookup shows not revoked", look.body?.keys?.[0]?.revoked === false);

const rvk = await post("/api/registry/revoke", {
	fingerprint: fpr,
	token: pub.body?.revocationToken,
	reason: "AI write probe — cleanup",
});
check("revoke with token -> 200", rvk.status === 200, `got ${rvk.status}`);

// Cache-busted: lookup responses are publicly cached (max-age=60, s-maxage=300),
// so a same-URL re-read right after revoke would return the stale cached body.
// Revoked keys are EXCLUDED from email lookup by design; the transparency
// view is the fingerprint lookup (revoked:true + reason). Cache-busted.
const after = await api(`/api/registry/lookup?fingerprint=${fpr}&cb=${Date.now()}`);
check(
	"lookup(fingerprint) shows revoked:true afterwards",
	after.body?.keys?.[0]?.revoked === true,
	`got ${JSON.stringify(after.body)}`,
);
const gone = await api(`/api/registry/lookup?email=${encodeURIComponent(email)}&cb=${Date.now()}`);
check(
	"email lookup no longer lists revoked key",
	gone.body?.keys?.length === 0,
	`got ${JSON.stringify(gone.body)}`,
);

console.log(
	fails === 0
		? "\nLIVE WRITE PROBE: ALL PASS — remote D1 accepts writes end-to-end"
		: `\nLIVE WRITE PROBE: ${fails} failure(s)`,
);
process.exit(fails === 0 ? 0 : 1);
