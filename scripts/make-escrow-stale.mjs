/**
 * make-escrow-stale — test fixture for the "escrow outdated" audit hint.
 *
 * Creates a throwaway key, publishes it WITH an escrowed private key, then
 * performs an authorized replace WITHOUT escrow fields. Per registry
 * semantics the escrow is KEPT — so the stored private-key backup now
 * predates the current key version (private_updated_at < updated_at),
 * which is exactly the drift the audit's escrow-staleness check flags.
 *
 * Prints a single JSON line to stdout: { "fingerprint": "<40 hex>" }
 * The key stays published (harmless, cap-guarded); it is NOT revoked so
 * the fixture remains lookable for UI tests.
 *
 * Usage: node scripts/make-escrow-stale.mjs [baseUrl]
 * # Mr. AI Acting on s183173's Behalf
 */
import * as openpgp from "openpgp";

const BASE = process.argv[2] ?? process.env.REGISTRY_TEST_BASE ?? "http://localhost:3000";
const RUN_OCTET = (Math.floor(Date.now() / 1000) % 250) + 1;
const IP = (n) => ({ "cf-connecting-ip": `10.7.${RUN_OCTET}.${n % 250}` });
const PASS = `stale-fixture-${Date.now().toString(36)}`;

async function api(path, opts = {}) {
	const { headers: extra, ...rest } = opts;
	const res = await fetch(`${BASE}${path}`, {
		...rest,
		headers: { "cf-connecting-ip": `10.7.${RUN_OCTET}.99`, ...extra },
	});
	let body = null;
	try {
		body = await res.json();
	} catch {}
	return { status: res.status, body };
}

const jsonPost = (path, payload, extra = {}) =>
	api(path, {
		method: "POST",
		headers: { "Content-Type": "application/json", ...extra },
		body: JSON.stringify(payload),
	});

async function signChallenge(privateKey, fingerprint, nonce) {
	const message = `encryptor key registry\naction: prove-key-possession\nfingerprint: ${fingerprint}\nnonce: ${nonce}\n`;
	const cleartext = await openpgp.createCleartextMessage({ text: message });
	return openpgp.sign({ message: cleartext, signingKeys: privateKey, format: "armored" });
}

const fail = (msg) => {
	console.error(msg);
	process.exit(1);
};

// 1. First publish needs no challenge (Turnstile gates it when enforced;
//    disabled locally). Response carries the fingerprint.
const name = `Stale Fixture ${Date.now().toString(36)}`;
const email = `stale.fixture.${Date.now().toString(36)}@example.com`;
const gen = await openpgp.generateKey({
	type: "ecc",
	curve: "curve25519",
	userIDs: [{ name, email }],
	passphrase: PASS,
	format: "object",
});
const armoredPublic = gen.publicKey.armor();
const armoredPrivate = gen.privateKey.armor();
const pub0 = await jsonPost("/api/registry/publish", { armored: armoredPublic }, IP(10));
if (pub0.status !== 201)
	fail(`first publish failed: ${pub0.status} ${JSON.stringify(pub0.body)?.slice(0, 200)}`);
const fingerprint = pub0.body.fingerprint;

// Passphrase-protected keys must be unlocked before signing.
const unlockedKey = await openpgp.decryptKey({ privateKey: gen.privateKey, passphrase: PASS });

// Passphrase-protected keys must be unlocked before signing.

// 2. Escrow the encrypted private key (possession proof via challenge).
const ch1 = await api(`/api/registry/challenge?fingerprint=${fingerprint}`, { headers: IP(11) });
if (ch1.status !== 200) fail(`challenge failed: ${ch1.status}`);
const esc = await jsonPost(
	"/api/registry/private-key",
	{
		fingerprint,
		nonce: ch1.body.nonce,
		signature: await signChallenge(unlockedKey, fingerprint, ch1.body.nonce),
		encryptedPrivate: armoredPrivate,
	},
	IP(12),
);
if (esc.status !== 200 || esc.body?.escrowed !== true) {
	fail(`escrow store failed: ${esc.status} ${JSON.stringify(esc.body)?.slice(0, 200)}`);
}

// 3. Authorized replace WITHOUT escrow fields → escrow is kept, key
//    updated_at moves forward, private_updated_at stays behind.
await new Promise((r) => setTimeout(r, 1100)); // ensure updated_at (sec) advances
const ch2 = await api(`/api/registry/challenge?fingerprint=${fingerprint}`, { headers: IP(13) });
if (ch2.status !== 200) fail(`challenge 2 failed: ${ch2.status}`);
const rep = await jsonPost(
	"/api/registry/publish",
	{
		armored: armoredPublic,
		nonce: ch2.body.nonce,
		signature: await signChallenge(unlockedKey, fingerprint, ch2.body.nonce),
	},
	IP(14),
);
if (rep.status !== 200 || rep.body?.replaced !== true) {
	fail(`replace failed: ${rep.status} ${JSON.stringify(rep.body)?.slice(0, 200)}`);
}

// 4. Verify the drift actually exists server-side.
const look = await api(`/api/registry/lookup?fingerprint=${fingerprint}`, { headers: IP(15) });
const escGet = await api(`/api/registry/private-key?fingerprint=${fingerprint}`, {
	headers: IP(16),
});
const keyUpdatedAt = look.body?.keys?.[0]?.updatedAt;
const escUpdatedAt = escGet.body?.updatedAt;
if (typeof keyUpdatedAt !== "number" || typeof escUpdatedAt !== "number") {
	fail(`could not read timestamps: key=${keyUpdatedAt} escrow=${escUpdatedAt}`);
}
if (!(escUpdatedAt < keyUpdatedAt)) {
	fail(`expected stale escrow (${escUpdatedAt}) < key (${keyUpdatedAt}) — got no drift`);
}

console.log(JSON.stringify({ fingerprint, keyUpdatedAt, escUpdatedAt }));
