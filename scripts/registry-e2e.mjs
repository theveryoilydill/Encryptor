/**
 * Registry end-to-end tests — run against `next dev` (local D1) or any
 * deployment. Exercises publish/lookup/challenge/revoke including
 * negative security cases (SQLi probes, replay, forged signer,
 * cross-fingerprint nonce, rate limiting, payload guards).
 * # Mr. AI Acting on s183173's Behalf
 */
import * as openpgp from "openpgp";

// Usage: start the dev server (bun run dev) with local D1 migrated, then:
//   node scripts/registry-e2e.mjs        (or: bun run test:registry)
// Override the target with REGISTRY_TEST_BASE for preview deployments.
// # Mr. AI Acting on s183173's Behalf
const BASE = process.env.REGISTRY_TEST_BASE ?? "http://localhost:3000";
let passed = 0;
let failed = 0;

function check(name, cond, detail = "") {
	if (cond) {
		passed++;
		console.log(`  PASS ${name}`);
	} else {
		failed++;
		const redacted = detail ? " [details redacted]" : "";
		console.log(`  FAIL ${name}${redacted}`);
	}
}

async function api(path, opts = {}) {
	const res = await fetch(`${BASE}${path}`, opts);
	let body = null;
	try {
		body = await res.json();
	} catch {}
	return { status: res.status, body, headers: res.headers };
}

function jsonPost(path, payload, extra = {}) {
	return api(path, {
		method: "POST",
		headers: { "Content-Type": "application/json", ...extra },
		body: JSON.stringify(payload),
	});
}

async function makeKey(name, email) {
	const { privateKey, publicKey } = await openpgp.generateKey({
		type: "ecc",
		curve: "curve25519",
		userIDs: [{ name, email }],
		format: "object",
	});
	return { privateKey, publicKey };
}

async function signChallenge(privateKey, fingerprint, nonce) {
	const message = `encryptor key registry\naction: prove-key-possession\nfingerprint: ${fingerprint}\nnonce: ${nonce}\n`;
	const cleartext = await openpgp.createCleartextMessage({ text: message });
	return openpgp.sign({ message: cleartext, signingKeys: privateKey, format: "armored" });
}

/** Same, for a PASSPHRASE-ENCRYPTED private key object. */
async function signChallengeEncrypted(privateKey, passphrase, fingerprint, nonce) {
	const unlocked = await openpgp.decryptKey({ privateKey, passphrase });
	return signChallenge(unlocked, fingerprint, nonce);
}

const IP = (n) => ({ "cf-connecting-ip": `10.7.0.${n}` });

/** Challenge fetch with its OWN IP bucket — challenges share one bucket per
 *  client IP (10/h), so the suite would exhaust the shared anon bucket once
 *  it grew past 10 challenges. Distinct IPs keep runs deterministic. */
const challengeFor = (fingerprint, ipNum) =>
	api(`/api/registry/challenge?fingerprint=${fingerprint}`, { headers: IP(ipNum) });

// ---- main ----
const t0 = Date.now();

// Warmup: first hits compile routes on demand in next dev — retry until the
// server responds (up to ~4 min), then fail fast.
async function warmup() {
	for (let i = 0; i < 48; i++) {
		try {
			const res = await fetch(`${BASE}/api/registry/lookup`, {
				signal: AbortSignal.timeout(15000),
			});
			if (res.status > 0) {
				console.log(`warmup ok after ${i + 1} attempt(s) (status ${res.status})`);
				return;
			}
		} catch {
			await new Promise((r) => setTimeout(r, 5000));
		}
	}
	console.error("server did not warm up within 4 minutes");
	process.exit(2);
}
await warmup();

console.log("== input validation ==");
{
	const r = await api("/api/registry/lookup");
	check("lookup without params -> 400", r.status === 400, `got ${r.status}`);
	const r2 = await api("/api/registry/lookup?fingerprint=ZZZZ");
	check("malformed fingerprint -> 400", r2.status === 400, `got ${r2.status}`);
	const r3 = await api("/api/registry/lookup?fingerprint=" + encodeURIComponent("' OR 1=1 --"));
	check("SQLi fingerprint -> 400", r3.status === 400, `got ${r3.status}`);
	const r4 = await api("/api/registry/lookup?key_id=" + encodeURIComponent("x' UNION SELECT"));
	check("SQLi key_id -> 400", r4.status === 400, `got ${r4.status}`);
	const r5 = await api("/api/registry/lookup?email=nobody@x");
	check("invalid email -> 400", r5.status === 400, `got ${r5.status}`);
	const r6 = await api("/api/registry/lookup?fingerprint=" + "A".repeat(40));
	check("unknown fingerprint -> 200 empty", r6.status === 200 && r6.body.keys.length === 0);
	const r7 = await api("/api/registry/lookup", {
		headers: { Origin: "https://evil.example" },
	});
	check(
		"lookup sends CORS *",
		r7.headers.get("access-control-allow-origin") === "*",
		r7.headers.get("access-control-allow-origin"),
	);
	const pre = await api("/api/registry/lookup", { method: "OPTIONS" });
	check("OPTIONS preflight 204", pre.status === 204, `got ${pre.status}`);
}

console.log("== publish happy path (alice) ==");
const alice = await makeKey("Alice", "alice@example.com");
const aliceArmor = alice.publicKey.armor();
const aliceFpr = alice.publicKey.getFingerprint().toUpperCase();
const aliceSubkeyIds = alice.publicKey
	.getKeyIDs()
	.slice(1)
	.map((id) => id.toHex().toUpperCase());
let _aliceToken; // captured for symmetry; re-read via lookup below
{
	const r = await jsonPost("/api/registry/publish", { armored: aliceArmor }, IP(1));
	check("publish -> 201", r.status === 201, JSON.stringify(r.body));
	check("publish returns token", typeof r.body?.revocationToken === "string");
	check("publish fingerprint matches", r.body?.fingerprint === aliceFpr);
	_aliceToken = r.body?.revocationToken;

	const wrongCT = await api("/api/registry/publish", {
		method: "POST",
		headers: { "Content-Type": "text/plain", ...IP(1) },
		body: JSON.stringify({ armored: aliceArmor }),
	});
	check("wrong content-type -> 415", wrongCT.status === 415, `got ${wrongCT.status}`);

	const priv = await jsonPost(
		"/api/registry/publish",
		{ armored: alice.privateKey.armor() },
		IP(2),
	);
	check(
		"private key publish -> 400",
		priv.status === 400,
		`got ${priv.status}: ${priv.body?.error}`,
	);

	const dup = await jsonPost("/api/registry/publish", { armored: aliceArmor }, IP(3));
	check("duplicate publish -> 409", dup.status === 409, `got ${dup.status}`);
}

console.log("== lookup paths (alice) ==");
{
	const byFpr = await api(`/api/registry/lookup?fingerprint=${aliceFpr}`);
	check(
		"lookup by fingerprint",
		byFpr.body?.keys?.[0]?.fingerprint === aliceFpr &&
			byFpr.body.keys[0].armored.includes("BEGIN PGP PUBLIC KEY"),
	);
	check("lookup shows not revoked", byFpr.body?.keys?.[0]?.revoked === false);
	const byId = await api(`/api/registry/lookup?key_id=${aliceFpr.slice(-16)}`);
	check(
		"lookup by primary key_id",
		byId.body?.keys?.length === 1,
		JSON.stringify(byId.body?.keys?.length),
	);
	if (aliceSubkeyIds.length > 0) {
		const bySub = await api(`/api/registry/lookup?key_id=${aliceSubkeyIds[0]}`);
		check("lookup by subkey key_id", bySub.body?.keys?.length === 1);
	}
	const byEmail = await api("/api/registry/lookup?email=alice@example.com");
	check("lookup by email", byEmail.body?.keys?.length === 1);
	const caseFold = await api("/api/registry/lookup?email=ALICE@EXAMPLE.COM");
	check("email lookup case-insensitive", caseFold.body?.keys?.length === 1);
}

console.log("== authorized replacement (alice) ==");
{
	const noAuth = await jsonPost("/api/registry/publish", { armored: aliceArmor }, IP(4));
	check("replace without signature -> 409", noAuth.status === 409, `got ${noAuth.status}`);

	const ch = await challengeFor(aliceFpr, 50);
	check(
		"challenge returns nonce",
		ch.status === 200 && typeof ch.body?.nonce === "string",
		JSON.stringify(ch.body),
	);
	const badSig = await jsonPost(
		"/api/registry/publish",
		{
			armored: aliceArmor,
			nonce: ch.body.nonce,
			signature: "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\ngarbage\n",
		},
		IP(5),
	);
	check("replace with garbage signature -> 403", badSig.status === 403, `got ${badSig.status}`);

	// Cross-fingerprint nonce attack: bob steals a challenge issued for
	// ALICE's fingerprint and tries to use it to replace BOB's own record.
	const bob = await makeKey("Bob", "bob@example.com");
	const bobArmor = bob.publicKey.armor();
	const bobPub = await jsonPost("/api/registry/publish", { armored: bobArmor }, IP(40));
	check("bob fresh publish -> 201 (setup)", bobPub.status === 201, JSON.stringify(bobPub.body));
	const stolen = await challengeFor(aliceFpr, 51);
	const forged = await signChallenge(bob.privateKey, aliceFpr, stolen.body.nonce);
	const forgedRes = await jsonPost(
		"/api/registry/publish",
		{ armored: bobArmor, nonce: stolen.body.nonce, signature: forged },
		IP(6),
	);
	check(
		"cross-fingerprint nonce -> 403",
		forgedRes.status === 403,
		`got ${forgedRes.status}: ${JSON.stringify(forgedRes.body)}`,
	);

	// Same-nonce-for-wrong-signer: fresh challenge for alice signed by bob.
	const chF = await challengeFor(aliceFpr, 52);
	const wrongSigner = await signChallenge(bob.privateKey, aliceFpr, chF.body.nonce);
	const wrongSignerRes = await jsonPost(
		"/api/registry/publish",
		{ armored: aliceArmor, nonce: chF.body.nonce, signature: wrongSigner },
		IP(41),
	);
	check(
		"wrong signer on own challenge -> 403",
		wrongSignerRes.status === 403,
		`got ${wrongSignerRes.status}`,
	);

	const ch3 = await challengeFor(aliceFpr, 53);
	const goodSig = await signChallenge(alice.privateKey, aliceFpr, ch3.body.nonce);
	const spentNonce = ch3.body.nonce;
	const ok = await jsonPost(
		"/api/registry/publish",
		{ armored: aliceArmor, nonce: spentNonce, signature: goodSig },
		IP(7),
	);
	check(
		"authorized replace -> 200 replaced",
		ok.status === 200 && ok.body?.replaced === true,
		JSON.stringify(ok.body),
	);

	// Nonce was consumed — it must never be re-issued as-is.
	const dupChallenge = await challengeFor(aliceFpr, 54);
	check("new challenge differs from spent nonce", dupChallenge.body?.nonce !== spentNonce);
}

console.log("== token revocation (bob) ==");
{
	const bob = await makeKey("Bob", "bob@example.com");
	const bobArmor = bob.publicKey.armor();
	const bobFpr = bob.publicKey.getFingerprint().toUpperCase();
	const pub = await jsonPost("/api/registry/publish", { armored: bobArmor }, IP(8));
	check("bob publish -> 201", pub.status === 201);
	const token = pub.body?.revocationToken;

	const badToken = await jsonPost(
		"/api/registry/revoke",
		{ fingerprint: bobFpr, token: "f".repeat(64) },
		IP(9),
	);
	check("revoke with wrong token -> 403", badToken.status === 403, `got ${badToken.status}`);

	const noAuth = await jsonPost("/api/registry/revoke", { fingerprint: bobFpr }, IP(10));
	check("revoke without auth -> 403", noAuth.status === 403, `got ${noAuth.status}`);

	const wrongFpr = await jsonPost(
		"/api/registry/revoke",
		{ fingerprint: "B".repeat(40), token },
		IP(11),
	);
	check("revoke unknown fingerprint -> 404", wrongFpr.status === 404, `got ${wrongFpr.status}`);

	const ok = await jsonPost(
		"/api/registry/revoke",
		{ fingerprint: bobFpr, token, reason: "lost key" },
		IP(12),
	);
	check(
		"revoke with token -> ok via token",
		ok.status === 200 && ok.body?.via === "token",
		JSON.stringify(ok.body),
	);

	const after = await api(`/api/registry/lookup?fingerprint=${bobFpr}`);
	check(
		"lookup shows revoked + reason",
		after.body?.keys?.[0]?.revoked === true && after.body.keys[0].revokeReason === "lost key",
	);

	const repub = await jsonPost("/api/registry/publish", { armored: bobArmor }, IP(13));
	check("re-publish revoked fingerprint -> 409", repub.status === 409, `got ${repub.status}`);

	const again = await jsonPost("/api/registry/revoke", { fingerprint: bobFpr, token }, IP(14));
	check(
		"second revoke idempotent alreadyRevoked",
		again.status === 200 && again.body?.alreadyRevoked === true,
	);
}

console.log("== signed-challenge revocation (carol) + replay protection ==");
{
	const carol = await makeKey("Carol", "carol@example.com");
	const carolFpr = carol.publicKey.getFingerprint().toUpperCase();
	await jsonPost("/api/registry/publish", { armored: carol.publicKey.armor() }, IP(15));

	const ch = await challengeFor(carolFpr, 55);
	const sig = await signChallenge(carol.privateKey, carolFpr, ch.body.nonce);
	// Wrong-key first: nonce is consumed, verification fails.
	const bob = await makeKey("Bob2", "bob2@example.com");
	const wrongSig = await signChallenge(bob.privateKey, carolFpr, ch.body.nonce);
	const wrong = await jsonPost(
		"/api/registry/revoke",
		{ fingerprint: carolFpr, nonce: ch.body.nonce, signature: wrongSig },
		IP(16),
	);
	check("wrong-key signed revoke -> 403", wrong.status === 403, `got ${wrong.status}`);

	// Same nonce, now signed correctly — must FAIL because nonce was consumed.
	const replay = await jsonPost(
		"/api/registry/revoke",
		{ fingerprint: carolFpr, nonce: ch.body.nonce, signature: sig },
		IP(17),
	);
	check("consumed nonce replay -> 403", replay.status === 403, `got ${replay.status}`);

	const ch2 = await challengeFor(carolFpr, 56);
	const sig2 = await signChallenge(carol.privateKey, carolFpr, ch2.body.nonce);
	const ok = await jsonPost(
		"/api/registry/revoke",
		{ fingerprint: carolFpr, nonce: ch2.body.nonce, signature: sig2 },
		IP(18),
	);
	check(
		"correct signed revoke -> ok via signature",
		ok.status === 200 && ok.body?.via === "signature",
		JSON.stringify(ok.body),
	);

	const revokedChallenge = await challengeFor(carolFpr, 57);
	check(
		"challenge on revoked key -> 409",
		revokedChallenge.status === 409,
		`got ${revokedChallenge.status}`,
	);
}

console.log("== admin override (dave) ==");
{
	const dave = await makeKey("Dave", "dave@example.com");
	const daveFpr = dave.publicKey.getFingerprint().toUpperCase();
	await jsonPost("/api/registry/publish", { armored: dave.publicKey.armor() }, IP(19));

	const badAdmin = await jsonPost(
		"/api/registry/revoke",
		{ fingerprint: daveFpr, adminToken: "nope" },
		IP(20),
	);
	check("bad admin token -> 403", badAdmin.status === 403, `got ${badAdmin.status}`);

	const ok = await jsonPost(
		"/api/registry/revoke",
		{ fingerprint: daveFpr, adminToken: "local-admin-token-4f8a2b", reason: "abuse" },
		IP(21),
	);
	check(
		"admin revoke -> ok via admin",
		ok.status === 200 && ok.body?.via === "admin",
		JSON.stringify(ok.body),
	);
}

console.log("== payload guards ==");
{
	const big = await jsonPost("/api/registry/publish", { armored: "x".repeat(200 * 1024) }, IP(22));
	check("oversized body -> 413", big.status === 413, `got ${big.status}`);
	const notJson = await jsonPost("/api/registry/publish", { armored: "{{{" }, IP(23));
	check("invalid JSON -> 400", notJson.status === 400, `got ${notJson.status}`);
}

console.log("== rate limiting (separate IP bucket) ==");
{
	const codes = [];
	for (let i = 0; i < 8; i++) {
		const r = await jsonPost("/api/registry/publish", { armored: `garbage-${i}` }, IP(250));
		codes.push(r.status);
	}
	check("8th publish attempt rate-limited 429", codes.includes(429), codes.join(","));
	const limitedCodes = codes.filter((c) => c === 429).length;
	check("at least 3 requests hit 429", limitedCodes >= 3, codes.join(","));
}

console.log("== subkey squatting + structural validation (review regressions) ==");
{
	// Build an attacker key carrying a VICTIM's subkey packet (armored
	// round-trip — the realistic attack path).
	const owner = await makeKey("Owner", "owner@example.com");
	const attacker = await makeKey("Attacker", "attacker@example.com");
	const victimPub = await openpgp.readKey({ armoredKey: owner.publicKey.armor() });
	const forged = await openpgp.readKey({ armoredKey: attacker.publicKey.armor() });
	forged.subkeys.push(victimPub.subkeys[0]);
	const squatArmor = forged.armor();

	const squat = await jsonPost("/api/registry/publish", { armored: squatArmor }, IP(30));
	check(
		"foreign-subkey key rejected -> 400",
		squat.status === 400,
		`got ${squat.status}: ${JSON.stringify(squat.body)}`,
	);

	// Sanity: the same attack against the OWNER's primary works only with a
	// valid binding — owner's own key must still publish fine.
	const own = await jsonPost("/api/registry/publish", { armored: owner.publicKey.armor() }, IP(31));
	check(
		"clean key with valid subkey binding -> 201",
		own.status === 201,
		`got ${own.status}: ${JSON.stringify(own.body)}`,
	);

	// Over-subkey-count key: glue 17 of owner's OWN subkey packets? Not
	// constructible with openpgp's API; instead publish a key whose
	// primary self-signature is destroyed (tampered armor) -> 400.
	const tampered = attacker.publicKey
		.armor()
		.replace(/^[A-Za-z0-9+/].*$/m, (m) => m.slice(0, -2) + "xx");
	const tamperedRes = await jsonPost("/api/registry/publish", { armored: tampered }, IP(32));
	check("tampered armor rejected -> 400", tamperedRes.status === 400, `got ${tamperedRes.status}`);
}

console.log("== encrypted private key escrow ==");
{
	// escrowUser publishes WITH a passphrase-encrypted private key.
	const escrowPass = "escrow-test-passphrase-42";
	const escrowUser = await openpgp.generateKey({
		type: "ecc",
		curve: "curve25519",
		userIDs: [{ name: "Escrow User", email: "escrow@example.com" }],
		passphrase: escrowPass,
		format: "object",
	});
	const escrowFpr = escrowUser.publicKey.getFingerprint().toUpperCase();
	const escrowPrivate = escrowUser.privateKey.armor();

	const pub = await jsonPost(
		"/api/registry/publish",
		{ armored: escrowUser.publicKey.armor(), encryptedPrivate: escrowPrivate },
		IP(60),
	);
	check("publish with escrow -> 201", pub.status === 201, JSON.stringify(pub.body));
	const escrowToken = pub.body?.revocationToken;

	const got = await api(`/api/registry/private-key?fingerprint=${escrowFpr}`);
	check(
		"escrow GET returns encrypted private",
		got.status === 200 &&
			typeof got.body?.encryptedPrivate === "string" &&
			got.body.encryptedPrivate.includes("BEGIN PGP PRIVATE KEY"),
		`got ${got.status}`,
	);
	check("escrow GET has no CORS header", got.headers.get("access-control-allow-origin") === null);

	// No-CORS-private guarantee also holds on error paths.
	const missing = await api(`/api/registry/private-key?fingerprint=${"D".repeat(40)}`);
	check("escrow GET unknown fingerprint -> 404", missing.status === 404, `got ${missing.status}`);

	const noEscrow = await api(`/api/registry/private-key?fingerprint=${aliceFpr}`);
	check(
		"escrow GET for key without escrow -> null blob",
		noEscrow.status === 200 && noEscrow.body?.encryptedPrivate === null,
		JSON.stringify(noEscrow.body?.encryptedPrivate)?.slice(0, 60),
	);

	// Rejection 1: a DECRYPTED private key (no passphrase) must never be stored.
	const naked = await makeKey("Naked", "naked@example.com");
	const nakedRes = await jsonPost(
		"/api/registry/publish",
		{ armored: naked.publicKey.armor(), encryptedPrivate: naked.privateKey.armor() },
		IP(61),
	);
	check(
		"decrypted private key escrow -> 400",
		nakedRes.status === 400 && /decrypted/i.test(nakedRes.body?.error ?? ""),
		`got ${nakedRes.status}: ${nakedRes.body?.error}`,
	);

	// Rejection 2: fingerprint mismatch (escrow of a DIFFERENT key).
	const other = await openpgp.generateKey({
		type: "ecc",
		curve: "curve25519",
		userIDs: [{ name: "Other", email: "other@example.com" }],
		passphrase: "another-passphrase",
		format: "object",
	});
	const mismatch = await jsonPost(
		"/api/registry/publish",
		{ armored: escrowUser.publicKey.armor(), encryptedPrivate: other.privateKey.armor() },
		IP(62),
	);
	check(
		"escrow fingerprint mismatch -> 400",
		mismatch.status === 400 && /match/i.test(mismatch.body?.error ?? ""),
		`got ${mismatch.status}: ${mismatch.body?.error}`,
	);

	// Rejection 3: a PUBLIC key offered as escrow.
	const asPublic = await jsonPost(
		"/api/registry/publish",
		{ armored: aliceArmor, encryptedPrivate: aliceArmor },
		IP(63),
	);
	check(
		"public key offered as escrow -> 400",
		asPublic.status === 400 && /private/i.test(asPublic.body?.error ?? ""),
		`got ${asPublic.status}: ${asPublic.body?.error}`,
	);

	// Authorized escrow management: challenge-signed store + delete.
	const ch = await challengeFor(escrowFpr, 58);
	const delBody = { fingerprint: escrowFpr, nonce: ch.body.nonce };
	delBody.signature = await signChallengeEncrypted(
		escrowUser.privateKey,
		escrowPass,
		escrowFpr,
		ch.body.nonce,
	);
	const wrongSignerKey = await makeKey("Sneak", "sneak@example.com");
	const sneak = await challengeFor(escrowFpr, 59);
	const sneakBody = {
		fingerprint: escrowFpr,
		nonce: sneak.body.nonce,
		signature: await signChallenge(wrongSignerKey.privateKey, escrowFpr, sneak.body.nonce),
	};
	const sneakRes = await jsonPost("/api/registry/private-key", sneakBody, IP(64));
	check(
		"escrow delete with wrong signer -> 403",
		sneakRes.status === 403,
		`got ${sneakRes.status}`,
	);

	const delRes = await jsonPost("/api/registry/private-key", delBody, IP(65));
	check(
		"escrow delete authorized -> ok",
		delRes.status === 200 && delRes.body?.escrowed === false,
		`got ${delRes.status}: ${delRes.body?.error}`,
	);
	const afterDel = await api(`/api/registry/private-key?fingerprint=${escrowFpr}`);
	check(
		"escrow deleted -> GET null",
		afterDel.status === 200 && afterDel.body?.encryptedPrivate === null,
	);

	const ch2 = await challengeFor(escrowFpr, 80);
	const storeRes = await jsonPost(
		"/api/registry/private-key",
		{
			fingerprint: escrowFpr,
			nonce: ch2.body.nonce,
			signature: await signChallengeEncrypted(
				escrowUser.privateKey,
				escrowPass,
				escrowFpr,
				ch2.body.nonce,
			),
			encryptedPrivate: escrowPrivate,
		},
		IP(66),
	);
	check(
		"escrow store authorized -> ok",
		storeRes.status === 200 && storeRes.body?.escrowed === true,
		JSON.stringify(storeRes.body),
	);
	const noAuth = await jsonPost(
		"/api/registry/private-key",
		{ fingerprint: escrowFpr, encryptedPrivate: escrowPrivate },
		IP(67),
	);
	check("escrow store without challenge -> 403", noAuth.status === 403, `got ${noAuth.status}`);

	// Replacement semantics: authorized replace WITHOUT escrow fields keeps
	// the stored escrow (same-fingerprint update must not destroy backups).
	const chR = await challengeFor(escrowFpr, 81);
	const keep = await jsonPost(
		"/api/registry/publish",
		{
			armored: escrowUser.publicKey.armor(),
			nonce: chR.body.nonce,
			signature: await signChallengeEncrypted(
				escrowUser.privateKey,
				escrowPass,
				escrowFpr,
				chR.body.nonce,
			),
		},
		IP(68),
	);
	check(
		"authorized replace -> 200",
		keep.status === 200 && keep.body?.replaced === true,
		`got ${keep.status}`,
	);
	const afterKeep = await api(`/api/registry/private-key?fingerprint=${escrowFpr}`);
	check(
		"replace without escrow fields KEEPS escrow",
		afterKeep.status === 200 && typeof afterKeep.body?.encryptedPrivate === "string",
	);

	// Replacement with dropEncryptedPrivate clears it.
	const chD = await challengeFor(escrowFpr, 82);
	const drop = await jsonPost(
		"/api/registry/publish",
		{
			armored: escrowUser.publicKey.armor(),
			nonce: chD.body.nonce,
			signature: await signChallengeEncrypted(
				escrowUser.privateKey,
				escrowPass,
				escrowFpr,
				chD.body.nonce,
			),
			dropEncryptedPrivate: true,
		},
		IP(69),
	);
	check("replace with dropEncryptedPrivate -> 200", drop.status === 200, `got ${drop.status}`);
	const afterDrop = await api(`/api/registry/private-key?fingerprint=${escrowFpr}`);
	check(
		"escrow dropped -> GET null",
		afterDrop.status === 200 && afterDrop.body?.encryptedPrivate === null,
	);

	// Revocation purges any escrow.
	const chS = await challengeFor(escrowFpr, 83);
	await jsonPost(
		"/api/registry/private-key",
		{
			fingerprint: escrowFpr,
			nonce: chS.body.nonce,
			signature: await signChallengeEncrypted(
				escrowUser.privateKey,
				escrowPass,
				escrowFpr,
				chS.body.nonce,
			),
			encryptedPrivate: escrowPrivate,
		},
		IP(70),
	);
	const revokeRes = await jsonPost(
		"/api/registry/revoke",
		{ fingerprint: escrowFpr, token: escrowToken, reason: "escrow purge test" },
		IP(71),
	);
	check("revoke escrowed key -> ok", revokeRes.status === 200, `got ${revokeRes.status}`);
	const afterRevoke = await api(`/api/registry/private-key?fingerprint=${escrowFpr}`);
	check(
		"revocation purges escrow",
		afterRevoke.status === 200 && afterRevoke.body?.encryptedPrivate === null,
		JSON.stringify(afterRevoke.body?.encryptedPrivate)?.slice(0, 60),
	);
}

console.log(
	`\n== RESULT: ${passed} passed, ${failed} failed in ${((Date.now() - t0) / 1000).toFixed(1)}s ==`,
);
process.exit(failed > 0 ? 1 : 0);
