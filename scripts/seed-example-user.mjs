/**
 * Seed an EXAMPLE user into the key registry — proving the full flow:
 * generate a key pair (passphrase-encrypted private), publish the public
 * key WITH encrypted-private escrow, and verify the registry can look it
 * up and hand the escrowed blob back.
 *
 * Usage:
 *   node scripts/seed-example-user.mjs                 # publish
 *   REGISTRY_TEST_BASE=https://… node scripts/seed-example-user.mjs
 *   node scripts/seed-example-user.mjs --show-secret   # print a reveal hint
 *
 * The full credentials (armored keys, passphrase, revocation token) are
 * written to .example-user.json (gitignored) — treat that file as a secret.
 * The passphrase is never echoed to the terminal, not even with
 * --show-secret: the flag prints a ready-made command that reveals it from
 * the JSON file, keeping secrets out of scrollback logs and CI output.
 * # Mr. AI Acting on s183173's Behalf
 */
import { createHash, randomBytes } from "node:crypto";
import { writeFileSync } from "node:fs";
import * as openpgp from "openpgp";

const BASE = process.env.REGISTRY_TEST_BASE ?? "http://localhost:3000";
const showSecret = process.argv.includes("--show-secret");

const EXAMPLE = {
	name: "Example User",
	email: "example.user@encryptor.app",
	label: "encryptor-example-user",
};

function log(step, message) {
	console.log(`[${step}] ${message}`);
}

async function main() {
	// 1. Generate an example key pair. The passphrase encrypts EVERY secret
	//    packet, which is exactly the form the registry accepts for escrow.
	const passphrase = randomBytes(24).toString("base64url");
	log("generate", `creating ECC (curve25519) key pair for ${EXAMPLE.name} <${EXAMPLE.email}>`);
	const { privateKey, publicKey } = await openpgp.generateKey({
		type: "ecc",
		curve: "curve25519",
		userIDs: [{ name: EXAMPLE.name, email: EXAMPLE.email }],
		passphrase,
		format: "object",
	});
	const fingerprint = publicKey.getFingerprint().toUpperCase();
	const keyId = publicKey.getKeyIDs()[0].toHex().toUpperCase();
	const publicArmored = publicKey.armor();
	const privateArmored = privateKey.armor();
	log("generate", `fingerprint ${fingerprint}`);

	// 2. Publish the public key WITH the encrypted private escrow.
	log("publish", `POST ${BASE}/api/registry/publish (public + encrypted private escrow)`);
	const res = await fetch(`${BASE}/api/registry/publish`, {
		method: "POST",
		headers: { "Content-Type": "application/json" },
		body: JSON.stringify({
			armored: publicArmored,
			encryptedPrivate: privateArmored,
		}),
	});
	const body = await res.json().catch(() => ({}));
	if (res.status === 409) {
		log("publish", `already registered (409): ${body.error ?? ""}`);
		log("publish", "if this was a previous seed run, its credentials are in .example-user.json");
		return;
	}
	if (!res.ok) {
		console.error(`publish failed: HTTP ${res.status}`, body);
		process.exit(1);
	}
	const token = body.revocationToken;
	log("publish", `ok — fingerprint ${body.fingerprint}, keyId ${body.keyId}`);
	log("publish", `emails indexed: ${(body.emails ?? []).join(", ") || "(none)"}`);
	log("publish", `revocation token: ${token}`);

	// 3. Verify public lookup by email works.
	const lookup = await fetch(
		`${BASE}/api/registry/lookup?email=${encodeURIComponent(EXAMPLE.email)}`,
	);
	const lookupBody = await lookup.json().catch(() => ({ keys: [] }));
	const hit = (lookupBody.keys ?? []).find((k) => k.fingerprint === fingerprint);
	log(
		"lookup",
		hit
			? `public key found by email ${EXAMPLE.email}`
			: "WARNING: lookup by email did NOT return the key",
	);

	// 4. Verify the escrowed private key is retrievable.
	const escrow = await fetch(`${BASE}/api/registry/private-key?fingerprint=${fingerprint}`);
	const escrowBody = await escrow.json().catch(() => ({}));
	const escrowed =
		typeof escrowBody.encryptedPrivate === "string" && escrowBody.encryptedPrivate.length > 0;
	log(
		"escrow",
		escrowed
			? "encrypted private key retrievable via /api/registry/private-key"
			: "WARNING: escrowed private key NOT retrievable",
	);

	// 5. Persist credentials locally (gitignored) so the operator can prove
	//    the restore flow with the passphrase later.
	const record = {
		...EXAMPLE,
		fingerprint,
		keyId,
		createdAt: new Date().toISOString(),
		passphrase,
		revocationToken: token,
		publicArmored,
		privateArmored,
	};
	writeFileSync(".example-user.json", JSON.stringify(record, null, 2));
	log("saved", "credentials written to .example-user.json (gitignored — treat as secret)");

	const tokenHash = createHash("sha256").update(token).digest("hex").slice(0, 12);
	console.log("\nSummary");
	console.log("  name        :", EXAMPLE.name);
	console.log("  email       :", EXAMPLE.email);
	console.log("  fingerprint :", fingerprint);
	console.log("  key id      :", keyId);
	console.log("  escrowed    :", escrowed ? "yes (passphrase-encrypted)" : "no");
	console.log("  token hash  :", `${tokenHash}… (stored server-side as SHA-256)`);
	if (showSecret)
		console.log("  passphrase  : reveal with →  jq -r .passphrase .example-user.json");
	else console.log("  passphrase  : (hidden — see .example-user.json, gitignored)");
}

main().catch((e) => {
	console.error(e);
	process.exit(1);
});
