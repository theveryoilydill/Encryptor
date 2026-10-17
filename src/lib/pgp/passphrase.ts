/**
 * Passphrase utilities — pure functions, no DOM.
 *
 * generatePassphrase builds a memorable, cryptographically random passphrase
 * using crypto.getRandomValues (never Math.random), suitable for the
 * "generate a new local key" flow. estimateStrength is a cheap UI-only
 * heuristic and is NOT a security measure.
 */

/** Short, memorable English words (security-flavored + common, 3–8 chars,
 *  lowercase). Exactly 64 entries → one word carries exactly 6 bits of
 *  entropy when picked uniformly (log2(64)). */
const WORDS: readonly string[] = [
	"anchor",
	"atlas",
	"bamboo",
	"beacon",
	"bishop",
	"bramble",
	"breeze",
	"cactus",
	"canyon",
	"castle",
	"cedar",
	"cipher",
	"cobalt",
	"comet",
	"compass",
	"copper",
	"coral",
	"cosmos",
	"crimson",
	"crystal",
	"delta",
	"dolphin",
	"dragon",
	"ember",
	"falcon",
	"feather",
	"flint",
	"forest",
	"fossil",
	"galaxy",
	"garnet",
	"glacier",
	"granite",
	"harbor",
	"harvest",
	"hazel",
	"horizon",
	"ivory",
	"jaguar",
	"jasmine",
	"kernel",
	"lagoon",
	"lantern",
	"lattice",
	"lemon",
	"lynx",
	"magnet",
	"maple",
	"marble",
	"meadow",
	"meteor",
	"mirror",
	"nebula",
	"nimbus",
	"oasis",
	"onyx",
	"orbit",
	"otter",
	"panda",
	"pebble",
	"pelican",
	"quartz",
	"raven",
	"summit",
];

/** Uniform random integer in [0, max) via rejection sampling on Uint32 —
 *  unbiased for any max, unlike a plain modulo. */
function randomInt(max: number): number {
	const range = 0x100000000; // 2^32
	const limit = range - (range % max);
	const buf = new Uint32Array(1);
	let value = 0;
	do {
		crypto.getRandomValues(buf);
		value = buf[0]!;
	} while (value >= limit);
	return value % max;
}

/**
 * Generate a dash-joined passphrase of `words` random words plus a 2-digit
 * suffix, e.g. "ember-vault" style: "granite-harbor-kernel-quartz-raven-42".
 *
 * ENTROPY: the 64-word list gives 6 bits per word (log2(64)); the 2-digit
 * suffix adds log2(100) ≈ 6.64 bits. Default 5 words → 5×6 + 6.64 ≈ 36.6 bits;
 * pass more words for higher entropy (≈ 6·words + 6.64 bits total).
 */
export function generatePassphrase(words = 5): string {
	const count = Math.max(1, Math.floor(words));
	const picked: string[] = [];
	for (let i = 0; i < count; i++) {
		picked.push(WORDS[randomInt(WORDS.length)]);
	}
	const digits = String(randomInt(100)).padStart(2, "0");
	return `${picked.join("-")}-${digits}`;
}

const STRENGTH_LABELS: readonly [string, string, string, string, string] = [
	"Very weak",
	"Weak",
	"Fair",
	"Strong",
	"Very strong",
];

/**
 * Cheap length/charset heuristic (0–4) for UI feedback only. Score grows
 * with length (≥8 / ≥12 / ≥16 chars); a mix of ≥3 character classes
 * (lowercase, uppercase, digits, other) earns +1, capped at 4.
 */
export function estimateStrength(pw: string): { score: 0 | 1 | 2 | 3 | 4; label: string } {
	if (!pw) return { score: 0, label: STRENGTH_LABELS[0] };
	let score = 0;
	if (pw.length >= 8) score++;
	if (pw.length >= 12) score++;
	if (pw.length >= 16) score++;
	const classes = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^A-Za-z0-9]/].filter((re) => re.test(pw)).length;
	if (classes >= 3) score++;
	score = Math.min(4, score);
	return { score: score as 0 | 1 | 2 | 3 | 4, label: STRENGTH_LABELS[score] };
}
