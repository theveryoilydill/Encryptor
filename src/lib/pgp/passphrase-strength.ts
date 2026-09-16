/**
 * Lightweight, dependency-free passphrase strength estimation (zxcvbn-style
 * heuristics, deliberately conservative). # Mr. AI Acting on s183173's Behalf
 *
 * This is NOT a cryptographically rigorous entropy measure — it is a UI guide
 * that catches the failure modes that matter in practice: short passphrases,
 * single character classes, dictionary/keyboard patterns, and the classic
 * "word + digits" shapes. Everything runs synchronously in well under a
 * millisecond for realistic inputs (the corpus is tiny and bounded).
 */

export interface PassphraseStrength {
	/** 0 = very weak … 4 = excellent. */
	score: 0 | 1 | 2 | 3 | 4;
	/** Short human label for the meter. */
	label: string;
	/** One actionable suggestion, or null when the passphrase is strong. */
	hint: string | null;
	/** Rough entropy estimate in bits (pattern-penalized). */
	entropyBits: number;
}

/** Top offenders from public breach corpora (kept tiny on purpose). */
const COMMON_PASSWORDS = new Set([
	"password",
	"passw0rd",
	"password1",
	"123456",
	"12345678",
	"123456789",
	"1234567890",
	"qwerty",
	"qwertyuiop",
	"abc123",
	"letmein",
	"welcome",
	"monkey",
	"dragon",
	"football",
	"baseball",
	"iloveyou",
	"admin",
	"login",
	"princess",
	"sunshine",
	"master",
	"hello",
	"freedom",
	"whatever",
	"qazwsx",
	"trustno1",
	"superman",
	"starwars",
	"shadow",
	"michael",
	"jennifer",
	"111111",
	"000000",
	"121212",
	"654321",
	"696969",
	"123123",
	"azerty",
	"encrypted",
	"encryptor",
	"openpgp",
	"prettygoodprivacy",
	"pgpkey",
]);

/** Small dictionary of common words used in passphrase cracking seeds. */
const COMMON_WORDS = new Set([
	"love",
	"secret",
	"summer",
	"winter",
	"spring",
	"autumn",
	"gamer",
	"hunter",
	"player",
	"school",
	"coffee",
	"matrix",
	"network",
	"system",
	"google",
	"apple",
	"samsung",
	"nintendo",
	"playstation",
	"crypto",
	"bitcoin",
	"wallet",
	"private",
	"public",
	"secure",
	"safety",
	"silver",
	"golden",
	"diamond",
	"orange",
	"purple",
	"yellow",
	"banana",
	"cherry",
]);

const KEYBOARD_ROWS = ["qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890"];

const SEQUENCES = ["abcdefghijklmnopqrstuvwxyz", "01234567890"];

/** Collapse common leet substitutions so "p4ssw0rd" still matches. */
function deLeet(s: string): string {
	return s
		.replace(/4/g, "a")
		.replace(/8/g, "b")
		.replace(/3/g, "e")
		.replace(/1/g, "i")
		.replace(/0/g, "o")
		.replace(/5/g, "s")
		.replace(/7/g, "t")
		.replace(/\$/g, "s")
		.replace(/@/g, "a");
}

/** Longest run of adjacent repeats like "aaa" or "111" (case-folded). */
function longestRepeat(s: string): number {
	let best = 0;
	let run = 0;
	let prev = "";
	for (const ch of s.toLowerCase()) {
		run = ch === prev ? run + 1 : 1;
		prev = ch;
		if (run > best) best = run;
	}
	return best;
}

/** True if the lowercase string contains a ≥4-char keyboard walk. */
function hasKeyboardWalk(s: string): boolean {
	const low = s.toLowerCase();
	for (const row of KEYBOARD_ROWS) {
		const reversed = [...row].reverse().join("");
		for (const seq of [row, reversed]) {
			for (let i = 0; i + 4 <= seq.length; i++) {
				if (low.includes(seq.slice(i, i + 4))) return true;
			}
		}
	}
	return false;
}

/** True if the string contains a ≥4-char alphabetical/numeric sequence. */
function hasSequence(s: string): boolean {
	for (const seq of SEQUENCES) {
		const reversed = [...seq].reverse().join("");
		for (const src of [seq, reversed]) {
			for (let i = 0; i + 4 <= src.length; i++) {
				if (s.includes(src.slice(i, i + 4))) return true;
			}
		}
	}
	return false;
}

/** Charset size for the Shannon-style entropy estimate. */
function charsetSize(s: string): number {
	let size = 0;
	if (/[a-z]/.test(s)) size += 26;
	if (/[A-Z]/.test(s)) size += 26;
	if (/[0-9]/.test(s)) size += 10;
	if (/[^a-zA-Z0-9]/.test(s)) size += 33;
	return size;
}

/**
 * Estimate passphrase strength. Score bands (approximate crack resistance):
 *   0 — trivially guessable;  1 — offline-attackable in minutes;
 *   2 — days-to-months;       3 — years (good for escrowed keys);
 *   4 — generational ( diceware-length or high mixed-class entropy ).
 */
export function estimatePassphraseStrength(passphrase: string): PassphraseStrength {
	const empty: PassphraseStrength = { score: 0, label: "Too weak", hint: null, entropyBits: 0 };
	if (!passphrase) return empty;

	const len = passphrase.length;
	const lower = passphrase.toLowerCase();
	const deLeeted = deLeet(lower);

	// Base charset entropy…
	let bits = len * Math.log2(Math.max(charsetSize(passphrase), 2));

	// …then pattern penalties.
	const classes =
		(/[a-z]/.test(passphrase) ? 1 : 0) +
		(/[A-Z]/.test(passphrase) ? 1 : 0) +
		(/[0-9]/.test(passphrase) ? 1 : 0) +
		(/[^a-zA-Z0-9]/.test(passphrase) ? 1 : 0);

	let hint: string | null = null;
	let penalized = false;

	if (len < 8) {
		return {
			score: 0,
			label: "Too weak",
			hint: "Use at least 8 characters — longer is much stronger.",
			entropyBits: bits,
		};
	}

	const repeat = longestRepeat(passphrase);
	if (repeat >= 3) {
		bits -= repeat * 4;
		penalized = true;
		hint ??= "Avoid repeating the same character 3+ times.";
	}
	if (hasKeyboardWalk(deLeeted)) {
		bits -= 12;
		penalized = true;
		hint ??= "Keyboard walks (e.g. “qwer”, “1234”) are easy to guess.";
	}
	if (hasSequence(deLeeted)) {
		bits -= 10;
		penalized = true;
		hint ??= "Sequences (abcd, 4321) add little strength.";
	}
	if (COMMON_PASSWORDS.has(lower) || COMMON_PASSWORDS.has(deLeeted)) {
		bits = Math.min(bits, 10);
		penalized = true;
		hint = "This is one of the most breached passwords — never use it.";
	} else {
		// Containment (e.g. “Letmein!2024”, “qwerty1234”): heavy penalty —
		// the matched word dominates the guessable search space.
		const hit = [...COMMON_PASSWORDS, ...COMMON_WORDS].find(
			(w) => w.length >= 5 && deLeeted.includes(w),
		);
		if (hit) {
			bits -= 35;
			penalized = true;
			hint ??= `Contains the well-known password word “${hit}” — avoid it.`;
		}
	}
	if (classes === 1 && len < 20) {
		bits -= 8;
		penalized = true;
		hint ??= "Mix letter cases, digits, or symbols — or go much longer.";
	}
	if (/^[a-z]+[\d!?.@#$%^&*-]{1,6}$/.test(lower)) {
		bits -= 10;
		penalized = true;
		hint ??= "“Word + digits” shapes are the first thing attackers try.";
	}
	if (len < 12 && !penalized) {
		hint ??= "A 4–5 word passphrase or 16+ mixed characters is ideal.";
	}

	bits = Math.max(bits, 0);

	// Score bands on the penalized entropy estimate, floored by hard rules.
	let score: 0 | 1 | 2 | 3 | 4;
	if (bits < 28) score = 0;
	else if (bits < 40) score = 1;
	else if (bits < 56) score = 2;
	else if (bits < 76) score = 3;
	else score = 4;
	if (len >= 16 && classes >= 3) score = Math.max(score, 3) as 3 | 4;
	if (len >= 20 && classes >= 2 && !COMMON_PASSWORDS.has(deLeeted)) {
		score = Math.max(score, 3) as 3 | 4;
	}

	const labels = ["Too weak", "Weak", "Fair", "Strong", "Excellent"] as const;
	if (score >= 3) hint = null;
	return { score, label: labels[score], hint, entropyBits: Math.round(bits) };
}
