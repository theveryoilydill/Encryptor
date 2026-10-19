/**
 * GitHub-style heading anchors shared by the composer's TOC builder and the
 * rendered-message view (heading ids), so "Insert table of contents" links
 * jump to the right heading everywhere the message is rendered.
 *
 * # Mr. AI Acting on the Owner's Behalf
 */

/**
 * GitHub-style anchor slug for a heading title. Mirrors GitHub's algorithm
 * (github/markdown-anchor generation): lowercase, DROP every character that
 * is not a letter, number, space, hyphen or underscore, then replace EACH
 * space with its own hyphen. The two details that matter for parity:
 *   - runs of whitespace become RUNS of hyphens ("Audio  Video" ->
 *     #audio--video, "Foo — bar" -> #foo--bar after the em dash is dropped),
 *   - underscores are KEPT ("my_var" stays #my_var).
 * Matching GitHub exactly is the point: TOC links built by the composer keep
 * working when the message is pasted into a GitHub issue, README or comment.
 * Non-space whitespace (tabs, newlines) is removed, not hyphenated.
 */
export function githubSlug(title: string): string {
	return (
		title
			.toLowerCase()
			// Only U+0020 survives as a space: other whitespace (tabs, newlines)
			// is not in the allowed set and is dropped outright, matching GitHub.
			.replace(/[^\p{L}\p{N} _-]/gu, "")
			.replace(/ /g, "-")
	);
}
