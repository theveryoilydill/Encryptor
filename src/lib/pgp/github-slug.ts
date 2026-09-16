/**
 * GitHub-style heading anchors shared by the composer's TOC builder and the
 * rendered-message view (heading ids), so "Insert table of contents" links
 * jump to the right heading everywhere the message is rendered.
 *
 * # Mr. AI Acting on s183173's Behalf
 */

/** GitHub-style anchor slug for a heading title: lowercase, strip every
 *  character that is not a letter, number, space or hyphen, then spaces
 *  become hyphens. Mirrors the anchors GitHub generates for its own
 *  headings, so TOC links keep working when the message is pasted into a
 *  GitHub issue, README or comment. */
export function githubSlug(title: string): string {
	return title
		.toLowerCase()
		.replace(/[^\p{L}\p{N}\s-]/gu, "")
		.replace(/\s+/g, "-");
}
