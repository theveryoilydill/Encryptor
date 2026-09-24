/**
 * Secure HTML rendering for message views.
 *
 * # Mr. AI Acting on s183173's Behalf
 *
 * The composer is a markdown editor, but senders can embed raw HTML
 * (VS Code mode). react-markdown escapes raw HTML by default; to actually
 * RENDER it safely we run rehype-raw (parse the HTML) followed by
 * rehype-sanitize with a strict allow-list (GitHub-flavored defaults plus a
 * few harmless tags). Everything not explicitly allowed — scripts, event
 * handler attributes, styles, iframe/embed, javascript: URLs — is stripped
 * before it can reach the DOM.
 *
 * `envelope:` is allowed as an image src protocol so inline-attachment
 * markers survive sanitization; the actual URL guard remains
 * isSafeImageUrl, applied in the img component override (shared.tsx) AFTER
 * sanitization, so the final src is always an https or strictly-shaped
 * data:image URL.
 */
import type { Pluggable } from "unified";
import rehypeHighlight from "rehype-highlight";
import rehypeRaw from "rehype-raw";
import rehypeSanitize, { defaultSchema } from "rehype-sanitize";

export const messageSanitizeSchema = {
	...defaultSchema,
	tagNames: [
		...(defaultSchema.tagNames ?? []),
		// harmless extras messages commonly use:
		"details",
		"summary",
		"kbd",
		"mark",
		"abbr",
		"sub",
		"sup",
	],
	protocols: {
		...defaultSchema.protocols,
		href: ["http", "https", "mailto"],
		// data: (base64 images) + envelope: (inline-attachment markers) — the
		// img override in shared.tsx re-guards every src after sanitization.
		src: ["https", "data", "envelope"],
		cite: ["http", "https"],
	},
	attributes: {
		...defaultSchema.attributes,
		"*": [...(defaultSchema.attributes?.["*"] ?? []), "abbr", "title"],
		img: [
			...(defaultSchema.attributes?.img ?? []),
			// alt|NN%[@dx,dy] inline-image metadata travels in alt text
			"alt",
			"src",
			"width",
			"height",
		],
	},
	strip: ["script", "style", "iframe", "object", "embed", "form", "link", "meta"],
};

/** rehype plugin pair ready to spread into react-markdown's rehypePlugins:
 *  rehype-raw parses the HTML the sender wrote, then rehype-sanitize
 *  strips everything the schema does not explicitly allow. rehype-highlight
 *  runs LAST — after sanitization — so the token spans it injects
 *  (className="hljs-*") never need their own sanitize rules: nothing
 *  sender-controlled can influence them (the language class must already
 *  match the strict code.className allow-list to survive sanitization). */
export const rehypeSecureHtml: Pluggable[] = [
	rehypeRaw,
	[rehypeSanitize, messageSanitizeSchema],
	[rehypeHighlight, { detect: false }],
];
