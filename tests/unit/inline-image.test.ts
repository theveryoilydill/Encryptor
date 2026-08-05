/**
 * Unit tests for the inline image marker helpers.
 *
 * Covers parsing, building, scaling, and removal of
 * `![alt|NN%](envelope://filename)` markers — the syntax used to embed
 * pasted images inline in encrypted message bodies.
 */
import { describe, expect, it } from "vitest";
import {
  buildInlineImageMarker,
  DEFAULT_INLINE_IMAGE_SCALE,
  findInlineImageMarkers,
  MAX_INLINE_IMAGE_SCALE,
  MIN_INLINE_IMAGE_SCALE,
  parseInlineImageAlt,
  removeMarker,
  updateMarkerScale,
} from "@/lib/pgp/inline-image";

describe("parseInlineImageAlt", () => {
  it("parses a name + scale suffix", () => {
    expect(parseInlineImageAlt("cat.png|50%")).toEqual({
      displayName: "cat.png",
      scale: 50,
    });
  });

  it("defaults to 100% when no scale suffix is present", () => {
    expect(parseInlineImageAlt("cat.png")).toEqual({
      displayName: "cat.png",
      scale: 100,
    });
  });

  it("handles an empty display name with a scale", () => {
    expect(parseInlineImageAlt("|75%")).toEqual({
      displayName: "",
      scale: 75,
    });
  });

  it("treats a non-numeric suffix as part of the display name", () => {
    // `|not-a-number%` doesn't match the `\|(\d+)%$` regex, so the whole
    // string becomes the displayName and scale defaults to 100.
    expect(parseInlineImageAlt("photo |large%")).toEqual({
      displayName: "photo |large%",
      scale: 100,
    });
  });

  it("handles display names that contain pipes elsewhere", () => {
    expect(parseInlineImageAlt("foo|bar|25%")).toEqual({
      displayName: "foo|bar",
      scale: 25,
    });
  });
});

describe("findInlineImageMarkers", () => {
  it("returns an empty array when there are no markers", () => {
    expect(findInlineImageMarkers("just plain text")).toEqual([]);
  });

  it("returns an empty array for an empty string", () => {
    expect(findInlineImageMarkers("")).toEqual([]);
  });

  it("finds a single marker with a scale", () => {
    const text = "Hello\n![cat.png|50%](envelope://cat.png)\nWorld";
    const markers = findInlineImageMarkers(text);
    expect(markers).toHaveLength(1);
    expect(markers[0]).toMatchObject({
      filename: "cat.png",
      scale: 50,
      displayName: "cat.png",
    });
    expect(markers[0].fullMatch).toBe("![cat.png|50%](envelope://cat.png)");
    // Indexes are correct: marker starts after "Hello\n"
    expect(text.slice(markers[0].startIndex, markers[0].endIndex)).toBe(
      markers[0].fullMatch,
    );
  });

  it("finds multiple markers in order", () => {
    const text =
      "![a.png|10%](envelope://a.png) middle ![b.jpg|200%](envelope://b.jpg)";
    const markers = findInlineImageMarkers(text);
    expect(markers).toHaveLength(2);
    expect(markers[0].filename).toBe("a.png");
    expect(markers[0].scale).toBe(10);
    expect(markers[1].filename).toBe("b.jpg");
    expect(markers[1].scale).toBe(200);
  });

  it("defaults to 100% scale when the suffix is omitted", () => {
    const text = "![photo.png](envelope://photo.png)";
    const markers = findInlineImageMarkers(text);
    expect(markers).toHaveLength(1);
    expect(markers[0].scale).toBe(100);
    expect(markers[0].displayName).toBe("photo.png");
  });

  it("decodes URI-encoded filenames", () => {
    // Spaces and special characters get encoded by buildInlineImageMarker.
    const marker = buildInlineImageMarker("my photo.png", 50);
    expect(marker).toContain("envelope://my%20photo.png");
    const parsed = findInlineImageMarkers(marker);
    expect(parsed[0].filename).toBe("my photo.png");
  });

  it("ignores non-envelope image markdown", () => {
    // Regular markdown images (https:// URLs) should NOT be picked up.
    const text = "![cat](https://example.com/cat.png)";
    expect(findInlineImageMarkers(text)).toEqual([]);
  });

  it("does not match across newlines for the URI group", () => {
    // The `[^)\s]+` character class excludes whitespace, so a URI with a
    // newline in it won't match — protects against greedy matching bugs.
    const text = "![a](envelope://a\n.png)";
    expect(findInlineImageMarkers(text)).toEqual([]);
  });
});

describe("buildInlineImageMarker", () => {
  it("builds a marker with the given scale", () => {
    expect(buildInlineImageMarker("cat.png", 50)).toBe(
      "![cat.png|50%](envelope://cat.png)",
    );
  });

  it("uses 100% scale explicitly", () => {
    expect(buildInlineImageMarker("cat.png", 100)).toBe(
      "![cat.png|100%](envelope://cat.png)",
    );
  });

  it("uses a custom display name when provided", () => {
    expect(buildInlineImageMarker("cat-1.png", 50, "cat.png")).toBe(
      "![cat.png|50%](envelope://cat-1.png)",
    );
  });

  it("clamps scale to the maximum", () => {
    expect(buildInlineImageMarker("cat.png", 500)).toBe(
      `![cat.png|${MAX_INLINE_IMAGE_SCALE}%](envelope://cat.png)`,
    );
  });

  it("clamps scale to the minimum", () => {
    expect(buildInlineImageMarker("cat.png", 1)).toBe(
      `![cat.png|${MIN_INLINE_IMAGE_SCALE}%](envelope://cat.png)`,
    );
  });

  it("URI-encodes special characters in the filename", () => {
    expect(buildInlineImageMarker("my photo.png", 50)).toBe(
      "![my photo.png|50%](envelope://my%20photo.png)",
    );
  });

  it("produces the default scale used for newly-pasted images", () => {
    expect(DEFAULT_INLINE_IMAGE_SCALE).toBe(50);
  });
});

describe("updateMarkerScale", () => {
  it("updates the scale of the marker at the given index", () => {
    const text = "![cat.png|50%](envelope://cat.png)";
    const updated = updateMarkerScale(text, 0, 75);
    expect(updated).toBe("![cat.png|75%](envelope://cat.png)");
  });

  it("preserves the display name and filename", () => {
    const text = "![My Cat|50%](envelope://cat-1.png)";
    const updated = updateMarkerScale(text, 0, 25);
    expect(updated).toBe("![My Cat|25%](envelope://cat-1.png)");
  });

  it("updates only the targeted marker when multiple are present", () => {
    const text =
      "![a.png|10%](envelope://a.png) X ![b.png|20%](envelope://b.png)";
    const updated = updateMarkerScale(text, 1, 90);
    expect(updated).toBe(
      "![a.png|10%](envelope://a.png) X ![b.png|90%](envelope://b.png)",
    );
  });

  it("returns the text unchanged when the index is out of bounds", () => {
    const text = "![a.png|10%](envelope://a.png)";
    expect(updateMarkerScale(text, 5, 50)).toBe(text);
  });

  it("clamps the new scale to the valid range", () => {
    const text = "![a.png|10%](envelope://a.png)";
    expect(updateMarkerScale(text, 0, 500)).toBe(
      `![a.png|${MAX_INLINE_IMAGE_SCALE}%](envelope://a.png)`,
    );
    expect(updateMarkerScale(text, 0, 0)).toBe(
      `![a.png|${MIN_INLINE_IMAGE_SCALE}%](envelope://a.png)`,
    );
  });
});

describe("removeMarker", () => {
  it("removes the marker at the given index", () => {
    const text = "before ![cat.png|50%](envelope://cat.png) after";
    const result = removeMarker(text, 0);
    expect(result).toBe("before  after");
  });

  it("also strips a single trailing newline pair", () => {
    const text = "Text\n\n![cat.png|50%](envelope://cat.png)\n\nMore text";
    const result = removeMarker(text, 0);
    // Trailing pair is stripped, leading pair is kept (so the two
    // surrounding paragraphs remain separated by a single \n\n).
    expect(result).toBe("Text\n\nMore text");
  });

  it("preserves paragraph separation when the marker sat between two paragraphs", () => {
    const text = "Para 1\n\n![cat.png|50%](envelope://cat.png)\n\nPara 2";
    const result = removeMarker(text, 0);
    // Both a leading and trailing \n\n are present — only the trailing one
    // is stripped, so a single \n\n remains separating the two paragraphs.
    expect(result).toBe("Para 1\n\nPara 2");
  });

  it("strips the leading newline pair when there is no trailing one", () => {
    const text = "Para 1\n\n![cat.png|50%](envelope://cat.png)Para 2";
    const result = removeMarker(text, 0);
    // No trailing newline → fall back to stripping the leading \n\n.
    expect(result).toBe("Para 1Para 2");
  });

  it("removes only the targeted marker when multiple are present", () => {
    const text =
      "![a.png|10%](envelope://a.png) X ![b.png|20%](envelope://b.png)";
    const result = removeMarker(text, 0);
    expect(result).toBe(" X ![b.png|20%](envelope://b.png)");
  });

  it("returns the text unchanged when the index is out of bounds", () => {
    const text = "![a.png|10%](envelope://a.png)";
    expect(removeMarker(text, 5)).toBe(text);
  });

  it("handles a marker at the very start of the text", () => {
    const text = "![cat.png|50%](envelope://cat.png)\nMore";
    const result = removeMarker(text, 0);
    expect(result).toBe("More");
  });

  it("handles a marker at the very end of the text", () => {
    const text = "More\n![cat.png|50%](envelope://cat.png)";
    const result = removeMarker(text, 0);
    expect(result).toBe("More");
  });
});

describe("round-trip: build → find → scale", () => {
  it("can build, find, rescale, and re-find a marker", () => {
    // Build a marker
    const marker = buildInlineImageMarker("photo.png", 50);
    expect(marker).toBe("![photo.png|50%](envelope://photo.png)");

    // Embed it in text
    const text = `Hello\n${marker}\nWorld`;

    // Find it
    const found = findInlineImageMarkers(text);
    expect(found).toHaveLength(1);
    expect(found[0].scale).toBe(50);

    // Scale it up
    const scaled = updateMarkerScale(text, 0, 125);
    expect(scaled).toContain("|125%");

    // Find it again — scale should be updated
    const found2 = findInlineImageMarkers(scaled);
    expect(found2[0].scale).toBe(125);
    expect(found2[0].filename).toBe("photo.png");
  });

  it("preserves attachment references across scale changes", () => {
    // The filename in the envelope:// URI must NOT change when the scale
    // changes — otherwise the rendered image would break.
    const text = "![My Holiday Photo|50%](envelope://img-001.png)";
    const scaled = updateMarkerScale(text, 0, 75);
    expect(scaled).toContain("envelope://img-001.png");
    expect(scaled).toContain("My Holiday Photo");
    expect(scaled).toContain("|75%");
  });
});
