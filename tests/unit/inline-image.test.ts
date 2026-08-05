/**
 * Unit tests for the inline image marker helpers.
 *
 * Covers parsing, building, scaling, positioning, and removal of
 * `![alt|NN%[@dx,dy]](envelope://filename)` markers — the syntax used to
 * embed pasted images inline in encrypted message bodies with scale and
 * position offsets.
 */
import { describe, expect, it } from "vitest";
import {
  buildInlineImageMarker,
  DEFAULT_INLINE_IMAGE_SCALE,
  findInlineImageMarkers,
  MAX_INLINE_IMAGE_SCALE,
  MIN_INLINE_IMAGE_SCALE,
  MOVE_STEP_MICRO,
  MOVE_STEP_NORMAL,
  parseInlineImageAlt,
  removeMarker,
  SCALE_STEP_MICRO,
  SCALE_STEP_NORMAL,
  updateMarkerScale,
  updateMarkerTransform,
} from "@/lib/pgp/inline-image";

describe("parseInlineImageAlt", () => {
  it("parses a name + scale suffix", () => {
    expect(parseInlineImageAlt("cat.png|50%")).toEqual({
      displayName: "cat.png",
      scale: 50,
      dx: 0,
      dy: 0,
    });
  });

  it("defaults to 100% scale and 0,0 position when no suffixes are present", () => {
    expect(parseInlineImageAlt("cat.png")).toEqual({
      displayName: "cat.png",
      scale: 100,
      dx: 0,
      dy: 0,
    });
  });

  it("parses scale + position suffix", () => {
    expect(parseInlineImageAlt("cat.png|50%@10,-5")).toEqual({
      displayName: "cat.png",
      scale: 50,
      dx: 10,
      dy: -5,
    });
  });

  it("parses position-only suffix (no scale)", () => {
    expect(parseInlineImageAlt("cat.png@10,-5")).toEqual({
      displayName: "cat.png",
      scale: 100,
      dx: 10,
      dy: -5,
    });
  });

  it("handles negative position values", () => {
    expect(parseInlineImageAlt("cat.png|75%@-100,-200")).toEqual({
      displayName: "cat.png",
      scale: 75,
      dx: -100,
      dy: -200,
    });
  });

  it("handles zero position values", () => {
    expect(parseInlineImageAlt("cat.png|50%@0,0")).toEqual({
      displayName: "cat.png",
      scale: 50,
      dx: 0,
      dy: 0,
    });
  });

  it("handles an empty display name with a scale", () => {
    expect(parseInlineImageAlt("|75%")).toEqual({
      displayName: "",
      scale: 75,
      dx: 0,
      dy: 0,
    });
  });

  it("treats a non-numeric suffix as part of the display name", () => {
    expect(parseInlineImageAlt("photo |large%")).toEqual({
      displayName: "photo |large%",
      scale: 100,
      dx: 0,
      dy: 0,
    });
  });

  it("handles display names that contain pipes elsewhere", () => {
    expect(parseInlineImageAlt("foo|bar|25%@5,5")).toEqual({
      displayName: "foo|bar",
      scale: 25,
      dx: 5,
      dy: 5,
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
      dx: 0,
      dy: 0,
    });
    expect(markers[0].fullMatch).toBe("![cat.png|50%](envelope://cat.png)");
    expect(text.slice(markers[0].startIndex, markers[0].endIndex)).toBe(markers[0].fullMatch);
  });

  it("finds a marker with scale + position", () => {
    const text = "![cat.png|50%@10,-5](envelope://cat.png)";
    const markers = findInlineImageMarkers(text);
    expect(markers).toHaveLength(1);
    expect(markers[0]).toMatchObject({
      filename: "cat.png",
      scale: 50,
      dx: 10,
      dy: -5,
      displayName: "cat.png",
    });
  });

  it("finds multiple markers in order", () => {
    const text = "![a.png|10%@0,0](envelope://a.png) middle ![b.jpg|200%@-5,10](envelope://b.jpg)";
    const markers = findInlineImageMarkers(text);
    expect(markers).toHaveLength(2);
    expect(markers[0].filename).toBe("a.png");
    expect(markers[0].scale).toBe(10);
    expect(markers[0].dx).toBe(0);
    expect(markers[0].dy).toBe(0);
    expect(markers[1].filename).toBe("b.jpg");
    expect(markers[1].scale).toBe(200);
    expect(markers[1].dx).toBe(-5);
    expect(markers[1].dy).toBe(10);
  });

  it("defaults to 100% scale and 0,0 position when suffixes are omitted", () => {
    const text = "![photo.png](envelope://photo.png)";
    const markers = findInlineImageMarkers(text);
    expect(markers).toHaveLength(1);
    expect(markers[0].scale).toBe(100);
    expect(markers[0].dx).toBe(0);
    expect(markers[0].dy).toBe(0);
    expect(markers[0].displayName).toBe("photo.png");
  });

  it("decodes URI-encoded filenames", () => {
    const marker = buildInlineImageMarker("my photo.png", 50);
    expect(marker).toContain("envelope://my%20photo.png");
    const parsed = findInlineImageMarkers(marker);
    expect(parsed[0].filename).toBe("my photo.png");
  });

  it("ignores non-envelope image markdown", () => {
    const text = "![cat](https://example.com/cat.png)";
    expect(findInlineImageMarkers(text)).toEqual([]);
  });

  it("does not match across newlines for the URI group", () => {
    const text = "![a](envelope://a\n.png)";
    expect(findInlineImageMarkers(text)).toEqual([]);
  });

  it("is backward compatible with old markers that have no position", () => {
    const text = "![cat.png|50%](envelope://cat.png)";
    const markers = findInlineImageMarkers(text);
    expect(markers).toHaveLength(1);
    expect(markers[0].scale).toBe(50);
    expect(markers[0].dx).toBe(0);
    expect(markers[0].dy).toBe(0);
  });
});

describe("buildInlineImageMarker", () => {
  it("builds a marker with the given scale and no position", () => {
    expect(buildInlineImageMarker("cat.png", 50)).toBe("![cat.png|50%](envelope://cat.png)");
  });

  it("builds a marker with scale + position", () => {
    expect(buildInlineImageMarker("cat.png", 50, 10, -5)).toBe(
      "![cat.png|50%@10,-5](envelope://cat.png)",
    );
  });

  it("omits the @0,0 suffix when position is (0,0)", () => {
    expect(buildInlineImageMarker("cat.png", 50, 0, 0)).toBe("![cat.png|50%](envelope://cat.png)");
  });

  it("uses 100% scale explicitly", () => {
    expect(buildInlineImageMarker("cat.png", 100)).toBe("![cat.png|100%](envelope://cat.png)");
  });

  it("uses a custom display name when provided", () => {
    expect(buildInlineImageMarker("cat-1.png", 50, 0, 0, "cat.png")).toBe(
      "![cat.png|50%](envelope://cat-1.png)",
    );
  });

  it("uses a custom display name with position", () => {
    expect(buildInlineImageMarker("cat-1.png", 75, 5, 10, "My Cat")).toBe(
      "![My Cat|75%@5,10](envelope://cat-1.png)",
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

  it("preserves the display name, filename, and position", () => {
    const text = "![My Cat|50%@10,-5](envelope://cat-1.png)";
    const updated = updateMarkerScale(text, 0, 25);
    expect(updated).toBe("![My Cat|25%@10,-5](envelope://cat-1.png)");
  });

  it("updates only the targeted marker when multiple are present", () => {
    const text = "![a.png|10%@0,0](envelope://a.png) X ![b.png|20%@5,5](envelope://b.png)";
    const updated = updateMarkerScale(text, 1, 90);
    expect(updated).toBe("![a.png|10%@0,0](envelope://a.png) X ![b.png|90%@5,5](envelope://b.png)");
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

describe("updateMarkerTransform", () => {
  it("updates only the scale", () => {
    const text = "![cat.png|50%@10,-5](envelope://cat.png)";
    const updated = updateMarkerTransform(text, 0, { scale: 75 });
    expect(updated).toBe("![cat.png|75%@10,-5](envelope://cat.png)");
  });

  it("updates only the position", () => {
    const text = "![cat.png|50%@10,-5](envelope://cat.png)";
    const updated = updateMarkerTransform(text, 0, { dx: 20, dy: 30 });
    expect(updated).toBe("![cat.png|50%@20,30](envelope://cat.png)");
  });

  it("updates scale and position together", () => {
    const text = "![cat.png|50%@10,-5](envelope://cat.png)";
    const updated = updateMarkerTransform(text, 0, {
      scale: 75,
      dx: 0,
      dy: 0,
    });
    // When dx=0 and dy=0, the @0,0 suffix is omitted.
    expect(updated).toBe("![cat.png|75%](envelope://cat.png)");
  });

  it("preserves unspecified fields", () => {
    const text = "![cat.png|50%@10,-5](envelope://cat.png)";
    const updated = updateMarkerTransform(text, 0, { dx: 20 });
    expect(updated).toBe("![cat.png|50%@20,-5](envelope://cat.png)");
  });

  it("adds position to a marker that had none", () => {
    const text = "![cat.png|50%](envelope://cat.png)";
    const updated = updateMarkerTransform(text, 0, { dx: 5, dy: 10 });
    expect(updated).toBe("![cat.png|50%@5,10](envelope://cat.png)");
  });

  it("returns the text unchanged when the index is out of bounds", () => {
    const text = "![a.png|10%](envelope://a.png)";
    expect(updateMarkerTransform(text, 5, { scale: 50 })).toBe(text);
  });

  it("clamps scale to the valid range", () => {
    const text = "![a.png|10%](envelope://a.png)";
    expect(updateMarkerTransform(text, 0, { scale: 500 })).toBe(
      `![a.png|${MAX_INLINE_IMAGE_SCALE}%](envelope://a.png)`,
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
    expect(result).toBe("Text\n\nMore text");
  });

  it("preserves paragraph separation when the marker sat between two paragraphs", () => {
    const text = "Para 1\n\n![cat.png|50%](envelope://cat.png)\n\nPara 2";
    const result = removeMarker(text, 0);
    expect(result).toBe("Para 1\n\nPara 2");
  });

  it("strips the leading newline pair when there is no trailing one", () => {
    const text = "Para 1\n\n![cat.png|50%](envelope://cat.png)Para 2";
    const result = removeMarker(text, 0);
    expect(result).toBe("Para 1Para 2");
  });

  it("removes only the targeted marker when multiple are present", () => {
    const text = "![a.png|10%](envelope://a.png) X ![b.png|20%](envelope://b.png)";
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

  it("handles a marker with position suffix", () => {
    const text = "![cat.png|50%@10,-5](envelope://cat.png) text";
    const result = removeMarker(text, 0);
    expect(result).toBe(" text");
  });
});

describe("keyboard step constants", () => {
  it("exposes the normal and micro move steps", () => {
    expect(MOVE_STEP_NORMAL).toBe(10);
    expect(MOVE_STEP_MICRO).toBe(1);
  });

  it("exposes the normal and micro scale steps", () => {
    expect(SCALE_STEP_NORMAL).toBe(5);
    expect(SCALE_STEP_MICRO).toBe(1);
  });
});

describe("round-trip: build → find → transform → re-find", () => {
  it("can build, find, rescale, reposition, and re-find a marker", () => {
    const marker = buildInlineImageMarker("photo.png", 50, 10, -5);
    expect(marker).toBe("![photo.png|50%@10,-5](envelope://photo.png)");

    const text = `Hello\n${marker}\nWorld`;

    const found = findInlineImageMarkers(text);
    expect(found).toHaveLength(1);
    expect(found[0].scale).toBe(50);
    expect(found[0].dx).toBe(10);
    expect(found[0].dy).toBe(-5);

    const transformed = updateMarkerTransform(text, 0, {
      scale: 125,
      dx: 0,
      dy: 0,
    });
    expect(transformed).toContain("|125%");
    expect(transformed).not.toContain("@");

    const found2 = findInlineImageMarkers(transformed);
    expect(found2[0].scale).toBe(125);
    expect(found2[0].dx).toBe(0);
    expect(found2[0].dy).toBe(0);
    expect(found2[0].filename).toBe("photo.png");
  });

  it("preserves attachment references across transform changes", () => {
    const text = "![My Holiday Photo|50%@10,-5](envelope://img-001.png)";
    const transformed = updateMarkerTransform(text, 0, {
      scale: 75,
      dx: 20,
      dy: 30,
    });
    expect(transformed).toContain("envelope://img-001.png");
    expect(transformed).toContain("My Holiday Photo");
    expect(transformed).toContain("|75%");
    expect(transformed).toContain("@20,30");
  });

  it("round-trips through build → parse without loss", () => {
    const cases = [
      { filename: "a.png", scale: 50, dx: 0, dy: 0, name: undefined as string | undefined },
      { filename: "b.png", scale: 75, dx: 10, dy: -5, name: undefined as string | undefined },
      { filename: "c.png", scale: 100, dx: -20, dy: 30, name: "My Photo" },
      { filename: "d.png", scale: 200, dx: 0, dy: 0, name: "Big" },
    ];
    for (const c of cases) {
      const marker = buildInlineImageMarker(c.filename, c.scale, c.dx, c.dy, c.name);
      const parsed = findInlineImageMarkers(marker);
      expect(parsed).toHaveLength(1);
      expect(parsed[0].filename).toBe(c.filename);
      expect(parsed[0].scale).toBe(c.scale);
      expect(parsed[0].dx).toBe(c.dx);
      expect(parsed[0].dy).toBe(c.dy);
      expect(parsed[0].displayName).toBe(c.name ?? c.filename);
    }
  });
});
