/**
 * React 19's type set omits the MathML intrinsic elements. The equation
 * blocks render <math><annotation encoding="application/x-tex">…</annotation>
 * </math> for markdown export (BlockNote's converter maps that markup to
 * $…$ / $$…$$), so the two elements we use are declared here. React itself
 * renders MathML fine at runtime — this is types-only.
 */

import type * as React from "react";

declare module "react" {
	namespace JSX {
		interface IntrinsicElements {
			math: React.DetailedHTMLProps<React.HTMLAttributes<HTMLElement>, HTMLElement>;
			annotation: React.DetailedHTMLProps<React.HTMLAttributes<HTMLElement>, HTMLElement> & {
				encoding?: string;
			};
		}
	}
}
