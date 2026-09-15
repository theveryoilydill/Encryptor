import type { NextConfig } from "next";

const nextConfig: NextConfig = {
	// Required by @opennextjs/cloudflare: the adapter reads the standalone
	// build output (.next/standalone) when packaging the worker + cache assets.
	output: "standalone",
	reactStrictMode: true,
	// Pin the Turbopack workspace root: environments with several lockfiles
	// (repo bun.lock + stray package-lock.json in a parent dir) make Turbopack
	// guess the root and warn; an explicit root keeps builds deterministic.
	// MUST be process.cwd() — NOT __dirname: the OpenNext Cloudflare adapter
	// re-emits this config as an ES module (.mjs) to patch it, where __dirname
	// is undefined and crashes the worker packaging step (Regression R9-f:
	// CF "Workers Builds" failed on every branch commit since R7 while
	// plain `next build`/`next dev` were fine). Scripts always run from the
	// package root, so cwd IS the workspace root in every build context.
	turbopack: { root: process.cwd() },
};

export default nextConfig;
