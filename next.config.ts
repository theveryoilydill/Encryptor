import path from "node:path";
import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // Required by @opennextjs/cloudflare: the adapter reads the standalone
  // build output (.next/standalone) when packaging the worker + cache assets.
  output: "standalone",
  reactStrictMode: true,
  // Pin the Turbopack workspace root: environments with several lockfiles
  // (repo bun.lock + stray package-lock.json in a parent dir) make Turbopack
  // guess the root and warn; an explicit root keeps builds deterministic.
  turbopack: { root: path.join(__dirname) },
};

export default nextConfig;
