import type { NextConfig } from "next";

const nextConfig: NextConfig = {
	// Required by @opennextjs/cloudflare: the adapter reads the standalone
	// build output (.next/standalone) when packaging the worker + cache assets.
	output: "standalone",
	reactStrictMode: true,
};

export default nextConfig;
