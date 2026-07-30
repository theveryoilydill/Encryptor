import { reactRouter } from "@react-router/dev/vite";
import { cloudflare } from "@cloudflare/vite-plugin";
import { defineConfig } from "vite";
import tsconfigPaths from "vite-tsconfig-paths";
import tailwindcss from "@tailwindcss/vite";

export default defineConfig({
  plugins: [
    cloudflare({
      viteEnvironment: { name: "ssr" },
    }),
    reactRouter(),
    tailwindcss(),
    tsconfigPaths(),
  ],
  ssr: {
    // openpgp + kbpgp + keybase-proofs ship ESM/CJS that needs to be
    // externalized for the worker bundle so Vite doesn't try to pre-bundle them.
    noExternal: ["openpgp", "kbpgp", "keybase-proofs", "scrypt-js"],
  },
  optimizeDeps: {
    include: ["kbpgp", "keybase-proofs", "scrypt-js"],
  },
});
