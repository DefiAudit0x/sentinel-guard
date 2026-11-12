import { fileURLToPath } from "node:url";
import path from "node:path";
import { defineConfig } from "vite";
import { nodePolyfills } from "vite-plugin-node-polyfills";

const projectRoot = path.dirname(fileURLToPath(import.meta.url));

export default defineConfig({
  root: path.join(projectRoot, "ui"),
  base: "/",
  plugins: [
    nodePolyfills({
      include: ["buffer"],
      globals: { Buffer: true, global: true, process: false },
    }),
  ],
  build: {
    outDir: path.join(projectRoot, "dist"),
    emptyOutDir: true,
    sourcemap: false,
  },
});
