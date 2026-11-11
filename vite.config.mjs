import { fileURLToPath } from "node:url";
import path from "node:path";
import { defineConfig } from "vite";

const projectRoot = path.dirname(fileURLToPath(import.meta.url));

export default defineConfig({
  root: path.join(projectRoot, "ui"),
  base: "/",
  build: {
    outDir: path.join(projectRoot, "dist"),
    emptyOutDir: true,
    sourcemap: false,
  },
});
