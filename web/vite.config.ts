import { defineConfig } from "vite";
import preact from "@preact/preset-vite";

export default defineConfig({
  plugins: [preact()],
  base: "./",
  build: {
    outDir: "dist",
    emptyOutDir: true,
    assetsDir: ".",
    assetsInlineLimit: 4096,
  },
  server: {
    proxy: {
      "/api": { target: "http://127.0.0.1:7480", changeOrigin: true },
      "/health": { target: "http://127.0.0.1:7480", changeOrigin: true },
    },
  },
  test: {
    environment: "node",
  },
});
