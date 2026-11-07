import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      // API_PROXY_TARGET lets a second copy run against another backend port; the default is the usual backend.
      "/api": process.env.API_PROXY_TARGET || "http://localhost:8001",
    },
  },
});
