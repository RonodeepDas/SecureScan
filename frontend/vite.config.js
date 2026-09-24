import fs from "node:fs";
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

const certPath = "certs";
const httpsOptions = {
  key: fs.readFileSync(`${certPath}/key.pem`),
  cert: fs.readFileSync(`${certPath}/cert.pem`),
};

export default defineConfig({
  plugins: [react()],
  server: {
    host: "0.0.0.0",
    port: 5173,
    https: httpsOptions,
    proxy: {
      "/api": {
        target: "https://localhost:8000",
        changeOrigin: true,
        secure: false,
      },
    },
  },
});
