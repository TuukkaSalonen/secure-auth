import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig(() => {
  return {
    preview: {
      port: 5173,
    },
    plugins: [
      react(),
      {
        name: "custom-middleware",
        configureServer(server) {
          server.middlewares.use((_, res, next) => {
            // Security headers
            res.setHeader("X-Frame-Options", "DENY");
            res.setHeader("X-Content-Type-Options", "nosniff");

            // Depending on the environment, set different CSP policies.
            const csp = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'self'; object-src 'none';"

            res.setHeader("Content-Security-Policy", csp);

            // Permissions
            res.setHeader("Permissions-Policy", "accelerometer=(), autoplay=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()");

            // Isolation
            res.setHeader("Cross-Origin-Resource-Policy", "same-origin");
            res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
            res.setHeader("Cross-Origin-Embedder-Policy", "require-corp");

            // Permissions
            res.setHeader("Cache-Control", "no-cache, no-store, must-revalidate, private");
            res.setHeader("Pragma", "no-cache");
            res.setHeader("Expires", "0");

            next();
          });
        },
      },
    ],
  };
});