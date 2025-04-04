import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// https://vite.dev/config/
export default defineConfig({
  plugins: [
    react(),
    {
      name: "custom-middleware",
      configureServer(server) {
        server.middlewares.use((_, res, next) => {
          // Set security headers
          res.setHeader("X-Frame-Options", "DENY");
          res.setHeader("X-Content-Type-Options", "nosniff");

          // Content Security Policy
          res.setHeader(
            "Content-Security-Policy",
            "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'self';"
          );

          // Isolation
          res.setHeader("Cross-Origin-Resource-Policy", "same-origin");
          res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
          res.setHeader("Cross-Origin-Embedder-Policy", "require-corp");

          // Permissions
          res.setHeader("Permissions-Policy", "interest-cohort=()");

          // Cache control
          // res.setHeader(
          //   "Cache-Control",
          //   "no-store, no-cache, must-revalidate, proxy-revalidate"
          // );
          res.setHeader("Cache-Control", "no-cache, no-store, must-revalidate, private");
          res.setHeader("Pragma", "no-cache");
          res.setHeader("Expires", "0");

          next();
        });
      },
    },
  ],
});
