import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vite.dev/config/
export default defineConfig({
  plugins: [
    react(),
    {
      name: 'custom-middleware',
      configureServer(server) {
        server.middlewares.use((_, res, next) => {
          res.setHeader("X-Frame-Options", "DENY");
          res.setHeader("X-Content-Type-Options", "nosniff");
          res.setHeader("Content-Security-Policy", "default-src 'self';");
          next();
        });
      },
    },
  ],
});
