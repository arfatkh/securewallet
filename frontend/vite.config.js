import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// In development the API runs on :8000 (docker-compose.dev.yml); in Docker nginx proxies /api.
export default defineConfig({
  plugins: [react()],
  server: { port: 5173, proxy: { '/api': 'http://localhost:8000' } },
  // No data: URIs, so the strict font-src 'self' CSP holds for every font file.
  build: { sourcemap: false, assetsInlineLimit: 0 },
})
