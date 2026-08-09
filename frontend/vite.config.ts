import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      '/api/chat/stream': { target: 'ws://localhost:8000', ws: true },
      '/api': 'http://localhost:8000',
      '/auth': 'http://localhost:8000',
      '/targets': 'http://localhost:8000',
    }
  }
})
