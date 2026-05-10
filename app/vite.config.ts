import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// Tauri-friendly defaults: when we wrap with Tauri later, these
// settings already match what Tauri's setup expects.
export default defineConfig({
  plugins: [react()],
  clearScreen: false,
  server: {
    port: 1420,
    strictPort: true,
  },
  envPrefix: ['VITE_', 'TAURI_ENV_*'],
  build: {
    target: 'es2022',
    minify: 'esbuild',
    sourcemap: true,
  },
});
