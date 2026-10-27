import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';
import { defineConfig, loadEnv } from 'vite';
import { rewriteDevApiProxyPath } from './src/shared/web-api-routing.ts';
import { DEFAULT_BACKEND_PORT, DEFAULT_WEB_PORT, PRODUCT_NAME } from '../config/app-config.mjs';

const root = resolve(import.meta.dirname, 'src/renderer');
const webDist = resolve(import.meta.dirname, '../frontend/dist');
const version = JSON.parse(
  readFileSync(resolve(import.meta.dirname, '../package.json'), 'utf8'),
).version;
const backendPort = process.env.OMNIVOICE_PORT || String(DEFAULT_BACKEND_PORT);
const backend = `http://127.0.0.1:${backendPort}`;
// Nexus sign-in (docs/nexus-auth.md), read from the same root .env the backend
// loads: the backend owns /auth/login and /auth/callback, and X-Forwarded-For
// makes it treat this browser as remote, the way cloudflared presents it.
const nexus = Boolean(
  loadEnv('development', resolve(import.meta.dirname, '..'), 'NEXUS_').NEXUS_CLIENT_ID?.trim(),
);

export default defineConfig({
  root,
  publicDir: resolve(import.meta.dirname, 'public'),
  plugins: [
    react(),
    tailwindcss(),
    {
      name: 'app-identity',
      transformIndexHtml(html) {
        return html.replaceAll('__APP_PRODUCT_NAME__', PRODUCT_NAME);
      },
    },
    {
      name: 'renderer-boot-script',
      generateBundle() {
        this.emitFile({
          type: 'asset',
          fileName: 'early-error-capture.js',
          source: readFileSync(resolve(import.meta.dirname, 'public/early-error-capture.js')),
        });
      },
    },
  ],
  define: {
    __APP_VERSION__: JSON.stringify(version),
    __WEB_DEPLOYMENT__: true,
  },
  resolve: {
    alias: {
      '@': resolve(root, 'src'),
      '@shared': resolve(import.meta.dirname, 'src/shared'),
      '@vercel/oidc': resolve(root, 'src/lib/vercel-oidc-browser.ts'),
    },
    dedupe: ['react', 'react-dom'],
  },
  optimizeDeps: { exclude: ['@scalar/api-reference-react'] },
  server: {
    host: 'localhost',
    // Same name the backend reads for its CORS/CSRF allow-list (core/csrf.py);
    // VOICESTUDIO_UI_PORT remains an accepted alias.
    port:
      Number(process.env.OMNIVOICE_UI_PORT || process.env.VOICESTUDIO_UI_PORT) || DEFAULT_WEB_PORT,
    strictPort: true,
    proxy: {
      '/api/ws': {
        target: backend,
        changeOrigin: true,
        xfwd: nexus,
        rewrite: (path) => path.replace(/^\/api/, ''),
        ws: true,
      },
      '/api': {
        target: backend,
        changeOrigin: true,
        xfwd: nexus,
        // Four backend router families genuinely own `/api`; every other
        // renderer request uses `/api` only as the Vite/Electron proxy prefix.
        rewrite: rewriteDevApiProxyPath,
      },
      ...(nexus && {
        '^/auth/(login|callback)(\\?|$)': { target: backend, changeOrigin: true, xfwd: true },
      }),
    },
  },
  build: {
    outDir: webDist,
    emptyOutDir: true,
    rollupOptions: { input: resolve(root, 'index.html') },
  },
});
