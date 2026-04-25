import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { copyFileSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from 'fs';
import { resolve } from 'path';

export default defineConfig({
  base: './',
  plugins: [
    react(),
    {
      name: 'copy-extension-assets',
      closeBundle() {
        const root = resolve(__dirname);
        const dist = resolve(root, 'dist');

        // Copy wasm files (also to dist/ root for wasm-pack's import.meta.url resolution)
        const wasmSrc = resolve(root, 'src/wasm');
        const wasmDest = resolve(dist, 'wasm');
        mkdirSync(wasmDest, { recursive: true });
        for (const file of readdirSync(wasmSrc)) {
          if (file.endsWith('.js') || file.endsWith('.wasm')) {
            copyFileSync(resolve(wasmSrc, file), resolve(wasmDest, file));
            // Also copy .wasm to dist/ root for wasm-pack's new URL() resolution
            if (file.endsWith('.wasm')) {
              copyFileSync(resolve(wasmSrc, file), resolve(dist, file));
            }
          }
        }

        // Copy content.js and background.js
        const srcDir = resolve(root, 'src');
        for (const file of ['content.js', 'background.js']) {
          copyFileSync(resolve(srcDir, file), resolve(dist, file));
        }

        // Copy icon files
        const iconsSrc = resolve(root, 'assets');
        const iconsDest = resolve(dist, 'assets');
        mkdirSync(iconsDest, { recursive: true });
        for (const file of readdirSync(iconsSrc)) {
          if (file.endsWith('.png')) {
            copyFileSync(resolve(iconsSrc, file), resolve(iconsDest, file));
          }
        }

        // Flatten popup.html with corrected paths
        const srcHtml = readFileSync(resolve(dist, 'src/popup/popup.html'), 'utf-8');
        const fixedHtml = srcHtml
          .replace('src="../../popup.js"', 'src="./popup.js"')
          .replace('href="../../assets/', 'href="./assets/');
        writeFileSync(resolve(dist, 'popup.html'), fixedHtml);

        // Update manifest paths for dist layout
        const manifest = JSON.parse(readFileSync(resolve(root, 'manifest.json'), 'utf-8'));
        manifest.content_scripts[0].js = ['content.js'];
        manifest.background.service_worker = 'background.js';
        manifest.action.default_popup = 'popup.html';
        writeFileSync(resolve(dist, 'manifest.json'), JSON.stringify(manifest, null, 2) + '\n');
      },
    },
  ],
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    rollupOptions: {
      input: {
        popup: 'src/popup/popup.html',
      },
      output: {
        entryFileNames: '[name].js',
        chunkFileNames: 'assets/[name].[hash].js',
        assetFileNames: 'assets/[name].[hash][extname]',
      },
    },
  },
});
