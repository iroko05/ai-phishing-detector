import { dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

/** @type {import('next').NextConfig} */
const nextConfig = {
  // standalone-бандл для Docker (server.js без полного node_modules)
  output: 'standalone',
  turbopack: {
    // корень Turbopack — сам проект, чтобы не цеплять lock-файлы из ~
    root: dirname(fileURLToPath(import.meta.url)),
  },
};

export default nextConfig;