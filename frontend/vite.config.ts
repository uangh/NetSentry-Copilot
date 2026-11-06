import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';
const port = Number(process.env.NETSENTRY_BACKEND_PORT || 8000);
if (!Number.isInteger(port) || port < 1024 || port > 65535) throw new Error('Invalid local backend port');
export default defineConfig({plugins:[react(),tailwindcss()],server:{host:'127.0.0.1',port:5173,strictPort:true,
  fs:{strict:true},proxy:{'/api':{target:`http://127.0.0.1:${port}`},'/health':{target:`http://127.0.0.1:${port}`}}},
  test:{environment:'jsdom',setupFiles:['./src/test/setup.ts'],include:['src/**/*.test.ts','src/**/*.test.tsx']}});
