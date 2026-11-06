import {defineConfig} from '@playwright/test';
export default defineConfig({testDir:'./e2e',workers:1,retries:0,timeout:90000,
  testIgnore:[...(process.env.NETSENTRY_M7A?[]:['**/portable.spec.ts']),...(process.env.NETSENTRY_DEMO_IID?[]:['**/demo.spec.ts']),...(process.env.NETSENTRY_RECOVERY_IID?[]:['**/recovery.spec.ts']),...(process.env.NETSENTRY_M631_CASES?[]:['**/registry.spec.ts']),...(process.env.NETSENTRY_M63_CASES?[]:['**/multistep.spec.ts']),...(process.env.NETSENTRY_M62_CASES?[]:['**/evidence-evaluation.spec.ts']),...(process.env.NETSENTRY_GEMINI_INVESTIGATION?[]:['**/gemini-live.spec.ts']),...(process.env.NETSENTRY_M61_INVESTIGATION?[]:['**/gemini-pending.spec.ts'])],
  reporter:[['list']],outputDir:process.env.NETSENTRY_E2E_OUT||'test-results',
  use:{baseURL:process.env.NETSENTRY_FRONTEND_URL||'http://127.0.0.1:5173',headless:true,actionTimeout:10000,navigationTimeout:15000,
    viewport:{width:1440,height:1000},trace:'off',screenshot:'only-on-failure'}});
