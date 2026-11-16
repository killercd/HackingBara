import { defineConfig } from '@playwright/test'
export default defineConfig({testDir:'tests/smoke',timeout:120000,use:{baseURL:process.env.SMOKE_URL||'http://127.0.0.1:8080',headless:true,launchOptions:{executablePath:process.env.SMOKE_CHROMIUM},trace:'retain-on-failure'},reporter:'list',workers:1})
