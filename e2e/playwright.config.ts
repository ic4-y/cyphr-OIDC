import { defineConfig } from '@playwright/test';

const BRIDGE_PORT = process.env.BRIDGE_PORT || '8089';
const BRIDGE_URL = `http://localhost:${BRIDGE_PORT}`;

export default defineConfig({
  testDir: '.',
  testMatch: /\.spec\.ts$/,
  fullyParallel: false,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  workers: 1,
  reporter: [['list'], ['html', { open: 'never' }]],
  timeout: 180_000,
  use: {
    trace: 'retain-on-failure',
    baseURL: BRIDGE_URL,
  },
  projects: [
    {
      name: 'chromium',
      use: {
        channel: 'chromium',
        executablePath: process.env.CHROMIUM_PATH || '/home/ap/.nix-profile/bin/chromium',
      },
    },
  ],
});
