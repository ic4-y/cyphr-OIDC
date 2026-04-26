import { test as base, chromium, type BrowserContext, type Page } from '@playwright/test';
import { spawn, type ChildProcess, execSync } from 'child_process';
import path from 'path';
import fs from 'fs';
import { TEST_IDENTITY } from '../test-data/identity';

const BRIDGE_PORT = process.env.BRIDGE_PORT || '8089';
const BRIDGE_URL = `http://localhost:${BRIDGE_PORT}`;
const CLIENT_SECRET = 'e2e-test-secret';
const REDIRECT_URI = 'http://localhost:8090/callback';
const CHROMIUM_PATH = process.env.CHROMIUM_PATH || '/home/ap/.nix-profile/bin/chromium';

// ---- Bridge fixture (worker-scoped) ----

async function buildBridge(): Promise<string> {
  const root = path.resolve(__dirname, '..', '..');
  const binary = path.join(root, 'bridge', 'bridge');
  if (!fs.existsSync(binary)) {
    console.log('[bridge] Building bridge binary...');
    execSync('go build -o bridge .', { cwd: path.join(root, 'bridge'), stdio: 'inherit' });
  }
  return binary;
}

async function waitForBridge(url: string, attempts = 50): Promise<void> {
  for (let i = 0; i < attempts; i++) {
    try {
      const resp = await fetch(`${url}/health`);
      if (resp.ok) return;
    } catch { /* not ready */ }
    await new Promise((r) => setTimeout(r, 200));
  }
  throw new Error(`Bridge did not become ready at ${url}`);
}

function getExtensionPath(): string {
  const root = path.resolve(__dirname, '..', '..');
  const dist = path.join(root, 'cyphrmask', 'dist');
  if (!fs.existsSync(dist)) {
    console.log('[extension] Building extension...');
    execSync('npm run build', { cwd: path.join(root, 'cyphrmask'), stdio: 'inherit' });
  }
  return dist;
}

// ---- Shared browser context (worker-scoped) ----

let _sharedContext: BrowserContext | null = null;
let _sharedExtId = '';

async function initSharedBrowser(): Promise<{ context: BrowserContext; extId: string }> {
  if (_sharedContext) return { context: _sharedContext, extId: _sharedExtId };

  const extPath = getExtensionPath();
  const userDataDir = path.resolve(__dirname, '..', '.e2e-user-data');
  if (fs.existsSync(userDataDir)) {
    fs.rmSync(userDataDir, { recursive: true, force: true });
  }
  fs.mkdirSync(userDataDir, { recursive: true });

  const context = await chromium.launchPersistentContext(userDataDir, {
    executablePath: CHROMIUM_PATH,
    headless: true,
    args: [
      `--disable-extensions-except=${extPath}`,
      `--load-extension=${extPath}`,
      '--no-sandbox',
      '--disable-gpu',
      '--disable-dev-shm-usage',
    ],
  });

  let workers = context.serviceWorkers();
  for (let i = 0; i < 30 && workers.length === 0; i++) {
    await new Promise((r) => setTimeout(r, 500));
    workers = context.serviceWorkers();
  }
  if (workers.length === 0) throw new Error('Extension service worker never started');

  const extId = workers[0].url().match(/^chrome-extension:\/\/([a-z]+)/)?.[1] || '';
  if (!extId) throw new Error('Could not determine extension ID');

  console.log(`[extension] Service worker loaded, ID: ${extId}`);
  _sharedContext = context;
  _sharedExtId = extId;
  return { context, extId };
}

async function destroySharedBrowser(): Promise<void> {
  if (_sharedContext) {
    await _sharedContext.close();
    _sharedContext = null;
    _sharedExtId = '';
  }
}

// The main test object — all tests use these fixtures
export const test = base.extend<{
  bridgeProcess: ChildProcess;
  bridgeUrl: string;
  extContext: BrowserContext;
  extensionId: string;
}>({
  bridgeProcess: [async ({}, use) => {
    console.log('[bridge-fixture] Starting...');
    const binary = await buildBridge();
    console.log('[bridge-fixture] Binary:', binary);
    const usersJSON = JSON.stringify({
      [TEST_IDENTITY.thumbprint]: {
        public_key: TEST_IDENTITY.publicKeyHex,
        email: TEST_IDENTITY.email,
      },
    });
    const clientsJSON = JSON.stringify([{
      id: 'e2e-test-client',
      secret: CLIENT_SECRET,
      redirect_uris: [
        'http://localhost:8090/callback',
        'http://localhost:8091/callback',
        'http://localhost:8092/callback',
      ],
    }]);

    const proc = spawn(binary, [], {
      env: {
        ...process.env,
        BRIDGE_PORT,
        BRIDGE_ISSUER_URL: BRIDGE_URL,
        BRIDGE_CLIENT_ID: 'e2e-test-client',
        BRIDGE_CLIENT_SECRET: CLIENT_SECRET,
        BRIDGE_CALLBACK_URL: REDIRECT_URI,
        BRIDGE_USERS: usersJSON,
        BRIDGE_CLIENTS: clientsJSON,
      },
      cwd: path.resolve(__dirname, '..', '..', 'bridge'),
      stdio: ['ignore', 'pipe', 'pipe'],
    });

    proc.stdout?.on('data', (d) => process.stdout.write(`[bridge] ${d}`));
    proc.stderr?.on('data', (d) => process.stderr.write(`[bridge] ${d}`));

    await waitForBridge(BRIDGE_URL);
    console.log('[bridge] Ready');

    await use(proc);

    proc.kill('SIGTERM');
    await new Promise((r) => proc.on('exit', r));
  }, { scope: 'worker' }],

  bridgeUrl: [async ({}, use) => {
    await use(BRIDGE_URL);
  }, { scope: 'worker' }],

  extContext: [async ({ bridgeProcess }, use) => {
    const { context } = await initSharedBrowser();
    await use(context);
  }, { scope: 'worker' }],

  extensionId: [async ({}, use) => {
    const { extId } = await initSharedBrowser();
    await use(extId);
  }, { scope: 'worker' }],
});

// Cleanup on process exit
process.on('exit', () => { destroySharedBrowser(); });

// ---- Helper: set bridge host in extension storage ----

export async function setBridgeHost(context: BrowserContext, extId: string, bridgeUrl: string): Promise<void> {
  // Store bridgeHost so the popup's detectBridgeHost falls back to it
  // (the popup skips chrome-extension:// URLs from tabs.query)
  const page = await context.newPage();
  await page.goto(`chrome-extension://${extId}/popup.html`);
  await page.evaluate((url) => chrome.storage.local.set({ bridgeHost: url }), bridgeUrl);
  await page.close();
  console.log(`[extension] Bridge host set to ${bridgeUrl}`);
}

// ---- Helper: wait for Wasm to be ready ----

export async function waitForWasmReady(context: BrowserContext, extId: string, timeout = 30000): Promise<void> {
  const start = Date.now();
  let attempts = 0;
  while (Date.now() - start < timeout) {
    attempts++;
    try {
      const page = await context.newPage();
      await page.goto(`chrome-extension://${extId}/popup.html`);
      try {
        await page.waitForSelector('button:has-text("Generate New Key"), button:has-text("Fetch Challenge"), button:has-text("Auth")', { timeout: 5000 });
        await page.close();
        console.log(`[extension] Wasm ready after ${attempts} attempts`);
        return;
      } catch {
        const body = await page.locator('body').textContent();
        await page.close();
        if (!body?.includes('Initializing') && !body?.includes('Failed')) {
          console.log(`[extension] Wasm ready after ${attempts} attempts`);
          return;
        }
      }
    } catch {
      // page might have been closed by something else
    }
    await new Promise((r) => setTimeout(r, 1000));
  }
  throw new Error('Wasm module did not become ready in time');
}

// ---- Helper: import test key via the popup UI ----

export async function seedTestKey(context: BrowserContext, extId: string, bridgeUrl?: string): Promise<void> {
  if (bridgeUrl) await setBridgeHost(context, extId, bridgeUrl);
  await waitForWasmReady(context, extId);

  const page = await context.newPage();
  await page.goto(`chrome-extension://${extId}/popup.html`);

  // Check if we need to import a key or if one already exists
  try {
    await page.waitForSelector('button:has-text("Generate New Key")', { timeout: 5000 });
    // No key — import one
    const input = page.locator('input[placeholder*="hex"]');
    await input.fill(TEST_IDENTITY.privateKeyHex);
    await page.getByRole('button', { name: 'Import Private Key' }).click();
  } catch {
    // Check if key is already imported (we'd see Auth/Settings tabs)
    const body = await page.locator('body').textContent();
    if (body?.includes('Auth') && body?.includes('Settings')) {
      // Key already exists — check if it's our test key
      const settingsBtn = await page.$('button:has-text("Settings")');
      if (settingsBtn) await settingsBtn.click();
      const codes = await page.locator('code').allTextContents();
      if (codes.some(c => c.includes(TEST_IDENTITY.thumbprint.substring(0, 16)))) {
        await page.close();
        console.log('[extension] Test key already present');
        return;
      }
    }
    // Try importing anyway
    const input = page.locator('input[placeholder*="hex"]');
    const count = await input.count();
    if (count > 0) {
      await input.fill(TEST_IDENTITY.privateKeyHex);
      await page.getByRole('button', { name: 'Import Private Key' }).click();
    } else {
      await page.close();
      console.log('[extension] Test key already present (no import field)');
      return;
    }
  }

  // Wait for thumbprint to appear
  try {
    await page.waitForSelector('code:has-text("' + TEST_IDENTITY.thumbprint.substring(0, 16) + '")', { timeout: 10000 });
  } catch {
    // Try switching to Settings tab
    const settingsBtn = await page.$('button:has-text("Settings")');
    if (settingsBtn) await settingsBtn.click();
    await page.waitForSelector('code:has-text("' + TEST_IDENTITY.thumbprint.substring(0, 16) + '")', { timeout: 10000 });
  }

  await page.close();
  console.log('[extension] Test key imported via popup');
}

// ---- Helper: open the extension popup as a Playwright page ----

export function openPopup(context: BrowserContext, extId: string): Promise<Page> {
  return context.newPage().then(async (page) => {
    await page.goto(`chrome-extension://${extId}/popup.html`);
    return page;
  });
}

// ---- Helper: wait for content script to be injected in a page ----

export async function waitForContentScript(page: Page): Promise<void> {
  await page.evaluate(() => {
    return new Promise<void>((resolve) => {
      window.addEventListener('message', (e) => {
        if (e.data?.source === 'cyphrmask' && e.data?.type === 'EXTENSION_STATUS') {
          resolve();
        }
      });
    });
  });
}
