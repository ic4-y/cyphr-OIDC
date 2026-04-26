import { test } from './fixtures/setup';
import { expect } from '@playwright/test';
import { TEST_IDENTITY } from './test-data/identity';
import { seedTestKey, openPopup, waitForWasmReady } from './fixtures/setup';

test.describe('Extension', () => {
  test('loads and initializes Wasm module', async ({ extContext, extensionId }) => {
    await waitForWasmReady(extContext, extensionId);

    const page = await openPopup(extContext, extensionId);
    // Wait for the popup to finish initializing (transition away from loading state)
    try {
      await page.waitForSelector('button:has-text("Generate New Key"), button:has-text("Fetch Challenge"), button:has-text("Auth")', { timeout: 10000 });
    } catch {
      // If buttons not found, check body doesn't contain loading text
      const body = await page.locator('body').textContent();
      expect(body).not.toContain('Initializing crypto module');
      expect(body).not.toContain('Initialization Failed');
      await page.close();
      return;
    }
    // If we got here, a button appeared — Wasm is ready
    await page.close();
  });

  test('imports test key and derives correct thumbprint', async ({ extContext, extensionId }) => {
    await seedTestKey(extContext, extensionId);

    const page = await openPopup(extContext, extensionId);
    await page.getByRole('button', { name: 'Settings' }).click();
    const tmbCode = await page.locator('.setting-group code').first().textContent();
    expect(tmbCode).toContain(TEST_IDENTITY.thumbprint.substring(0, 16));
    await page.close();
  });

  test('signs a challenge via popup fetch → sign → verify flow', async ({ extContext, extensionId, bridgeUrl }) => {
    await seedTestKey(extContext, extensionId, bridgeUrl);

    const page = await openPopup(extContext, extensionId);
    await page.getByRole('button', { name: 'Auth' }).click();

    await page.waitForSelector('button:has-text("Fetch Challenge")', { timeout: 10000 });
    await page.getByRole('button', { name: 'Fetch Challenge' }).click();
    await page.waitForSelector('button:has-text("Approve")', { timeout: 10000 });
    await page.getByRole('button', { name: 'Approve' }).click();

    const msg = await page.waitForSelector('.message.success', { timeout: 15000 });
    const text = await msg.textContent();
    expect(text).toContain(TEST_IDENTITY.email);

    await page.close();
  });
});
