import { test } from './fixtures/setup';
import { expect } from '@playwright/test';
import { TEST_IDENTITY } from './test-data/identity';
import { seedTestKey } from './fixtures/setup';

const CLIENT_ID = 'e2e-test-client';
const CLIENT_SECRET = 'e2e-test-secret';

function startCallbackServer(port: number) {
  const http = require('http');
  let srv: any;
  const captured = new Promise<string>((resolve) => {
    srv = http.createServer((req: any, res: any) => {
      const url = `http://${req.headers.host}${req.url}`;
      res.writeHead(200, { 'Content-Type': 'text/plain' });
      res.end('OK');
      resolve(url);
    });
    srv.listen(port);
  });
  return {
    close: () => srv.close(),
    captured,
  };
}

test.describe('OIDC Flow', () => {
  test('full authorization code flow: /auth → login → sign → callback → redirect', async ({ extContext, extensionId, bridgeUrl }) => {
    await seedTestKey(extContext, extensionId);

    const server = startCallbackServer(8090);
    const REDIRECT_URI = 'http://localhost:8090/callback';

    const state = 'test-state-' + Date.now();
    const authUrl = `${bridgeUrl}/authorize?client_id=${CLIENT_ID}&redirect_uri=${encodeURIComponent(REDIRECT_URI)}&response_type=code&state=${state}&scope=openid+email`;

    const page = await extContext.newPage();
    await page.goto(authUrl);

    await page.waitForURL(/\/login\?authRequestID=/, { timeout: 10000 });
    console.log('[oidc] At login page, waiting for sign button...');
    // The sign button enables when: (1) challenge fetched, (2) extension signals via postMessage
    await page.waitForSelector('#sign-btn:not([disabled])', { timeout: 30000 });
    console.log('[oidc] Sign button enabled, clicking...');
    await page.click('#sign-btn');

    const statusEl = await page.waitForSelector('.status.success', { timeout: 20000 });
    const statusText = await statusEl.textContent();
    expect(statusText).toContain(TEST_IDENTITY.email);

    const callbackUrl = await server.captured;
    expect(callbackUrl).toContain(REDIRECT_URI);
    expect(callbackUrl).toContain('code=');
    expect(callbackUrl).toContain('state=' + state);

    const code = new URL(callbackUrl).searchParams.get('code');
    expect(code).toBeTruthy();

    const tokenResp = await fetch(`${bridgeUrl}/oauth/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code: code!,
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
        redirect_uri: REDIRECT_URI,
      }),
    });

    expect(tokenResp.ok).toBe(true);
    const tokens = await tokenResp.json();
    expect(tokens.access_token).toBeTruthy();
    expect(tokens.id_token).toBeTruthy();
    expect(tokens.token_type).toBe('Bearer');

    server.close();
    await page.close();
  });

  test('ID token contains correct claims', async ({ extContext, extensionId, bridgeUrl }) => {
    await seedTestKey(extContext, extensionId);

    const server = startCallbackServer(8091);
    const REDIRECT_URI = 'http://localhost:8091/callback';

    const state = 'claims-test-' + Date.now();
    const authUrl = `${bridgeUrl}/authorize?client_id=${CLIENT_ID}&redirect_uri=${encodeURIComponent(REDIRECT_URI)}&response_type=code&state=${state}&scope=openid+email`;

    const page = await extContext.newPage();
    await page.goto(authUrl);
    await page.waitForURL(/\/login\?authRequestID=/, { timeout: 10000 });
    await page.waitForSelector('#sign-btn:not([disabled])', { timeout: 30000 });
    await page.click('#sign-btn');

    const callbackUrl = await server.captured;
    const code = new URL(callbackUrl).searchParams.get('code');
    expect(code).toBeTruthy();

    const tokenResp = await fetch(`${bridgeUrl}/oauth/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code: code!,
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
        redirect_uri: REDIRECT_URI,
      }),
    });

    const tokens = await tokenResp.json();
    const idToken = tokens.id_token as string;
    const payloadB64 = idToken.split('.')[1];
    const padded = payloadB64 + '='.repeat((4 - payloadB64.length % 4) % 4);
    const payload = JSON.parse(Buffer.from(padded, 'base64').toString('utf-8'));

    expect(payload.sub).toBe(TEST_IDENTITY.thumbprint);
    expect(payload.email).toBe(TEST_IDENTITY.email);
    expect(payload.iss).toBe(bridgeUrl);
    expect(payload.aud).toEqual([CLIENT_ID]);

    server.close();
    await page.close();
  });

  test('userinfo endpoint returns correct subject', async ({ extContext, extensionId, bridgeUrl }) => {
    await seedTestKey(extContext, extensionId);

    const server = startCallbackServer(8092);
    const REDIRECT_URI = 'http://localhost:8092/callback';

    const state = 'userinfo-test-' + Date.now();
    const authUrl = `${bridgeUrl}/authorize?client_id=${CLIENT_ID}&redirect_uri=${encodeURIComponent(REDIRECT_URI)}&response_type=code&state=${state}&scope=openid+email`;

    const page = await extContext.newPage();
    await page.goto(authUrl);
    await page.waitForURL(/\/login\?authRequestID=/, { timeout: 10000 });
    await page.waitForSelector('#sign-btn:not([disabled])', { timeout: 30000 });
    await page.click('#sign-btn');

    const callbackUrl = await server.captured;
    const code = new URL(callbackUrl).searchParams.get('code');
    expect(code).toBeTruthy();

    const tokenResp = await fetch(`${bridgeUrl}/oauth/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code: code!,
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
        redirect_uri: REDIRECT_URI,
      }),
    });

    const tokens = await tokenResp.json();
    const userinfoResp = await fetch(`${bridgeUrl}/userinfo`, {
      headers: { 'Authorization': `Bearer ${tokens.access_token}` },
    });

    expect(userinfoResp.ok).toBe(true);
    const userinfo = await userinfoResp.json();
    expect(userinfo.sub).toBe(TEST_IDENTITY.thumbprint);
    expect(userinfo.email).toBe(TEST_IDENTITY.email);

    server.close();
    await page.close();
  });
});
