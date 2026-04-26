import { describe, it, expect, vi, beforeEach } from 'vitest';

describe('Background Worker Message Handler', () => {
  let listeners;
  let mockStorage;

  beforeEach(() => {
    listeners = [];
    mockStorage = {
      data: {},
      get: vi.fn((keys, callback) => callback(mockStorage.data)),
      set: vi.fn((data) => { Object.assign(mockStorage.data, data); }),
    };

    global.chrome = {
      runtime: {
        getURL: (path) => `chrome-extension://mock-id/${path}`,
        onMessage: {
          addListener: vi.fn((fn) => { listeners.push(fn); }),
        },
      },
      storage: {
        local: mockStorage,
      },
    };
  });

  function createMessageHandler() {
    let wasmReady = false;
    let privateKey = null;
    let wasmInitError = null;

    return {
      setWasmReady: (ready) => { wasmReady = ready; },
      setPrivateKey: (key) => { privateKey = key; },
      setWasmInitError: (err) => { wasmInitError = err; },
      getPrivateKey: () => privateKey,
      getWasmReady: () => wasmReady,
      handleMessage: (message, sendResponse) => {
        switch (message.action) {
          case 'PING':
            sendResponse({ status: wasmReady ? 'ready' : wasmInitError ? `error: ${wasmInitError}` : 'loading' });
            break;
          case 'REQUEST_SIGNATURE':
            if (wasmInitError) {
              sendResponse({ error: `Wasm not ready: ${wasmInitError}` });
              break;
            }
            if (!wasmReady) {
              sendResponse({ error: 'Wasm module not ready' });
              break;
            }
            if (!privateKey) {
              sendResponse({ error: 'No private key configured' });
              break;
            }
            sendResponse({ coz: `{"pay":{"nonce":"${message.nonce}"},"sig":"mock"}` });
            break;
          case 'SET_KEY':
            privateKey = message.privateKey;
            chrome.storage.local.set({ privateKey: message.privateKey });
            sendResponse({ success: true });
            break;
          case 'GET_STATUS':
            sendResponse({
              wasmReady,
              hasKey: !!privateKey,
              status: wasmReady ? 'ready' : wasmInitError ? `error: ${wasmInitError}` : 'loading',
            });
            break;
          case 'GENERATE_KEY':
            sendResponse({
              privateKey: 'mock-private-key',
              publicKeyX: 'mock-x',
              publicKeyY: 'mock-y',
              thumbprint: 'mock-thumbprint',
            });
            break;
          default:
            sendResponse({ error: 'Unknown action' });
        }
      },
    };
  }

  it('responds to PING with loading status when wasm not ready', () => {
    const handler = createMessageHandler();
    const sendResponse = vi.fn();

    handler.handleMessage({ action: 'PING' }, sendResponse);

    expect(sendResponse).toHaveBeenCalledWith({ status: 'loading' });
  });

  it('responds to PING with ready status when wasm is ready', () => {
    const handler = createMessageHandler();
    handler.setWasmReady(true);
    const sendResponse = vi.fn();

    handler.handleMessage({ action: 'PING' }, sendResponse);

    expect(sendResponse).toHaveBeenCalledWith({ status: 'ready' });
  });

  it('responds to PING with error status when wasm failed', () => {
    const handler = createMessageHandler();
    handler.setWasmInitError('Failed to load');
    const sendResponse = vi.fn();

    handler.handleMessage({ action: 'PING' }, sendResponse);

    expect(sendResponse).toHaveBeenCalledWith({ status: 'error: Failed to load' });
  });

  it('rejects signature request when wasm not ready', () => {
    const handler = createMessageHandler();
    const sendResponse = vi.fn();

    handler.handleMessage({ action: 'REQUEST_SIGNATURE', nonce: 'test-nonce' }, sendResponse);

    expect(sendResponse).toHaveBeenCalledWith({ error: 'Wasm module not ready' });
  });

  it('rejects signature request when no private key', () => {
    const handler = createMessageHandler();
    handler.setWasmReady(true);
    const sendResponse = vi.fn();

    handler.handleMessage({ action: 'REQUEST_SIGNATURE', nonce: 'test-nonce' }, sendResponse);

    expect(sendResponse).toHaveBeenCalledWith({ error: 'No private key configured' });
  });

  it('returns coz when wasm ready and key set', () => {
    const handler = createMessageHandler();
    handler.setWasmReady(true);
    handler.setPrivateKey('test-key');
    const sendResponse = vi.fn();

    handler.handleMessage({ action: 'REQUEST_SIGNATURE', nonce: 'abc123' }, sendResponse);

    expect(sendResponse).toHaveBeenCalledWith({
      coz: '{"pay":{"nonce":"abc123"},"sig":"mock"}'
    });
  });

  it('stores private key when SET_KEY is called', () => {
    const handler = createMessageHandler();
    const sendResponse = vi.fn();

    handler.handleMessage({ action: 'SET_KEY', privateKey: 'new-key' }, sendResponse);

    expect(sendResponse).toHaveBeenCalledWith({ success: true });
    expect(mockStorage.set).toHaveBeenCalledWith({ privateKey: 'new-key' });
    expect(handler.getPrivateKey()).toBe('new-key');
  });

  it('reports status with wasmReady and hasKey', () => {
    const handler = createMessageHandler();
    handler.setWasmReady(true);
    handler.setPrivateKey('some-key');
    const sendResponse = vi.fn();

    handler.handleMessage({ action: 'GET_STATUS' }, sendResponse);

    expect(sendResponse).toHaveBeenCalledWith({
      wasmReady: true,
      hasKey: true,
      status: 'ready',
    });
  });

  it('reports hasKey false when no key set', () => {
    const handler = createMessageHandler();
    const sendResponse = vi.fn();

    handler.handleMessage({ action: 'GET_STATUS' }, sendResponse);

    expect(sendResponse).toHaveBeenCalledWith({
      wasmReady: false,
      hasKey: false,
      status: 'loading',
    });
  });

  it('returns error for unknown action', () => {
    const handler = createMessageHandler();
    const sendResponse = vi.fn();

    handler.handleMessage({ action: 'UNKNOWN_ACTION' }, sendResponse);

    expect(sendResponse).toHaveBeenCalledWith({ error: 'Unknown action' });
  });

  it('GENERATE_KEY returns key material', () => {
    const handler = createMessageHandler();
    const sendResponse = vi.fn();

    handler.handleMessage({ action: 'GENERATE_KEY' }, sendResponse);

    expect(sendResponse).toHaveBeenCalledWith({
      privateKey: 'mock-private-key',
      publicKeyX: 'mock-x',
      publicKeyY: 'mock-y',
      thumbprint: 'mock-thumbprint',
    });
  });
});
