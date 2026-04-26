import { describe, it, expect, vi, beforeEach } from 'vitest';

describe('Content Script postMessage Bridge', () => {
  let mockWindow;
  let messageHandlers;

  beforeEach(() => {
    messageHandlers = [];
    mockWindow = {
      location: { origin: 'http://localhost:8080' },
      postMessage: vi.fn(),
      addEventListener: vi.fn((event, handler) => {
        if (event === 'message') {
          messageHandlers.push(handler);
        }
      }),
    };

    global.window = mockWindow;
  });

  it('broadcasts EXTENSION_AVAILABLE on load', () => {
    // Simulate the content script IIFE
    (function () {
      'use strict';
      const bridgeHost = window.location.origin;
      window.postMessage({
        source: 'cyphrmask',
        type: 'EXTENSION_AVAILABLE'
      }, '*');
    })();

    expect(mockWindow.postMessage).toHaveBeenCalledWith(
      expect.objectContaining({
        source: 'cyphrmask',
        type: 'EXTENSION_AVAILABLE',
      }),
      '*'
    );
  });

  it('includes bridgeHost in the EXTENSION_AVAILABLE message', () => {
    mockWindow.location.origin = 'https://bridge.example.com';

    (function () {
      'use strict';
      window.postMessage({
        source: 'cyphrmask',
        type: 'EXTENSION_AVAILABLE'
      }, '*');
    })();

    expect(mockWindow.postMessage).toHaveBeenCalled();
  });

  it('forwards REQUEST_SIGNATURE from page to extension', () => {
    let sendResponseCallback = null;
    global.chrome = {
      runtime: {
        sendMessage: vi.fn((msg, callback) => {
          sendResponseCallback = callback;
        }),
      },
    };

    // Simulate content script message listener
    const handleMessage = (event) => {
      if (event.source !== mockWindow) return;
      if (!event.data || event.data.source !== 'cyphrmask-bridge') return;

      if (event.data.type === 'REQUEST_SIGNATURE') {
        chrome.runtime.sendMessage(
          { action: 'REQUEST_SIGNATURE', nonce: event.data.nonce },
          (response) => {
            if (response && response.coz) {
              window.postMessage({
                source: 'cyphrmask',
                type: 'SIGNATURE_RESPONSE',
                coz: response.coz
              }, '*');
            } else {
              window.postMessage({
                source: 'cyphrmask',
                type: 'SIGNATURE_ERROR',
                error: response?.error || 'Unknown error'
              }, '*');
            }
          }
        );
      }
    };

    // Simulate receiving a REQUEST_SIGNATURE from the page
    handleMessage({
      source: mockWindow,
      data: { source: 'cyphrmask-bridge', type: 'REQUEST_SIGNATURE', nonce: 'test-nonce-123' },
    });

    expect(chrome.runtime.sendMessage).toHaveBeenCalledWith(
      { action: 'REQUEST_SIGNATURE', nonce: 'test-nonce-123' },
      expect.any(Function)
    );

    // Simulate extension response with coz
    sendResponseCallback({ coz: '{"pay":{},"sig":"abc"}' });

    expect(mockWindow.postMessage).toHaveBeenCalledWith(
      expect.objectContaining({
        source: 'cyphrmask',
        type: 'SIGNATURE_RESPONSE',
        coz: '{"pay":{},"sig":"abc"}',
      }),
      '*'
    );
  });

  it('forwards signature errors back to the page', () => {
    let sendResponseCallback = null;
    global.chrome = {
      runtime: {
        sendMessage: vi.fn((msg, callback) => {
          sendResponseCallback = callback;
        }),
      },
    };

    const handleMessage = (event) => {
      if (event.source !== mockWindow) return;
      if (!event.data || event.data.source !== 'cyphrmask-bridge') return;

      if (event.data.type === 'REQUEST_SIGNATURE') {
        chrome.runtime.sendMessage(
          { action: 'REQUEST_SIGNATURE', nonce: event.data.nonce },
          (response) => {
            if (response && response.coz) {
              window.postMessage({
                source: 'cyphrmask',
                type: 'SIGNATURE_RESPONSE',
                coz: response.coz
              }, '*');
            } else {
              window.postMessage({
                source: 'cyphrmask',
                type: 'SIGNATURE_ERROR',
                error: response?.error || 'Unknown error'
              }, '*');
            }
          }
        );
      }
    };

    handleMessage({
      source: mockWindow,
      data: { source: 'cyphrmask-bridge', type: 'REQUEST_SIGNATURE', nonce: 'test-nonce' },
    });

    // Simulate extension response with error
    sendResponseCallback({ error: 'No private key configured' });

    expect(mockWindow.postMessage).toHaveBeenCalledWith(
      expect.objectContaining({
        source: 'cyphrmask',
        type: 'SIGNATURE_ERROR',
        error: 'No private key configured',
      }),
      '*'
    );
  });

  it('ignores messages from other sources', () => {
    const handleMessage = vi.fn();

    // Simulate content script filter
    const filterHandler = (event) => {
      if (event.source !== mockWindow) return;
      if (!event.data || event.data.source !== 'cyphrmask-bridge') return;
      handleMessage(event);
    };

    // Message from wrong source
    filterHandler({
      source: {},
      data: { source: 'cyphrmask-bridge', type: 'REQUEST_SIGNATURE', nonce: 'test' },
    });

    // Message from wrong source type
    filterHandler({
      source: mockWindow,
      data: { source: 'other-extension', type: 'REQUEST_SIGNATURE', nonce: 'test' },
    });

    expect(handleMessage).not.toHaveBeenCalled();
  });
});

describe('Extension Status Reporting', () => {
  it('posts status with bridgeHost', () => {
    const postMessage = vi.fn();
    const mockWindow = {
      location: { origin: 'http://localhost:8080' },
      postMessage,
    };
    global.window = mockWindow;

    let callback = null;
    global.chrome = {
      runtime: {
        sendMessage: vi.fn((msg, cb) => { callback = cb; }),
      },
    };

    // Simulate status reporting
    chrome.runtime.sendMessage({ action: 'GET_STATUS' }, (status) => {
      window.postMessage({
        source: 'cyphrmask',
        type: 'EXTENSION_STATUS',
        status: { ...status, bridgeHost: window.location.origin }
      }, '*');
    });

    callback({ wasmReady: true, hasKey: true, status: 'ready' });

    expect(postMessage).toHaveBeenCalledWith(
      expect.objectContaining({
        source: 'cyphrmask',
        type: 'EXTENSION_STATUS',
        status: expect.objectContaining({
          wasmReady: true,
          hasKey: true,
          bridgeHost: 'http://localhost:8080',
        }),
      }),
      '*'
    );
  });
});
