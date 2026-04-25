// CyphrMask Background Service Worker
// Handles Wasm crypto module loading and signature requests

import initWasm, { sign_action } from './wasm/cyphr_crypto.js';

let wasmReady = false;
let privateKey = null;

// Initialize Wasm module on startup
(async () => {
  try {
    await initWasm();
    wasmReady = true;
    console.log('[CyphrMask] Wasm crypto module initialized');
  } catch (err) {
    console.error('[CyphrMask] Failed to initialize Wasm:', err);
  }
})();

// Load key from Chrome storage on startup
chrome.storage.local.get(['privateKey'], (result) => {
  if (result.privateKey) {
    privateKey = result.privateKey;
  }
});

// Handle messages from content scripts and popup
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  switch (message.action) {
    case 'PING':
      sendResponse({ status: wasmReady ? 'ready' : 'loading' });
      break;

    case 'REQUEST_SIGNATURE':
      handleSignatureRequest(message.nonce)
        .then(coz => sendResponse({ coz }))
        .catch(err => sendResponse({ error: err.message }));
      return true; // Keep message channel open for async response

    case 'SET_KEY':
      privateKey = message.privateKey;
      chrome.storage.local.set({ privateKey: message.privateKey });
      sendResponse({ success: true });
      break;

    case 'GET_STATUS':
      sendResponse({
        wasmReady,
        hasKey: !!privateKey,
      });
      break;

    default:
      sendResponse({ error: 'Unknown action' });
  }
});

async function handleSignatureRequest(nonce) {
  if (!wasmReady) {
    throw new Error('Wasm module not ready');
  }
  if (!privateKey) {
    throw new Error('No private key configured');
  }

  // Pass the hex-encoded private key directly to the Wasm function
  const cozString = sign_action(privateKey, nonce);

  return cozString;
}
