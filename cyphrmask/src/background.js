// CyphrMask Background Service Worker
// Handles Wasm crypto module loading and signature requests

// Import wasm module natively (Chrome Extension supports ESM wasm imports)
import wasmModule, { sign_action, derive_public_key, compute_thumbprint, generate_keypair } from './wasm/cyphr_crypto.js';

let wasmReady = false;
let privateKey = null;
let wasmInitError = null;

// Initialize Wasm module on startup
(async () => {
  try {
    await wasmModule();
    wasmReady = true;
    console.log('[CyphrMask] Wasm crypto module initialized');
  } catch (err) {
    wasmInitError = err.message;
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
      sendResponse({ status: wasmReady ? 'ready' : wasmInitError ? `error: ${wasmInitError}` : 'loading' });
      break;

    case 'REQUEST_SIGNATURE':
      if (wasmInitError) {
        sendResponse({ error: `Wasm not ready: ${wasmInitError}` });
        break;
      }
      handleSignatureRequest(message.nonce)
        .then(coz => sendResponse({ coz }))
        .catch(err => sendResponse({ error: err.message }));
      return true;

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
      try {
        const keys = JSON.parse(generate_keypair());
        const thumbprint = compute_thumbprint(keys.public_key_x, keys.public_key_y);
        privateKey = keys.private_key;
        chrome.storage.local.set({ privateKey: keys.private_key });
        sendResponse({
          privateKey: keys.private_key,
          publicKeyX: keys.public_key_x,
          publicKeyY: keys.public_key_y,
          thumbprint,
        });
      } catch (err) {
        sendResponse({ error: err.message });
      }
      break;

    case 'DERIVE_KEY':
      try {
        const derived = JSON.parse(derive_public_key(message.privateKey));
        sendResponse(derived);
      } catch (err) {
        sendResponse({ error: err.message });
      }
      break;

    case 'IMPORT_KEY':
      try {
        const derived = JSON.parse(derive_public_key(message.privateKey));
        privateKey = message.privateKey;
        chrome.storage.local.set({ privateKey: message.privateKey });
        sendResponse({
          privateKey: message.privateKey,
          publicKeyX: derived.public_key_x,
          publicKeyY: derived.public_key_y,
          thumbprint: derived.thumbprint,
        });
      } catch (err) {
        sendResponse({ error: err.message });
      }
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
  const derived = JSON.parse(derive_public_key(privateKey));
  return sign_action(privateKey, nonce, derived.thumbprint);
}
