// CyphrMask Content Script
// Injects into the Bridge page to facilitate extension communication

(function () {
  'use strict';

  // Detect the bridge host from the current page URL
  const bridgeHost = window.location.origin;

  // Signal to the page that the extension is available
  window.postMessage({
    source: 'cyphrmask',
    type: 'EXTENSION_AVAILABLE'
  }, '*');

  // Listen for messages from the Bridge page
  window.addEventListener('message', (event) => {
    if (event.source !== window) return;
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
  });

  // Notify the page when the extension is ready, including the detected host
  chrome.runtime.sendMessage({ action: 'GET_STATUS' }, (status) => {
    window.postMessage({
      source: 'cyphrmask',
      type: 'EXTENSION_STATUS',
      status: { ...status, bridgeHost }
    }, '*');
  });
})();
