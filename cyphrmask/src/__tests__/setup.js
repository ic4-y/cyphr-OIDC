// Mock Chrome extension APIs for Vitest
global.chrome = {
  runtime: {
    getURL: (path) => `chrome-extension://mock-id/${path}`,
    onMessage: {
      addListener: () => {},
    },
    sendMessage: (msg, callback) => {
      if (msg.action === 'PING') {
        callback({ status: 'ready' });
      } else if (msg.action === 'GET_STATUS') {
        callback({ wasmReady: true, hasKey: true, status: 'ready' });
      }
    },
  },
  storage: {
    local: {
      get: (keys, callback) => callback({}),
      set: () => {},
    },
  },
};
