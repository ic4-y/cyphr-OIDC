// Deterministic ECDSA P-256 test identity for e2e tests.
// Generated once; same key is used across all runs so the bridge
// can be pre-configured with BRIDGE_USERS.
export const TEST_IDENTITY = {
  // Raw 32-byte private key as 64-char hex string
  privateKeyHex: '53a3ae6a231cac1562372dead986f6f1e19ccb50d9549a9ea5ba068d449d1ff5',
  // Uncompressed public key: 04 || X(32) || Y(32) = 65 bytes = 130 hex chars
  publicKeyHex: '041e65c079314884a299a1052e2a65dcc322b16cfec6228b42f9c3082c372fd31f4a4be96ad5707e79c849666db8bf84318da28a0f77c9caa377d6e71c84143621',
  // JWK thumbprint (RFC 7638), base64url-encoded SHA-256 of canonical JWK
  thumbprint: 'azXsImbzLeghWzQsPs_oPWDRPRZi2pVpS-65-svOuPU',
  email: 'e2e-test@example.com',
} as const;
