# Day 2 — 2026-04-26

## What Was Achieved

### 1. 🔴 WebAssembly Service Worker Init — Fixed

The wasm-pack generated code uses `new URL('cyphr_crypto_bg.wasm', import.meta.url)` which fails in Chrome's service worker context. Fixed in `background.js` by passing an explicit path:

```js
const wasmUrl = chrome.runtime.getURL('wasm/cyphr_crypto_bg.wasm');
await wasmModule(wasmUrl);
```

The `.wasm` file is already copied to `dist/wasm/` by `vite.config.js`, so the path resolves correctly from the extension origin.

### 2. 🔴 Login Page → Extension Messaging — Fixed

`login.html` (served as a regular web page at `http://localhost:8080/login`) was calling `chrome.runtime.sendMessage` directly. This API is `undefined` in web page contexts — it only works inside extension pages (popup, service worker).

**Root cause:** The extension's content script (`content.js`) injects into `http://localhost:8080/*` and sets up a `postMessage` bridge, but `login.html` never used it.

**Fix:** Replaced direct `chrome.runtime.sendMessage` with `window.postMessage`. The message flows: `login.html` → `window.postMessage` → content script → `chrome.runtime.sendMessage` → background worker → response back through content script → `postMessage` → `login.html`.

### 3. 🔴 Signature Verification Encoding — Fixed

`verify.go` extracted the base64url signature string by slicing off the first and last characters (`sigStr[1:len(sigStr)-1]`), assuming JSON string quotes. This is fragile — it breaks if the JSON encoder uses different formatting or if the signature contains escaped quotes.

**Fix:** Replaced with `json.Unmarshal(sigRaw, &sigStr)` — proper JSON decoding into a string variable.

### 4. 🔴 Chrome MV3 Popup + File Input Crash — Resolved via Options Page

`<input type="file">` inside a Manifest V3 extension popup reliably crashes Chromium on Linux (issues [40276394](https://issues.chromium.org/issues/40276394), [40638231](https://issues.chromium.org/issues/40638231)). The native file picker kills the extension popup process. The only reliable workaround is to avoid `<input type="file">` in the popup entirely.

**Solution:** Created a dedicated options page (`options_ui` in manifest, `open_in_tab: true`) that contains all key management — identity display, hex import, file import, export, and key generation. The popup's "Import Backup File" button now calls `chrome.runtime.openOptionsPage()` instead of using a file input.

The options page is a full browser tab, not a popup, so `<input type="file">` works without crashing.

### 5. 🔴 OIDC Callback Flow — Fixed

After successful Coz verification, the login page redirected to `/login/callback?id=...` which hit Zitadel's `AuthorizeCallbackHandler` (designed for external IDPs). This returned a 404 because our custom Coz verification flow doesn't use Zitadel's external IDP redirect mechanism.

**Fix:** Replaced with a custom `CallbackHandler` (`bridge/handlers/callback.go`) that:
1. Looks up the auth request by ID
2. Generates a random authorization code
3. Stores the code→request mapping via `storage.SaveAuthCode`
4. Redirects to the client's `redirect_uri` with `code` and `state` parameters

Added a `TokenCallbackHandler` (`bridge/handlers/token_callback.go`) for the `/callback` endpoint that the client redirects to. Shows a success page with the subject (thumbprint) and state.

### 6. 🔴 Rust Double-Hash Bug — Fixed

The Rust `sign_bytes` function in `wasm-crypto/src/lib.rs` pre-hashed the payload before signing:

```rust
let hash = Sha256::digest(data);
let signature: Signature = signing_key.sign(&hash);
```

`ecdsa::SigningKey::sign()` already hashes internally with SHA-256. Passing a pre-hashed value caused `SHA256(SHA256(data))`, while the Go verifier expected `SHA256(data)`. This caused `ecdsa.Verify` to return `false` every time.

**Fix:** Sign the raw bytes directly:

```rust
let signature: Signature = signing_key.sign(data);
```

### 7. 🟡 Empty Public Key from `.env` — Fixed

`storage.TestUser` struct had no JSON tags. The `.env` file uses snake_case field names (`"public_key"`, `"email"`) but Go's `json.Unmarshal` looks for `"PublicKey"`, `"Email"` by default. The public key field was silently ignored, leaving it empty.

**Fix:** Added struct tags:

```go
type TestUser struct {
    PublicKey string `json:"public_key"`
    Email     string `json:"email"`
}
```

### 8. 🟡 Developer Experience Improvements

- **`just run`** — new recipe to start the bridge for local dev testing (no Docker). Auto-creates `bridge/.keys/` directory.
- **`.env` support** — `justfile` uses `set dotenv-load` to auto-load `.env` files. Added `.env` (gitignored) and updated `.env.example`.
- **Copy Bridge User JSON button** — one-click copy of `BRIDGE_USERS='{"tmb":{"public_key":"04...","email":"..."}}'` from both the popup (Settings tab) and options page. The public key is pre-formatted as uncompressed hex (`04` + X + Y).
- **Popup feedback** — "copied!" success message now renders in the Settings tab (was only visible in Auth tab).
- **`.keys/` gitignored** — signing key directory added to `.gitignore`.
- **Error logging** — backup import `catch` blocks in both popup and options page now log errors to console instead of silently swallowing them.

### 9. 🟡 Debug Infrastructure

Added (and later removed) debug logging to `verify.go` to diagnose signature verification failures:
- Logged thumbprint lookup results and public key values
- Logged SHA-256 hash of payload bytes for comparison with Rust-side signing

All debug logs removed after fixing the double-hash bug.

### 10. Commits (Squashed to 1 in main)

All changes merged via PR #2, squashed into `main`:

```
7ec59ee fix: complete OIDC auth flow — options page, login bridge, and callback handling
```

**17 files changed, 535 insertions, 92 deletions.**

---

## Testing Infrastructure (PR #6 — feat/comprehensive-testing)

### Test Suite

**127 tests total** across 3 ecosystems:

| Layer | Tests | Coverage |
|-------|-------|----------|
| Go — crypto | 27 (coz: 16, multihash: 11) | 89.8% |
| Go — handlers | 25 (challenge: 13, verify: 10, callback: 5, token_callback: 3) | 69.0% |
| Go — storage | 19 | 29.4% |
| Go — e2e | 6 | integration flow covered |
| Go — testutil | 9 helpers (covered by callers) | n/a |
| Rust wasm | 13 | all pass |
| Extension | 17 (background: 11, content: 6) | all pass (mocks) |
| **Total** | **127** | **40.5% Go overall** |

### New Test Files

- `bridge/crypto/coz_test.go` — expanded from 3 to 16 tests (signature verification, timeliness, thumbprint)
- `bridge/crypto/multihash_test.go` — 11 new tests (EncodeMultihash, ParseMultihash, Equal, round-trip)
- `bridge/handlers/challenge_test.go` — 13 tests (ChallengeStore lifecycle, nonce/state generation)
- `bridge/handlers/verify_test.go` — 10 tests (loadUsers, HTTP handler error paths)
- `bridge/handlers/callback_test.go` — 5 tests (CallbackHandler.ServeHTTP, genCode)
- `bridge/handlers/token_callback_test.go` — 3 tests (TokenCallbackHandler.ServeHTTP)
- `bridge/e2e/e2e_test.go` — 6 tests (full flow, nonce mismatch, unknown key, replay, timeliness, multi-user)
- `bridge/storage/storage_test.go` — 19 tests (auth requests, codes, clients, username/password)
- `bridge/storage/testing.go` — test helpers (CreateTestAuthRequest, CompleteTestAuthRequest)
- `bridge/internal/testutil/testutil.go` — shared test utilities (NewTestKey, SignCozPayload, BuildUsersJSON)
- `cyphrmask/src/__tests__/background.test.js` — 11 tests (message routing)
- `cyphrmask/src/__tests__/content.test.js` — 6 tests (postMessage bridge)
- `cyphrmask/vitest.config.js` — Vitest configuration
- `cyphrmask/src/__tests__/setup.js` — Chrome API mocks

### CI & Tooling

- `.github/workflows/test.yml` — GitHub Actions: Go tests, Rust tests, extension tests, build verification
- `justfile` — `test`, `test-go`, `test-go-unit`, `test-go-e2e`, `test-rust`, `test-extension` recipes

### Fully Covered (100%)

- `crypto/multihash.go`, `handlers/callback.go`, `handlers/token_callback.go`, `handlers/challenge.go`, `crypto/coz.go` (core functions)

---

## Blockers Remaining

### 🟡 No HTTPS/TLS

The bridge runs HTTP-only on `localhost:8080`. OIDC providers require HTTPS in production. Local dev uses `op.WithAllowInsecure()`. A reverse proxy (Caddy) with TLS would be needed for production deployment.

### 🟡 No Real Client Integration

Forgejo was not tested as an OIDC client. The full flow works with the built-in `cyphrmask-poc` client, but Forgejo's OIDC implementation hasn't been validated.

### 🟡 No User Database

User identity mapping still relies on `BRIDGE_USERS` env var. No runtime user management, no password/PIN to unlock the extension, no multi-user support.

### 🔴 CI Failures (PR #6)

- **Missing go.sum** — dependencies added by tests (storage, handlers) were not committed to `go.sum`
- **Node.js 20 deprecation** — GitHub Actions `actions/checkout@v4` and `actions/setup-go@v5` running on deprecated Node.js 20 runtime

---

## Next Steps (Priority Order)

1. **Fix CI** — commit `go.sum`, update GitHub Actions to Node.js 24 compatible versions
2. **Test with Forgejo** — register as an OIDC client, configure Forgejo to use the bridge, verify full auth flow
3. **Add TLS** — Caddy reverse proxy with Let's Encrypt for HTTPS
4. **Extension unlock PIN** — require a PIN to use the extension, preventing unauthorized signing
5. **User database** — replace `BRIDGE_USERS` with a persistent store
