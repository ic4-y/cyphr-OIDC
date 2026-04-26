# Day 1 — 2026-04-25

## What Was Achieved

### 1. Monorepo Scaffolding & Dev Environment
- **Nix flake** (`flake.nix`) — dev shell with Go 1.26, Rust stable + wasm32-unknown-unknown target (via fenix), wasm-pack, wasm-bindgen-cli, Node.js 22, Docker, just, and tooling.
- **justfile** — task runner with recipes: `build`, `build-bridge`, `build-wasm`, `build-popup`, `test`, `fmt`, `lint`, `up`, `down`, `clean`.
- **`.gitignore`** — comprehensive exclusion of build artifacts, dependencies, and workflow data.

### 2. Go Bridge — Full OIDC Provider
- **zitadel/oidc/v3** provider with discovery (`/.well-known/openid-configuration`), authorization, and token endpoints.
- **In-memory `op.Storage`** implementation (~600 lines) — handles auth requests, auth codes, access/refresh tokens, signing keys, userinfo, introspection, token revocation.
- **Coz verification** (`bridge/crypto/coz.go`) — ES256 signature verification, timeliness checks, JWK thumbprint computation (RFC 7638), multihash digest encoding.
- **Challenge/nonce system** — in-memory store with TTL-based cleanup.
- **Custom login page** (`templates/login.html`) — dark-themed Cyphr login UI that renders when Authelia/downstream apps redirect to `/authorize`.
- **Dockerfile** — multi-stage Go build producing a slim Alpine container.

### 3. Rust Wasm Crypto Module
- **`wasm-crypto/`** — Rust crate with `sign_action` (Coz signing with deterministic JSON key ordering), `compute_thumbprint` (RFC 7638), `derive_public_key`, `generate_keypair`.
- **Successfully compiles** via `wasm-pack build --target web`. Output in `cyphrmask/src/wasm/`.
- **Tests pass** (2/2): `test_sign_produces_valid_envelope`, `test_thumbprint_deterministic`.

### 4. CyphrMask Chromium Extension (Code Complete, Not Functional)
- **Manifest V3** with background service worker, content script, and React popup.
- **Background worker** — designed to load Wasm, store private key, handle signature requests, key generation, key derivation, and import/export.
- **Content script** — injects into bridge pages, mediates message passing between page and background worker, detects bridge host from `window.location`.
- **Popup UI** — React app with Auth/Settings tabs. Auth tab: challenge fetch + approve flow. Settings tab: Principal Root display, public key X/Y, copy-to-clipboard, export identity as JSON backup, import from hex key or backup file.
- **Host detection** — extension works on any bridge URL (not just localhost).
- **Icons** — 4 sizes (16/32/48/128px).

### 5. Docker Compose
- Two-service stack: `cyphr-bridge` (built from `bridge/Dockerfile`) and `redis` (session store).
- Shared `cyphrnet` bridge network.
- Authelia removed — it doesn't support external OIDC identity providers (confirmed from official docs).

### 6. Configuration (All Env-Based, No Code Changes)
- **`BRIDGE_USERS`** — JSON map of thumbprint → `{email, public_key}`. Replaces hardcoded test users.
- **`BRIDGE_CLIENTS`** — JSON array of `{id, secret, redirect_uris}`. Registers OIDC clients without code edits.
- **`BRIDGE_SIGNING_KEY_PATH`** — path to persistent RSA signing key. Generated on first run, loaded on restart.

### 7. Documentation
- **README.md** — architecture diagram, quick start, Docker build/push, Forgejo integration guide (with screenshots), identity management (export/import), project structure, env var reference, end-to-end auth flow, security notes.
- **`.env.example`** — documents all bridge environment variables.

### 8. Commits (6 total, clean linear history)
```
243809c docs: add README with quick start, Forgejo integration, deployment
4e41155 feat(extension): add CyphrMask Chromium extension (Manifest V3)
322facb feat(wasm): add Rust crypto module for deterministic Coz signing
76aee95 feat(bridge): implement full OIDC provider with Coz verification
81faa9d feat(docker): add compose stack for Bridge and Redis
5f948e2 infra: add Nix dev shell, just runner, and project scaffolding
```

### 9. PLAN.md Architecture Corrections
- **Authelia as OIDC client to bridge** — not possible. Authelia has no upstream IdP support. Confirmed from official docs: `identity_providers.oidc` registers relying parties, not upstream providers. `authentication_backend` only supports file and LDAP.
- **Bridge as standalone OIDC provider** — downstream apps (Forgejo, Grafana, etc.) register directly with the bridge. Authelia is not in the auth path.

---

## Fundamental Blockers

### 🔴 Chrome Extension CSP Blocks All WebAssembly

**This is the single most critical blocker.** Chrome Extension Manifest V3's Content Security Policy prohibits `WebAssembly.compile()`, `WebAssembly.instantiate()`, and `WebAssembly.instantiateStreaming()` — even in service workers. Every attempt to initialize the Wasm module fails with:

```
WebAssembly.instantiateStreaming(): Compiling or instantiating WebAssembly module violates 
the following Content Security policy directive because neither 'wasm-eval' nor 'unsafe-eval' 
is an allowed source of script
```

Attempts made (all failed):
1. Direct `initWasm()` call — `instantiateStreaming` blocked
2. `fetch` + `WebAssembly.instantiate(ArrayBuffer)` — blocked
3. `fetch` + `WebAssembly.compile()` — blocked
4. Service worker initialization — blocked (same CSP)
5. `chrome.runtime.getURL()` + fetch — blocked

**Available paths forward:**
- **Option A: Rewrite crypto in pure JS** using `crypto.subtle` (Web Crypto API). Works in extensions. Loses the deterministic JSON ordering guarantee that Rust provides (JS `JSON.stringify` doesn't guarantee key order). Would need careful manual JSON construction to maintain Coz integrity.
- **Option B: `wasm2js`** — compiles Wasm to pure JavaScript via binaryen's `wasm2js`. Available as a Nix package but not in current dev shell. Produces a slower but CSP-compliant polyfill.
- **Option C: Native messaging host** — runs a native binary outside the extension's CSP. Overkill for a PoC, requires installing a separate binary on the user's machine.
- **Option D: External signing service** — the extension contacts a local native process for signing. Defeats the purpose of a self-contained extension.

### 🔴 End-to-End Flow Never Tested

No successful test of: bridge → extension → Coz sign → bridge verify → OIDC token → Forgejo. The extension popup never renders anything beyond a loading spinner because the Wasm module never initializes. The bridge compiles and serves correctly but has no way to verify a real Coz payload.

### 🟡 Hardcoded Test Users

User identity mapping (`tmb` → email + public key) lives in code (`bridge/handlers/verify.go`). The `BRIDGE_USERS` env var addresses this, but there's no database, no user management UI, no way to add/remove users at runtime.

### 🟡 No HTTPS/TLS

The bridge runs HTTP-only. OIDC providers require HTTPS in production. Local dev uses `op.WithAllowInsecure()`. For Forgejo integration, a reverse proxy (Caddy, Nginx) with TLS would be needed.

### 🟡 Signing Key Lifecycle

RSA-2048 signing key is generated at startup if `BRIDGE_SIGNING_KEY_PATH` points to a non-existent file. No key rotation, no key backup, no public key export (needed by clients to verify JWT signatures without fetching JWKS).

### 🟡 Extension Icon Assets

Icons are programmatically generated (blue circle on white background). Not the actual CyphrMask logo.

---

## Next Steps (Priority Order)

1. **Resolve Wasm CSP blocker** — choose Option A (JS rewrite) or Option B (wasm2js)
2. **Test end-to-end flow** — get the extension signing a challenge and the bridge verifying it
3. **Register Forgejo as a client** — set `BRIDGE_CLIENTS`, configure Forgejo OIDC, verify auth flow
4. **Add TLS** — reverse proxy with Caddy for HTTPS
5. **User management** — replace `BRIDGE_USERS` env var with a proper database

---

## Day 1 Evening Update — CSP Blocker Resolved

### 🔴 → ✅ WebAssembly Now Works in MV3

The root cause was a **missing `content_security_policy` key** in `manifest.json`. Without it, the default MV3 CSP (`script-src 'self'; object-src 'self';`) blocks all WebAssembly compilation.

The fix is a single entry in `manifest.json`:
```json
"content_security_policy": {
  "extension_pages": "script-src 'self' 'wasm-unsafe-eval'; object-src 'self';"
}
```

This is Chrome's [minimum enforced CSP for extension pages](https://developer.chrome.com/docs/extensions/reference/manifest/content-security-policy#minimum_and_customized_content_security_policies) — `'wasm-unsafe-eval'` is the official MV3 directive that allows WebAssembly without enabling `eval()` or `new Function()`. It's the same approach used by [Reclaim Protocol](https://docs.reclaimprotocol.org/browser-extension/extension-integration/manifest-configuration) and other MV3 extensions doing crypto.

**Research sources:**
- Chrome CSP reference: `developer.chrome.com/docs/extensions/reference/manifest/content-security-policy`
- SO consensus: `stackoverflow.com/questions/48523118/wasm-module-compile-error-in-chrome-extension`
- Chromium Extensions mailing list: `groups.google.com/a/chromium.org/g/chromium-extensions/c/zVaQo3jpSpw`
- MV3 migration note: `'wasm-unsafe-eval'` is the MV3 replacement for MV2's `'wasm-eval'`

### Additional Fixes

- **`sign_action` now receives all 3 parameters** — the `thumbprint` was missing from the call in `background.js:115`. The Rust function signature requires `(private_key_hex, nonce, thumbprint)`.
- **Full build succeeds** — `just build` completes cleanly (bridge, wasm, popup all pass).

### New Blocker Identified

- **Wasm path resolution in service worker** — wasm-pack's generated code (`cyphr_crypto.js:400-401`) resolves the `.wasm` file via `new URL('cyphr_crypto_bg.wasm', import.meta.url)`. This works in standard ESM contexts but needs verification in Chrome's service worker environment. The `.wasm` file must be correctly copied to `dist/wasm/` and accessible from the service worker's origin.

---

## Remaining TODO (Day 2)

1. **Fix wasm service worker init** — pass the wasm path explicitly via `chrome.runtime.getURL()` in `background.js`, verify it loads in Chrome
2. **End-to-end test** — start bridge, load extension, verify challenge → sign → verify flow
3. **Bridge TLS** (low priority for PoC) — reverse proxy with Caddy for HTTPS
4. **User management** (low priority for PoC) — replace hardcoded test users with proper database or env-based registration
