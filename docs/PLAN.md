

---

## Status: COMPLETE (2026-04-26)

All phases implemented. The repo is public at https://github.com/ic4-y/cyphr-OIDC.

### What was built

- **Go Bridge** — Full OIDC provider via `zitadel/oidc/v3` with Coz signature verification
- **Rust Wasm crypto** — Deterministic Coz signing, thumbprint computation, key generation
- **CyphrMask extension** — Manifest V3, React popup, Wasm service worker, content script bridge
- **Forgejo integration** — Pre-configured in `docker-compose.yml` with SQLite, auto admin user, auto OIDC auth source
- **End-to-end flow** — Forgejo → Bridge → Extension signs → Bridge verifies → OIDC token → Forgejo creates user

### What was NOT built (intentionally deferred)

- **TLS / HTTPS** — HTTP only with `op.WithAllowInsecure()`. Add Caddy reverse proxy for production.
- **User database** — Env-var based (`BRIDGE_USERS`). No runtime user management.
- **Extension unlock PIN** — No PIN protecting signing operations.
- **Authelia integration** — The original plan mentioned Authelia, but Forgejo was used instead as the real-world OIDC client.

---

Based on the core mechanics and specifications of the Cyphr protocol, here is the **Enriched Cyphr-OIDC Bridge & CyphrMask PoC Plan**. 


Since Cyphr introduces very specific cryptographic constraints—most notably **Coz (Bit-Perfect JSON Signing)**, **MultihashDigests**, and **Implicit Promotion**—we must design the Bridge and Extension to handle these data structures flawlessly. Standard web tools (like JavaScript's `JSON.stringify`) will break the signature if not handled correctly.

Here is the updated, spec-compliant technical blueprint for your Monorepo.

---

# 1. Monorepo Architecture & Spec Alignment

The system relies on three primary actors:
1.  **Authelia (OIDC Client):** Requires a standard JWT/session.
2.  **Cyphr-OIDC Bridge (Go Backend):** Translates Cyphr `Coz` signatures into OIDC JWTs. Validates `MultihashDigest` and Level 1 Principal Roots.
3.  **CyphrMask (Chromium Extension):** Stores the Level 1 key, executes Rust-compiled Wasm to guarantee bit-perfect `Coz` formatting, and intercepts Bridge challenges.

### Directory Structure
```text
cyphr-poc-monorepo/
├── bridge/                     # Go Backend
│   ├── go.mod                  # Requires: github.com/Cyphrme/Cyphr, github.com/zitadel/oidc/v3
│   ├── main.go
│   ├── crypto/                 # Multihash and Coz verification logic
│   └── templates/              # HTML frontend for the bridge page
├── cyphrmask/                  # Chromium Extension
│   ├── manifest.json           # Manifest V3
│   ├── src/                    # TS React UI, content.js, background.js
│   └── wasm-crypto/            # Rust Wasm (cyphr crate) for Bit-Perfect JSON
└── docker-compose.yml          # Authelia + Bridge + Apps network
```

---

# 2. Spec-Enriched Component Design

### A. The Cryptographic Payload (Coz)
According to the specification, Cyphr uses **Coz** to prevent JSON serialization from breaking signatures. The payload must retain exact byte fidelity. For authentication into the Bridge, we will use an Authenticated Atomic Action (AAA) payload.

The Bridge will expect the extension to return a signed Coz message that looks like this:

```json
{
  "pay": {
    "alg": "ES256",
    "tmb": "cLj8vsYtMBwYkzoFVZHBZo6SNL5hTN0OU1ygWJdBJak",
    "typ": "cyphr/auth/challenge",
    "now": 1745523600,
    "nonce": "a8f9c2...<32-byte-hex>..."
  },
  "sig": "<base64url-encoded-signature-of-pay-bytes>"
}
```
*Note: Because this is a Level 1 Principal, the protocol's **Implicit Promotion** rule means the key's thumbprint (`tmb`) IS the Principal Root (PR). No MALT tree traversal is needed yet.*

### B. CyphrMask (The Wasm/Rust Strategy)
The biggest trap in web cryptography is JavaScript's unpredictable object key ordering. If JS reorders `"typ"` and `"now"`, the signature verification will fail on the backend. 

**The Wasm Solution:**
1.  The TS/React frontend handles the UI and retrieves the `nonce` from the Bridge.
2.  It passes the `nonce` and the user's private key material (from Chrome local storage) to the Rust Wasm module.
3.  **The Rust `cyphr` crate constructs the string in memory**, ensuring deterministic byte-order.
4.  Rust signs the raw bytes of `"pay"`.
5.  Rust constructs the final JSON string with `"pay"` and `"sig"` and returns it to JavaScript as an immutable string.
6.  JS sends this *exact string* to the Bridge via a `POST` request (`Content-Type: application/json`).

### C. The Cyphr-OIDC Bridge (The Go Backend)
The backend must adhere to the **Algorithm Agnostic** and **Multihash** specifications. 

1.  **State/DB Schema:** 
    Instead of standard strings, user identities must be stored as parsed `MultihashDigest` values.
    *   Table: `users`
    *   Columns: `internal_id` (UUID), `principal_root` (Multihash blob), `email` (String, mapped to Authelia).
2.  **Challenge Generation (`GET /api/challenge`):** 
    Generates a cryptographically secure 32-byte nonce, stores it in an ephemeral Redis/memory cache tied to the browser's session cookie.
3.  **Verification (`POST /api/verify`):** 
    *   Reads the raw request body bytes to preserve Coz integrity.
    *   Uses the Go `Cyphr` library to parse the `Coz` envelope.
    *   Checks the `now` timestamp against server time (e.g., +/- 60 seconds) to prevent replay.
    *   Validates the `nonce` against the session cache.
    *   Verifies the `sig` against the `pay` bytes using the algorithm specified in `alg` (e.g., `ES256` or post-quantum `ML-DSA`).
    *   Extracts `tmb`. Because it's a Level 1 identity, `tmb == PR`. 
    *   Queries the DB: `SELECT email FROM users WHERE principal_root = ?`
    *   Mints the OIDC JWT for Authelia.

---

# 3. Step-by-Step Development Execution

### Phase 1: Local Environment & Authelia Setup
1.  Initialize `docker-compose.yml`.
2.  Configure Authelia's `configuration.yml` to use `http://cyphr-bridge:8080` as an upstream OIDC Provider (OIDC Client configuration).
3.  Set up a dummy target application (e.g., Nextcloud or a simple `whoami` container) protected by Authelia.

### Phase 2: Build the Go Bridge Service
1.  Initialize the Go module in `/bridge`.
2.  Import `github.com/zitadel/oidc/v3/op` to stand up the OIDC provider endpoints (`/.well-known/openid-configuration`, `/oauth/token`, etc.).
3.  Build the custom UI at `/authorize` (the HTML page that loads when Authelia redirects the user).
4.  Build the `/api/challenge` and `/api/verify` endpoints implementing the Coz parsing logic described above.
5.  Hardcode a test user database mapping your intended `tmb` to your Authelia `email` for the PoC.

### Phase 3: Build the Wasm Crypto Module
1.  In `/cyphrmask/wasm-crypto`, run `cargo init --lib`.
2.  Add `wasm-bindgen` and the Rust `cyphr` crate to `Cargo.toml`.
3.  Write the `sign_action(private_key: &[u8], nonce: &str) -> String` function.
4.  Run `wasm-pack build --target web` to compile it.

### Phase 4: Build the CyphrMask Extension
1.  Set up the Manifest V3 extension.
2.  Import the generated Wasm bundle into the background service worker.
3.  **Content Script (`content.js`):** Inject a listener into the Bridge's HTML page so that clicking "Sign In" on the Bridge triggers `chrome.runtime.sendMessage({ action: "REQUEST_SIGNATURE", nonce: ... })`.
4.  **Popup UI:** Build a simple React popup that displays the challenge and an "Approve" button.
5.  On approval, route the `nonce` and local key to the Wasm module, get the `Coz` string, and return it to the content script.

---

# 4. Addressing Future Specifications (The Roadmap)

By building the PoC this way, you perfectly position your organization for the missing Cyphr features once they are implemented by the upstream protocol maintainers:

*   **When Mutual State Synchronization (MSS) is released:** You won't need to change the Extension or Authelia. You simply update the Bridge to act as a **Witness Node**. The Bridge will automatically subscribe to your principal's state updates, meaning if you revoke a key from your phone, the Bridge knows instantly and invalidates any active OIDC sessions tied to that key.
*   **When you upgrade to Level 2 (Key Replacement):** The Bridge's verification logic just changes from `tmb == PR` to walking the **MALT (Merkle Append-only Log Tree)**. The Wasm module will append your commit history to the `Coz` payload, proving your new key traces back mathematically to the original `tmb` stored in the Bridge's database.

This architecture creates a completely frictionless transition: you get the structural security and post-quantum readiness of self-sovereign identity, while seamlessly speaking the legacy OIDC language that your existing network stack requires.
