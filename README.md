# Cyphr-OIDC Bridge

A proof-of-concept that bridges the **Cyphr protocol** (self-sovereign identity with Coz bit-perfect JSON signing) to **standard OpenID Connect**. Any OIDC-capable application — Forgejo, Grafana, Nextcloud, Gitea — can authenticate users via CyphrMask, a Chromium extension that holds the user's cryptographic identity.

No fork, no patch, no protocol changes to downstream apps. They just see a standard OIDC provider.

> **New to Cyphr?** Read the [introduction post](https://blog.cyphr.me/posts/introducing-cyphr.html) or the full [protocol documentation](https://docs.cyphr.me/).

---

## Quick Start

### From Scratch (5 minutes)

```bash
# 1. Enter the dev shell (NixOS)
nix develop

# 2. Build everything
just build

# 3. Start the bridge
just up

# 4. Verify it's running
curl http://localhost:8080/.well-known/openid-configuration
curl http://localhost:8080/health
```

The bridge is now serving as an OIDC provider on `http://localhost:8080`. See [Registering a Client Application](#registering-a-client-application) below for connecting Forgejo or any other OIDC-capable app.

### Deploying a Docker Image

The bridge builds into a slim Alpine container:

```bash
# Build locally
docker compose build

# Tag and push to GHCR (or any registry)
docker tag cyphrmask-oidc-poc-bridge ghcr.io/<your-username>/cyphr-bridge:latest
docker push ghcr.io/<your-username>/cyphr-bridge:latest
```

On your deployment server:

```yaml
# docker-compose.yml (production)
services:
  bridge:
    image: ghcr.io/<your-username>/cyphr-bridge:latest
    environment:
      - BRIDGE_ISSUER_URL=https://bridge.example.com
    ports:
      - "8080:8080"
    # Mount your TLS certs, configure a reverse proxy, etc.
```

---

## Architecture

```
┌─────────────────┐     ┌──────────────────┐     ┌──────────────────┐
│   Downstream     │     │  Cyphr-OIDC      │     │   CyphrMask      │
│   Application    │────▶│     Bridge       │◀───▶│  (Chromium Ext)  │
│  (Forgejo, etc.) │     │  (Go + zitadel)  │     │  (TS + Rust/Wasm)│
└─────────────────┘     └──────────────────┘     └──────────────────┘
        │                        │                        │
        │ OIDC redirect          │ OIDC token             │ Coz payload
        │ + code exchange        │ minting + JWT          │ (ES256 signed)
        ▼                        ▼                        ▼
    User authenticated    Discovery: /.well-known/   Stores P-256 keypair
                          openid-configuration        Signs challenges in Wasm
                          /authorize → /login         Returns bit-perfect JSON
                          /oauth/token
```

### Key Components

| Component | Stack | Role |
|-----------|-------|------|
| **Bridge** | Go + `zitadel/oidc/v3` | Full OIDC provider. Exposes discovery, authorization, and token endpoints. Renders the Cyphr login page and verifies Coz signatures. |
| **CyphrMask** | Chromium Extension (Manifest V3) | Stores the user's P-256 keypair. Signs challenge nonces using a Rust/Wasm module to guarantee bit-perfect `Coz` JSON ordering. |
| **Wasm Crypto** | Rust + `p256` + `wasm-bindgen` | Constructs the AAA payload in memory with deterministic key ordering, signs raw bytes with ES256, returns the complete `Coz` envelope. |
| **Redis** | `redis:7-alpine` | Session store for challenge nonces (ephemeral, TTL-based). |

### What is Coz?

**Coz** (Cyphr One-Zero) is a bit-perfect JSON signing format. Unlike standard web crypto where `JSON.stringify` may reorder object keys between platforms, Coz preserves the exact byte sequence that was signed. This is critical because if the backend re-serializes the payload, the signature verification fails. The Rust Wasm module guarantees the `pay` field bytes match exactly what was signed.

---

## Forgejo Integration

Forgejo supports OpenID Connect authentication natively. Here's how to register the Bridge as an OIDC login source.

### Step 1: Register the Bridge as a Client

In `bridge/main.go`, add Forgejo as an OIDC client:

```go
oidcStore.RegisterClient(storage.NewClient(
    "forgejo",                         // client_id
    "forgejo-secret",                  // client_secret (save this!)
    []string{"https://forgejo.example.com/user/oauth2/Cyphr/callback"},
    func(id string) string {
        return "/login?authRequestID=" + id
    },
))
```

Rebuild and deploy the bridge.

### Step 2: Add an Authentication Source in Forgejo

1. Log in to Forgejo as an **admin**
2. Navigate to **Site Administration → Authentication Sources** (`/admin/auths/new`)
3. Create a new source with these settings:

| Field | Value |
|-------|-------|
| **Authentication type** | OAuth2 |
| **Authentication name** | CyphrMask (or any name you like) |
| **OAuth2 provider** | OpenID Connect |
| **Client ID** | `forgejo` (the `client_id` from Step 1) |
| **Client Secret** | `forgejo-secret` (the secret from Step 1) |
| **OpenID Connect Auto Discovery URL** | `https://bridge.example.com/.well-known/openid-configuration` |
| **Icon URL** | (optional, e.g. your CyphrMask logo) |

Leave all other fields at their default values.

### Step 3: Test the Login Flow

1. Log out of Forgejo
2. Visit `https://forgejo.example.com/user/login`
3. You should now see a **Sign in with CyphrMask** button
4. Click it → you'll be redirected to the Bridge's Cyphr login page
5. Approve in the CyphrMask extension → Forgejo creates/links your account

### Optional: Make CyphrMask the Only Login Method

If you want to skip the username/password form entirely:

```ini
# In your Forgejo app.ini
[service]
DISABLE_REGISTRATION = true

# And in Forgejo admin → Authentication Sources, set the CyphrMask source as default
```

This is [an open issue](https://codeberg.org/forgejo/forgejo/issues/732) in Forgejo — for now, the login form still appears but users can only authenticate via OIDC if `DISABLE_REGISTRATION = true` and no other auth sources exist.

---

## Registering a Client Application

Any OIDC-capable application can use the Bridge. The registration pattern is the same as Forgejo:

1. **Add the client** in `bridge/main.go`:
   ```go
   oidcStore.RegisterClient(storage.NewClient(
       "my-app",
       "app-secret",
       []string{"https://my-app.example.com/callback"},
       func(id string) string {
           return "/login?authRequestID=" + id
       },
   ))
   ```

2. **Configure the app** to use OIDC with the Bridge's discovery URL:
   ```
   https://bridge.example.com/.well-known/openid-configuration
   ```

3. **Use Authorization Code Grant** — the Bridge supports `response_type=code` with PKCE.

---

## Adding Your Identity (tmb + Public Key)

The Bridge needs to map your Cyphr Principal Root (`tmb`) to an identity. For the PoC, this is done in code.

### Step 1: Get Your Thumbprint

1. Load the CyphrMask extension in your browser
2. Click the extension icon to open the popup
3. Your **Principal Root** (thumbprint) is displayed — copy it

### Step 2: Get Your Public Key

The extension stores your P-256 keypair in `chrome.storage.local`. You can extract the public key from the browser console:

```javascript
chrome.storage.local.get(['privateKey'], (result) => {
    // The private key is stored as hex. You'll need to derive the public key.
    // For now, use the popup UI which shows both.
    console.log(result);
});
```

Alternatively, use the Wasm module directly to generate a keypair and get all three values:

```javascript
// In the browser console with the extension loaded
import init, { generate_keypair, compute_thumbprint } from './wasm/cyphr_crypto.js';
await init();
const keys = JSON.parse(generate_keypair());
// keys = { private_key, public_key_x, public_key_y }
const tmb = compute_thumbprint(keys.public_key_x, keys.public_key_y);
```

### Step 3: Register in the Bridge

Edit `bridge/handlers/verify.go`:

```go
var testUsers = map[string]storage.TestUser{
    "cLj8vsYtMBwYkzoFVZHBZo6SNL5hTN0OU1ygWJdBJak": {
        PublicKey: "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...\n-----END PUBLIC KEY-----",
        Email:     "test@example.com",
    },
    "YOUR_THUMBPRINT_HERE": {
        PublicKey: "-----BEGIN PUBLIC KEY-----\nYOUR_PUBLIC_KEY_PEM_HERE\n-----END PUBLIC KEY-----",
        Email:     "you@example.com",
    },
}
```

Rebuild and restart the bridge:

```bash
just build-bridge
just down && just up
```

### Production Path

For production, replace the hardcoded map with a proper database (SQLite, PostgreSQL). The `storage/storage.go` already implements `op.Storage` — you'd add a `Users` table with columns `principal_root`, `public_key_pem`, `email`, and update `HandleVerify` to query instead of map-lookup.

---

## Project Structure

```
├── bridge/                     # Go OIDC provider
│   ├── main.go                 # Server entrypoint, zitadel provider setup
│   ├── go.mod / go.sum         # Go dependencies
│   ├── Dockerfile              # Multi-stage Docker build
│   ├── crypto/
│   │   ├── coz.go              # Coz signature verification (ES256)
│   │   ├── coz_test.go         # Timeliness unit tests
│   │   └── multihash.go        # Multihash digest encoding/parsing
│   ├── handlers/
│   │   ├── challenge.go        # Nonce store with TTL cleanup
│   │   ├── login.go            # Login page handler (receives authRequestID)
│   │   └── verify.go           # Coz verification + OIDC auth completion
│   ├── storage/
│   │   └── storage.go          # op.Storage implementation (zitadel interface)
│   └── templates/
│       └── login.html          # Cyphr login UI
├── cyphrmask/                  # Chromium extension
│   ├── manifest.json           # Manifest V3
│   ├── package.json            # NPM dependencies
│   ├── tsconfig.json           # TypeScript config
│   ├── assets/                 # Extension icons
│   ├── src/
│   │   ├── background.js       # Wasm loader + signature request handler
│   │   ├── content.js          # Bridge page injection
│   │   ├── popup/              # React popup UI
│   │   └── wasm/               # Generated by wasm-pack (not committed)
│   └── wasm-crypto/            # Rust Wasm module
│       ├── Cargo.toml
│       └── src/lib.rs          # sign_action, compute_thumbprint, generate_keypair
├── docker-compose.yml          # Local dev stack
├── justfile                    # Task runner
├── .env.example                # Environment variables
└── docs/
    └── PLAN.md                 # Original technical specification
```

## Tasks

| Command | Description |
|---------|-------------|
| `just build` | Build Bridge + Wasm module |
| `just build-bridge` | Compile Go binary |
| `just build-wasm` | Compile Rust Wasm → JS bundle |
| `just test` | Run all tests (Go + Rust) |
| `just fmt` | Format Go code with gofumpt |
| `just lint` | Run `go vet` |
| `just up` | Start Docker stack |
| `just down` | Stop Docker stack + remove volumes |
| `just clean` | Remove generated artifacts |

## Configuration

All configuration is via environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `BRIDGE_PORT` | `8080` | HTTP listen port |
| `BRIDGE_ISSUER_URL` | `http://localhost:8080` | OIDC issuer URL (must match the public URL) |
| `BRIDGE_CLIENT_ID` | `cyphrmask-poc` | Default client ID |
| `BRIDGE_CLIENT_SECRET` | `dev-secret-change-me` | Default client secret |
| `BRIDGE_CALLBACK_URL` | `http://localhost:8080/callback` | OAuth2 callback URI |

Copy `.env.example` to `.env` and adjust for your environment.

## Authentication Flow

Here's exactly what happens end-to-end:

1. **User visits a protected app** (e.g., `https://forgejo.example.com`)
2. **App redirects to Bridge** at `/authorize?client_id=forgejo&redirect_uri=...&response_type=code&scope=openid+email+profile`
3. **Bridge renders the Cyphr login page** (`/login?authRequestID=XXX`) — a dark-themed page with a "Sign in with CyphrMask" button
4. **Frontend fetches a challenge nonce** from `/api/challenge`
5. **Content script calls the extension** with `{ action: "REQUEST_SIGNATURE", nonce: "..." }`
6. **CyphrMask popup appears** — user clicks "Approve"
7. **Wasm module constructs and signs** the Coz payload (ES256 + SHA-256, deterministic JSON ordering)
8. **Frontend POSTs the Coz string** to `/api/verify?authRequestID=XXX`
9. **Bridge verifies**: timeliness check → nonce match → signature verification → thumbprint lookup
10. **Bridge marks the auth request as done** and redirects to zitadel's callback (`/login/callback?id=XXX`)
11. **zitadel issues an auth code** and redirects back to the app's `redirect_uri` with `?code=YYY`
12. **App exchanges the code** at `/oauth/token` for a JWT
13. **User is authenticated** — the app creates a session

## Security Notes

This is a **proof-of-concept**. Do not deploy to production without:

- Replacing hardcoded test users with a proper database
- Using real RSA/ECDSA signing keys (currently generated at startup, lost on restart)
- Adding HTTPS / TLS
- Implementing proper session management
- Adding rate limiting and abuse prevention
- Auditing the Coz verification logic against the latest Cyphr protocol specification
