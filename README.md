# Cyphr-OIDC Bridge

A proof-of-concept that bridges the **Cyphr protocol** (self-sovereign identity with Coz bit-perfect JSON signing) to **standard OpenID Connect**. Any OIDC-capable application — Forgejo, Grafana, Nextcloud, Gitea — can authenticate users via CyphrMask, a Chromium extension that holds the user's cryptographic identity.

No fork, no patch, no protocol changes to downstream apps. They just see a standard OIDC provider.

> **New to Cyphr?** Read the [introduction post](https://blog.cyphr.me/posts/introducing-cyphr.html) or the full [protocol documentation](https://docs.cyphr.me/).

---

## Quick Start

### From Scratch (5 minutes)

```bash
# 0. Allow container-to-host traffic on port 8080
sudo iptables -I INPUT -p tcp --dport 8080 -j ACCEPT
# To remove later: sudo iptables -D INPUT -p tcp --dport 8080 -j ACCEPT

# 1. Enter the dev shell (NixOS)
nix develop

# 2. Build everything
just build

# 3. Start the full stack (bridge + redis + forgejo)
just up

# 4. Verify it's running
curl http://localhost:8080/.well-known/openid-configuration
curl http://localhost:8080/health
curl http://localhost:3000
```

The bridge runs directly on the host network (`:8080`). Forgejo uses `extra_hosts` to resolve `localhost` to the Docker host gateway, so the OIDC token exchange works from inside the container. Forgejo is available at `http://localhost:3000` with an admin user (`forgejo-admin`/`admin123`) and the CyphrMask OIDC auth source pre-registered. Open `http://localhost:3000/user/login` and click **Sign in with CyphrMask** to test.

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

### Installing the CyphrMask Extension

The extension is built with Vite (React popup) and wasm-pack (Rust crypto). After building, load the `cyphrmask/dist/` directory as an unpacked extension.

```bash
# 1. Build the Wasm module
just build-wasm

# 2. Build the extension popup
just build-popup
```

Then in your Chromium browser (Chrome, Brave, Edge):

1. Navigate to `chrome://extensions` (or `brave://extensions` / `edge://extensions`)
2. Enable **Developer mode** (toggle in the top-right corner)
3. Click **Load unpacked**
4. Select the `cyphrmask/dist/` directory (not `cyphrmask/`)
5. The CyphrMask icon appears in your toolbar

On first use:
- Click the extension icon
- Click **Generate New Key** (or import an existing key/backup file)
- Switch to the **Settings** tab to copy your Principal Root (`tmb`) and public keys for registering with the Bridge

For production deployments, remove `http://localhost:8080/*` from `host_permissions` and `content_scripts` in `manifest.json` — the `https://*/*` pattern covers any HTTPS bridge.

---

## Architecture

```
┌──────────────────┐     ┌──────────────────┐     ┌──────────────────┐
│   Downstream     │     │  Cyphr-OIDC      │     │   CyphrMask      │
│   Application    │────▶│     Bridge       │◀───▶│  (Chromium Ext)  │
│  (Forgejo, etc.) │     │  (Go + zitadel)  │     │  (TS + Rust/Wasm)│
└──────────────────┘     └──────────────────┘     └──────────────────┘
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

Forgejo supports OpenID Connect authentication natively. The `docker-compose.yml` includes a pre-configured Forgejo instance with SQLite — no external database required.

### Automated Setup (PoC)

`just up` starts Forgejo with:
- SQLite database (no Postgres/MySQL)
- Admin user: `forgejo-admin` / `admin123`
- CyphrMask OIDC auth source pre-registered via `forgejo admin auth add-oauth`

Just open `http://localhost:3000/user/login` and click **Sign in with CyphrMask**.

### Manual Setup (Production)

For production deployments, register the Bridge as an OIDC client:

In `bridge/main.go`, add Forgejo as an OIDC client:

```go
oidcStore.RegisterClient(storage.NewClient(
    "forgejo",                         // client_id
    "forgejo-secret",                  // client_secret (save this!)
    []string{"https://forgejo.example.com/user/oauth2/CyphrMask/callback"},
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

Any OIDC-capable application can use the Bridge. Register clients via the `BRIDGE_CLIENTS` environment variable:

```bash
BRIDGE_CLIENTS='[{"id":"forgejo","secret":"forgejo-secret","redirect_uris":["https://forgejo.example/user/oauth2/CyphrMask/callback"]}]'
```

Or in `docker-compose.yml`:

```yaml
environment:
  - BRIDGE_CLIENTS=[{"id":"forgejo","secret":"forgejo-secret","redirect_uris":["https://forgejo.example/user/oauth2/CyphrMask/callback"]}]
```

To register multiple clients:

```json
[
  {"id":"forgejo","secret":"forgejo-secret","redirect_uris":["https://forgejo.example/user/oauth2/CyphrMask/callback"]},
  {"id":"grafana","secret":"grafana-secret","redirect_uris":["https://grafana.example/login/generic_oauth"]}
]
```

When `BRIDGE_CLIENTS` is set, it replaces the default client (`BRIDGE_CLIENT_ID`). When unset, the single default client is registered from `BRIDGE_CLIENT_ID`, `BRIDGE_CLIENT_SECRET`, and `BRIDGE_CALLBACK_URL`.

Then configure your app to use OIDC with the Bridge's discovery URL:

```
https://bridge.example.com/.well-known/openid-configuration
```

The Bridge supports the Authorization Code Grant with `response_type=code` and PKCE.

---

## Managing Your Cyphr Identity

Your identity is your P-256 keypair. The CyphrMask popup has a **Settings** tab that handles everything.

### First Setup

1. Load the CyphrMask extension in your browser
2. Click the extension icon
3. Click **Generate New Key** (or import an existing key/backup)
4. Switch to the **Settings** tab to view your Principal Root and public keys

### Export Your Identity

In the Settings tab, click **Export Identity Backup**. This downloads a JSON file:

```json
{
  "principal_root": "cLj8vsYt...",
  "public_key_x": "...",
  "public_key_y": "...",
  "private_key": "...",
  "algorithm": "P-256",
  "format": "cyphr-backup-v1"
}
```

⚠️ **Anyone with this file can impersonate you.** Keep it secure.

### Import Your Identity

In the Settings tab, either:
- **Paste a private key** — enter the 64-character hex-encoded private key
- **Import a backup file** — upload the JSON file from export

The extension validates the key format before accepting it.

---

## Adding Your Identity to the Bridge

The Bridge needs to map your Principal Root (`tmb`) to an identity (email + public key).

### Option 1: Environment Variable (recommended for testing)

Copy your `tmb` and public key from the extension's Settings tab, then set:

```bash
BRIDGE_USERS='{"cLj8vsYt...":{"email":"you@example.com","public_key":"-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----"}}'
```

Or add to `docker-compose.yml`:

```yaml
environment:
  - BRIDGE_USERS={"<your-tmb>":{"email":"you@example.com","public_key":"..."}}
```

### Option 2: Hardcoded in Code

Edit `bridge/handlers/verify.go` and add to the `testUsers` map:

```go
var testUsers = map[string]storage.TestUser{
    "YOUR_THUMBPRINT_HERE": {
        PublicKey: "-----BEGIN PUBLIC KEY-----\nYOUR_PUBLIC_KEY_PEM\n-----END PUBLIC KEY-----",
        Email:     "you@example.com",
    },
}
```

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
│       └── src/lib.rs          # sign_action, compute_thumbprint, generate_keypair, derive_public_key
├── docker-compose.yml          # Local dev stack
├── justfile                    # Task runner
├── .env.example                # Environment variables
└── docs/
    └── PLAN.md                 # Original technical specification
```

## Tasks

| Command | Description |
|---------|-------------|
| `just build` | Build Bridge + Wasm module + extension popup |
| `just build-bridge` | Compile Go binary |
| `just build-wasm` | Compile Rust Wasm → JS bundle |
| `just build-popup` | Build extension popup (React → JS via Vite) |
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
| `BRIDGE_SIGNING_KEY_PATH` | _(empty)_ | Path to RSA signing key PEM file. If the file doesn't exist, a new key is generated and saved there. Persists across restarts. |
| `BRIDGE_USERS` | _(empty)_ | JSON map of thumbprint → `{email, public_key}`. Overrides the default test user. |
| `BRIDGE_CLIENTS` | _(empty)_ | JSON array of `{"id","secret","redirect_uris"}`. When set, replaces the default client. |

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

- Replacing `BRIDGE_USERS` env var with a proper database
- Restricting signing key file permissions (currently 0600, good for PoC)
- Adding HTTPS / TLS
- Implementing proper session management
- Adding rate limiting and abuse prevention
- Auditing the Coz verification logic against the latest Cyphr protocol specification
