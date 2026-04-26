# Day 2 — 2026-04-26 — PLAN

## Current Status (as of 2026-04-26)

**End-to-end flow works.** Forgejo → Bridge → CyphrMask extension → Coz verification → OIDC token → Forgejo user creation. Repo is public at https://github.com/ic4-y/cyphr-OIDC. Testing infrastructure added (PR #6 — 127 tests, 40.5% Go coverage) but CI is failing.

### Completed

| # | Task | Status |
|---|------|--------|
| 1 | Fix Wasm service worker init (`chrome.runtime.getURL()`) | Done |
| 2 | End-to-end challenge → sign → verify (curl/PoC client) | Done |
| 2a–2f | Challenge endpoint, signing, verification, debugging | Done |
| 3a–3d | MV3 CSP (`'wasm-unsafe-eval'`) | Done |
| – | Login page → extension messaging (`postMessage` bridge) | Done |
| – | Signature verification encoding (proper `json.Unmarshal`) | Done |
| – | Chrome MV3 popup file-input crash → options page | Done |
| – | OIDC callback flow (custom `CallbackHandler`) | Done |
| – | Rust double-hash bug (`signing_key.sign(data)`) | Done |
| – | Empty public key from `.env` (JSON struct tags) | Done |
| 3.0a–d | OIDC claim fixes (sub=thumbprint, proper userinfo, ID token claims, `findEmailBySubject`) | Done |
| 3.1 | Forgejo + forgejo-init in docker-compose (SQLite, auto-config) | Done |
| 3.2 | Bridge config (`BRIDGE_CLIENTS`, `BRIDGE_USERS`, issuer URL) | Done |
| 3.3 | End-to-end test with Forgejo (working) | Done |
| – | Forgejo reserved username fix (`admin` → `forgejo-admin`) | Done |
| – | Forgejo redirect URI case fix (`CyphrMask` not `cyphrmask`) | Done |
| – | Host firewall + host-network bridge for container-to-host token exchange | Done |
| – | Go unit tests (crypto, handlers, storage) | Done (46 tests) |
| – | Go e2e tests (challenge → sign → verify) | Done (6 tests) |
| – | Rust tests (signing, thumbprint, keypair) | Done (13 tests) |
| – | Extension tests (Vitest, mocks) | Done (17 tests) |
| – | CI workflow (GitHub Actions) | Done |
| – | `justfile` test recipes | Done |

### Remaining from original plan

| # | Task | Priority |
|---|------|----------|
| 3 | Bridge TLS / Caddy reverse proxy | Low (production only) |
| 4 | User management / database | Low (env var OK for PoC) |

### Remaining from testing work

| # | Gap | Status |
|---|-----|--------|
| T1 | **CI failing** — missing `go.sum` entries | Fix needed: `go mod tidy` committed |
| T2 | **CI failing** — Node.js 20 deprecation in GitHub Actions | Fix needed: add `FORCE_JAVASCRIPT_ACTIONS_TO_NODE24=true` or update actions |
| T3 | **No browser-level e2e** — extension popup, content.js bridge, and full OIDC redirect flow with Forgejo untested in a real browser | Requires Playwright/Puppeteer setup |
| T4 | **Extension tests test mocks, not real code** — `background.test.js` tests a mock re-implementation of the message handler; `content.test.js` tests inline duplicated logic from `content.js`. Any drift between mock and production code goes undetected. | Deferred — issues [ic4-y/cyphr-OIDC#4](https://github.com/ic4-y/cyphr-OIDC/issues/4) and [#5](https://github.com/ic4-y/cyphr-OIDC/issues/5) |
| T5 | **`login.go` untested** — template rendering and authRequestID lookup | Low value (template-dependent, tested at e2e level when T3 is done) |
| T6 | **~20 storage OIDC lifecycle methods untested** — token creation/refresh, userinfo, signing keys. These are called by zitadel/oidc's `op.NewOpenIDProvider` at runtime, not directly invocable. | Low value — would require full OIDC provider integration tests |
| T7 | **`main.go` wiring untested** — `loadConfig`, `registerClients` | Acceptable — `main()` is rarely unit-tested; wiring is validated by e2e |

---

## Notes for Future Work

### Network topology

The bridge runs with `network_mode: host` so port 8080 is directly on the host. Forgejo uses `extra_hosts: ["localhost:host-gateway"]` to resolve `localhost` to the Docker host gateway for OIDC token exchange. This requires the host firewall to allow container-to-host traffic on port 8080:

```bash
sudo iptables -I INPUT -p tcp --dport 8080 -j ACCEPT
```

### Forgejo admin credentials

- Username: `forgejo-admin` (not `admin` — reserved)
- Password: `admin123`

### Known limitations (PoC)

- Single `iptables` rule needed for container-to-host communication
- Bridge runs on host network (no container isolation)
- `BRIDGE_USERS` is env-var based — no runtime user management
- No HTTPS / TLS — HTTP only with `op.WithAllowInsecure()`
- No extension unlock PIN — anyone with browser access can approve challenges

### CI failures (PR #6)

Two independent issues:

1. **Missing go.sum**: Dependencies pulled in by new test files (`storage/testing.go`, `handlers/callback_test.go`, `handlers/token_callback_test.go`) were not committed to `go.sum`. GitHub Actions reports: `missing go.sum entry for module providing package github.com/zitadel/logging`. Fix: `go mod tidy` and commit the result.

2. **Node.js 20 deprecation**: GitHub Actions runtime is migrating from Node.js 20 to Node.js 24. `actions/checkout@v4` and `actions/setup-go@v5` are running on the deprecated Node.js 20 runtime. The warning states: "Actions will be forced to run with Node.js 24 by default starting June 2nd, 2026." Fix: either add `FORCE_JAVASCRIPT_ACTIONS_TO_NODE24=true` to the workflow env, or update action versions that support Node.js 24.
