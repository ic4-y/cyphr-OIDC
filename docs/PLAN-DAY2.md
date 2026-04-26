# Day 2 — 2026-04-26 — PLAN

## Current Status (as of 2026-04-26)

**All tasks completed.** The end-to-end flow works: Forgejo → Bridge → CyphrMask extension → Coz verification → OIDC token → Forgejo user creation. Repo is public at https://github.com/ic4-y/cyphr-OIDC.

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

### Remaining from original plan

| # | Task | Priority |
|---|------|----------|
| 3 | Bridge TLS / Caddy reverse proxy | Low (production only) |
| 4 | User management / database | Low (env var OK for PoC) |

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
