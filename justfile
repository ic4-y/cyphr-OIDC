# Cyphr-OIDC Bridge — Task Runner
# Install: https://github.com/casey/just

set shell := ["bash", "-c"]
set dotenv-load

# Compile Go binary
build-bridge:
    cd bridge && go mod tidy
    cd bridge && go build ./...

# Compile Rust Wasm module → JS bundle for extension
build-wasm:
    cd cyphrmask/wasm-crypto && wasm-pack build --target web --out-dir ../src/wasm

# Build extension popup (React → JS, output to cyphrmask/dist/)
build-popup:
    cd cyphrmask && npm install
    cd cyphrmask && npx vite build

# Build everything
build: build-bridge build-wasm build-popup

# Run all tests (Go + Rust + Extension)
test: test-go test-rust test-extension

# Run Go tests (unit + integration + e2e)
test-go:
    cd bridge && go test ./... -v

# Run Go unit tests only
test-go-unit:
    cd bridge && go test ./crypto/... ./handlers/... -v

# Run Go e2e tests only
test-go-e2e:
    cd bridge && go test ./e2e/... -v

# Run Rust tests
test-rust:
    cd cyphrmask/wasm-crypto && cargo test

# Run extension tests
test-extension:
    cd cyphrmask && npm test

# Run extension tests in watch mode
test-extension-watch:
    cd cyphrmask && npm run test:watch

# Format Go code
fmt:
    gofumpt -w bridge/

# Lint Go code
lint:
    cd bridge && go vet ./...

# Run bridge locally for dev testing
run:
    mkdir -p bridge/.keys
    cd bridge && go run ./...

# Start local dev stack
up:
    docker compose up -d

# Stop and remove all containers + volumes
down:
    docker compose down -v

# Clean generated artifacts
clean:
    rm -rf cyphrmask/src/wasm/
    rm -rf cyphrmask/node_modules/
    rm -rf cyphrmask/wasm-crypto/target/
    cd bridge && go clean
