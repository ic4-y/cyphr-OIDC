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

# Run all tests
test:
    cd bridge && go test ./...
    cd cyphrmask/wasm-crypto && cargo test

# Format Go code
fmt:
    gofumpt -w bridge/

# Lint Go code
lint:
    cd bridge && go vet ./...

# Run bridge locally for dev testing
run:
    mkdir -p .keys
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
