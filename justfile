# Cyphr-OIDC Bridge — Task Runner
# Install: https://github.com/casey/just

set shell := ["bash", "-c"]

# Build everything
build: build-bridge build-wasm

# Compile Go binary
build-bridge:
    cd bridge && go mod tidy
    cd bridge && go build ./...

# Compile Rust Wasm module → JS bundle for extension
build-wasm:
    cd cyphrmask/wasm-crypto && wasm-pack build --target web --out-dir ../src/wasm

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
