{
  description = "Nix development shell for CyphrMask OIDC PoC";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    fenix = {
      url = "github:nix-community/fenix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, fenix }:
    let
      system = "x86_64-linux";

      pkgs = import nixpkgs {
        inherit system;
        config.allowUnfree = true;
      };

      # Fenix provides Rust toolchains with wasm32 target
      # https://github.com/nix-community/fenix#targets
      rustToolchain = fenix.packages.${system}.combine [
        fenix.packages.${system}.stable.cargo
        fenix.packages.${system}.stable.rustc
        fenix.packages.${system}.stable.rust-src
        fenix.packages.${system}.targets.wasm32-unknown-unknown.stable.rust-std
      ];
    in
    {
      devShells.${system} = {
        default = pkgs.mkShell {
          buildInputs = with pkgs; [
            # Git + hooks
            git
            lefthook
            conform

            # Formatting
            treefmt
            nixpkgs-fmt
            gofumpt

            # Task runner
            just

            # Go toolchain for bridge service
            go
            gopls
            golangci-lint

            # Rust toolchain for wasm-crypto (via fenix)
            rustToolchain

            # Wasm compilation
            wasm-pack
            wasm-bindgen-cli

            # Node.js runtime for CyphrMask extension (TS/React)
            nodejs_22

            # Docker Compose for Authelia + Bridge + Apps network
            docker
            docker-compose

            # Nix tooling & LSP
            nixd
          ];

          shellHook = ''
            export PATH="$PATH:$HOME/go/bin"

            # Set RUST_SRC_PATH for rust-analyzer
            export RUST_SRC_PATH="${fenix.packages.${system}.stable.rust-src}/lib/rustlib/src/rust/library"

            echo "[cyphrmask-OIDC-poc] Nix dev shell loaded:"
            echo "  - Go toolchain (go, gopls, golangci-lint, gofumpt)"
            echo "  - Rust toolchain (stable + wasm32-unknown-unknown target)"
            echo "  - Wasm tooling (wasm-pack, wasm-bindgen)"
            echo "  - Node.js 22 + corepack (npm/pnpm via corepack enable)"
            echo "  - Docker + docker-compose (Bridge + Redis stack)"
            echo "  - Nix tooling (nixpkgs-fmt, nixd)"
            echo "  - Git hooks + commit linting (lefthook, conform)"
          '';
        };
      };
    };
}
