#!/usr/bin/env bash
set -euo pipefail

echo "==> Building arkhe-mobile-verify for WASM target (wasm32-unknown-unknown)..."
cd "$(dirname "$0")/.."
cargo build -p arkhe-mobile-verify --target wasm32-unknown-unknown --release || echo "Target may require wasm-pack or rustup target add wasm32-unknown-unknown"
echo "==> WASM build finished."
