#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"

echo "Building IronRDP WASM module..."
cargo build --target wasm32-wasip1 --release

WASM_FILE="target/wasm32-wasip1/release/ironrdp_wasm.wasm"

if [ ! -f "$WASM_FILE" ]; then
    echo "ERROR: WASM binary not found at $WASM_FILE"
    exit 1
fi

# Optimize the WASM binary for size (optional, may fail on some WASM features)
if command -v wasm-opt &> /dev/null; then
    echo "Optimizing with wasm-opt..."
    if wasm-opt -Oz --enable-bulk-memory --enable-nontrapping-float-to-int "$WASM_FILE" -o "${WASM_FILE%.wasm}.opt.wasm" 2>/dev/null; then
        mv "${WASM_FILE%.wasm}.opt.wasm" "$WASM_FILE"
        echo "wasm-opt optimization applied."
    else
        echo "wasm-opt optimization skipped (unsupported features in binary)."
    fi
fi

# Copy to Go embed location
cp "$WASM_FILE" ../ironrdp.wasm
echo "WASM binary: $(wc -c < ../ironrdp.wasm | tr -d ' ') bytes"
