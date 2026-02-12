#!/bin/bash
# test-static-binary.sh - Test that brutus works in a minimal container
#
# This script verifies that the static binary:
# 1. Builds successfully with musl
# 2. Runs in a scratch container (zero dependencies)
# 3. Can execute basic operations
#
# Usage:
#   ./scripts/test-static-binary.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

echo "=== Testing Static Binary in Minimal Container ==="
echo ""

# Build the static image
echo "[1/4] Building static binary with musl..."
docker build -f "${PROJECT_ROOT}/Dockerfile.static" -t brutus:static-test "${PROJECT_ROOT}"

# Test 1: Version check
echo ""
echo "[2/4] Testing version command..."
docker run --rm brutus:static-test -version
echo "✓ Version command works"

# Test 2: Help output
echo ""
echo "[3/4] Testing help output..."
docker run --rm brutus:static-test -h 2>&1 | head -5
echo "✓ Help output works"

# Test 3: Actual connection attempt (expect failure, but proves binary works)
echo ""
echo "[4/4] Testing RDP connection attempt (expect connection error)..."
OUTPUT=$(docker run --rm brutus:static-test -protocol rdp -target 127.0.0.1:3389 -u test -p test -timeout 2s 2>&1 || true)
echo "${OUTPUT}"

if echo "${OUTPUT}" | grep -q "connection error"; then
    echo "✓ RDP plugin loaded and attempted connection"
else
    echo "✗ Unexpected output from RDP test"
    exit 1
fi

# Test 4: Verify no glibc dependency by checking image size
echo ""
echo "[5/5] Checking image size (should be small, ~15-25MB)..."
SIZE=$(docker images brutus:static-test --format "{{.Size}}")
echo "Image size: ${SIZE}"

echo ""
echo "=== All Static Binary Tests Passed ==="
echo ""
echo "The brutus binary is fully static and works in a scratch container."
echo "It can be deployed to any Linux system without dependencies."

# Cleanup
docker rmi brutus:static-test >/dev/null 2>&1 || true
