#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${ROOT_DIR}"

BUILD_DIR="${ROOT_DIR}/build/build-darwin-arm64"

npx bare-make generate --platform darwin --arch arm64 -b "${BUILD_DIR}"

ln -sf "${BUILD_DIR}/compile_commands.json" "${ROOT_DIR}/compile_commands.json"

echo "Symlinked compile_commands.json -> build/build-darwin-arm64/compile_commands.json"
