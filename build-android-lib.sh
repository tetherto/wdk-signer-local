#!/usr/bin/env bash

set -euo pipefail
set -x

export ANDROID_SDK_ROOT="${ANDROID_SDK_ROOT:-$HOME/Library/Android/sdk}"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
pushd "${ROOT_DIR}"/android-lib
./gradlew clean copyAarToNpmAndroid
echo "✅ AAR ready at: ${ROOT_DIR}/libs/android/bare-signer-android.aar"
popd
