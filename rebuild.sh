#!/usr/bin/env bash

set -euo pipefail
set -x

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${ROOT_DIR}"

export ANDROID_HOME=${ANDROID_HOME:-${HOME}/Library/Android/sdk}

# 2. Original build() helper
build() {
    local platform=$1
    local arch=$2
    local simulator=${3:-}
    local build_dir="${ROOT_DIR}/build/build-${platform}-${arch}${simulator:+-simulator}"

    rm -fr "${build_dir}"

    local generate_cmd="npx bare-make generate --platform ${platform} --arch ${arch}"
    if [ -n "${simulator}" ]; then
        generate_cmd="${generate_cmd} --simulator"
    fi
    generate_cmd="${generate_cmd} -b ${build_dir}"

    ${generate_cmd}
    npx bare-make build -b "${build_dir}"
    npx bare-make install --link -b "${build_dir}"
}

# 3. Cleanup
rm -fr "${ROOT_DIR}/build" "${ROOT_DIR}/prebuilds"
mkdir -p "${ROOT_DIR}/build"

pids=()

# 4. Android builds
build android arm64 &
pids+=($!)
build android arm &
pids+=($!)
build android ia32 &
pids+=($!)
build android x64 &
pids+=($!)

# 5. iOS builds
build ios arm64 &
pids+=($!)
build ios arm64 yes &
pids+=($!)

# 6. Darwin build
build darwin arm64 &
pids+=($!)

failed=0
for pid in "${pids[@]}"; do
    if ! wait "$pid"; then
        failed=1
    fi
done

if [ $failed -ne 0 ]; then
    echo "One or more builds failed"
    exit 1
fi
