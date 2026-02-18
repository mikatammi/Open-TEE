#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Mika Tammi
#
# Generate code coverage report for Open-TEE using gcov/lcov.
# Usage: bash run_coverage.sh [test_name ...]
set -euo pipefail

GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="${SCRIPT_DIR}/build-coverage"
COV_DIR="${BUILD_DIR}/coverage"

# ── 1. Configure and build with coverage ────────────────────────────────────
echo "==> Configuring with coverage instrumentation..."
cmake -B "${BUILD_DIR}" -G Ninja \
    -DCMAKE_BUILD_TYPE=Debug \
    -DOPENTEE_ENABLE_COVERAGE=ON \
    "${SCRIPT_DIR}"

echo "==> Building..."
cmake --build "${BUILD_DIR}"

# ── 2. Clean stale .gcda files ───────────────────────────────────────────────
echo "==> Cleaning stale coverage data..."
find "${BUILD_DIR}" -name '*.gcda' -delete

# ── 3. Write opentee.conf for the coverage build ─────────────────────────────
COV_CONF="${BUILD_DIR}/opentee.conf.coverage"
cat > "${COV_CONF}" <<EOF
# Coverage build configuration
[PATHS]
ta_dir_path = ${BUILD_DIR}/TAs
core_lib_path = ${BUILD_DIR}/lib
opentee_bin = ${BUILD_DIR}/bin/opentee-engine
subprocess_manager = libManagerApi.so
subprocess_launcher = libLauncherApi.so
EOF

# ── 4. Start opentee-engine ──────────────────────────────────────────────────
echo "==> Starting opentee-engine..."
rm -f /tmp/open_tee_sock
"${BUILD_DIR}/bin/opentee-engine" -f -c "${COV_CONF}" &
OPENTEE_PID="$!"
trap 'kill "${OPENTEE_PID}" 2>/dev/null || true; wait "${OPENTEE_PID}" 2>/dev/null || true' EXIT

wait_for_sock() {
    local retries=20
    while [ $retries -gt 0 ]; do
        [ -S /tmp/open_tee_sock ] && return 0
        echo "   Waiting for Open-TEE socket..."
        sleep 1
        retries=$((retries - 1))
    done
    echo "ERROR: Open-TEE socket did not appear" >&2
    kill "${OPENTEE_PID}" 2>/dev/null || true
    exit 1
}
wait_for_sock

# ── 5. Run tests ─────────────────────────────────────────────────────────────
echo "==> Running tests..."
if [ $# -gt 0 ]; then
    TESTS=("$@")
else
    TESTS=(conn_test example_sha1 pkcs11_test property_test_ca sign_tee_ecdsa_256 svc_test)
fi
TEST_FAIL=0
for t in "${TESTS[@]}"; do
    echo "--- Running ${t}..."
    if "${BUILD_DIR}/bin/${t}"; then
        echo -e "    ${t}: ${GREEN}OK${NC}"
    else
        echo -e "    ${t}: ${RED}FAILED (exit $?)${NC}"
        TEST_FAIL=1
    fi
done

# ── 6. Shut down engine gracefully so TA processes can flush gcov data ────────
echo "==> Sending SIGTERM to opentee-engine (pid ${OPENTEE_PID})..."
kill -TERM "${OPENTEE_PID}" 2>/dev/null || true
sleep 3   # Give TA child processes time to flush .gcda files
wait "${OPENTEE_PID}" 2>/dev/null || true
trap - EXIT

# ── 7. Collect coverage data with lcov ───────────────────────────────────────
mkdir -p "${COV_DIR}"

echo "==> Collecting coverage data..."
lcov \
    --capture \
    --directory "${BUILD_DIR}" \
    --output-file "${COV_DIR}/coverage.info" \
    --ignore-errors mismatch,empty \
    --rc branch_coverage=1 2>/dev/null || \
lcov \
    --capture \
    --directory "${BUILD_DIR}" \
    --output-file "${COV_DIR}/coverage.info" \
    --rc branch_coverage=1

# ── 8. Full HTML report ───────────────────────────────────────────────────────
echo "==> Generating full HTML report..."
mkdir -p "${COV_DIR}/html-full"
genhtml \
    "${COV_DIR}/coverage.info" \
    --output-directory "${COV_DIR}/html-full" \
    --branch-coverage \
    --ignore-errors inconsistent,corrupt \
    --title "Open-TEE full coverage" \
    --quiet

echo ""
echo "==> Per-file coverage summary:"
lcov --list "${COV_DIR}/coverage.info"

echo ""
echo "==> Full report: ${COV_DIR}/html-full/index.html"
echo "Done."
