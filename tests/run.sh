#!/usr/bin/env bash
# Repository unit, configuration and cross-file contract tests.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
TEST_TMP="$(mktemp -d)"
trap 'rm -rf "${TEST_TMP}"' EXIT

# shellcheck disable=SC1091
source "${ROOT}/tests/test-lib.sh"
# shellcheck disable=SC1091
source "${ROOT}/tests/scripts.sh"
# shellcheck disable=SC1091
source "${ROOT}/tests/configs.sh"
# shellcheck disable=SC1091
source "${ROOT}/tests/contracts.sh"

echo
if [ "${fails}" -gt 0 ]; then
  echo "${fails} test(s) failed; ${skips} skipped"
  exit 1
fi
echo "all tests passed; ${skips} skipped"
