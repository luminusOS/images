#!/usr/bin/env bash

fails=0
skips=0

pass() { echo "ok   - $1"; }
fail() {
  echo "FAIL - $1"
  fails=$((fails + 1))
}
skip() {
  echo "skip - $1"
  skips=$((skips + 1))
}

expect() {
  local description="$1" output
  shift
  if output="$("$@" 2>&1)"; then
    pass "${description}"
  else
    fail "${description}"
    if [ -n "${output}" ]; then
      printf '%s\n' "${output}" | sed 's/^/       /'
    fi
  fi
}

expect_failure() {
  local description="$1"
  shift
  if "$@" >/dev/null 2>&1; then fail "${description}"; else pass "${description}"; fi
}

expect_contains() {
  local description="$1" needle="$2" output
  shift 2
  if ! output="$("$@" 2>&1)"; then
    fail "${description}"
    printf '%s\n' "${output}" | sed 's/^/       /'
  elif grep -Fq -- "${needle}" <<<"${output}"; then
    pass "${description}"
  else
    fail "${description}"
    printf '       missing %q in: %s\n' "${needle}" "${output}"
  fi
}
