#!/usr/bin/env bash
set -euo pipefail

case "${1:?missing boot mode}" in
  iso) pattern='sirius|start installation|iniciar instala..o' ;;
  disk) pattern='welcome|bem.vindo|initial setup|configura..o inicial|sign in|iniciar sess.o' ;;
  *) echo "Unknown boot mode: $1" >&2; exit 1 ;;
esac
grep -iEq "${pattern}" "${2:?missing OCR output}"
