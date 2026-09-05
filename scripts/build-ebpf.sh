#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${1:-$ROOT/dist/bpf/fluxvm_tc.bpf.o}"
ARCH="${FLUXVM_BPF_ARCH:-x86}"
MULTIARCH="$(gcc -dumpmachine)"

mkdir -p "$(dirname "$OUT")"

clang \
  -O2 -g -target bpf \
  -D"__TARGET_ARCH_${ARCH}" \
  -I/usr/include \
  -I"/usr/include/${MULTIARCH}" \
  -Wall -Werror \
  -c "$ROOT/bpf/fluxvm_tc.bpf.c" \
  -o "$OUT"

echo "built $OUT"
