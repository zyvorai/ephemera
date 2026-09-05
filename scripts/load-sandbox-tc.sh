#!/usr/bin/env bash
# Copyright 2026 Zyvor
# SPDX-License-Identifier: Apache-2.0
#
# Stub TC hook for FluxVM sandbox dataplane. Called by fluxvm-network when
# a sandbox nftables policy is applied. Replace with a real clsact/bpf program
# when you have one compiled for your kernel.
#
# Usage: load-sandbox-tc.sh <sandbox-uuid>

set -euo pipefail

ID="${1:?sandbox uuid required}"

if ! command -v tc >/dev/null 2>&1; then
  echo "tc not installed — skipping TC attach for sandbox ${ID}" >&2
  exit 0
fi

# Best-effort: log intent; operators can extend this script to attach bpf to
# the TAP device for sandbox ${ID} once they know the interface name.
echo "fluxvm: TC stub for sandbox ${ID} (no program loaded — extend this script)" >&2
exit 0
