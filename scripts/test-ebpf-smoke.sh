#!/usr/bin/env bash
# Copyright 2026 Zyvor
# SPDX-License-Identifier: Apache-2.0
#
# Kernel smoke for FluxVM TC/XDP objects. Uses two network namespaces so
# traffic truly crosses the veth (same-netns `ping -I` is unreliable on
# some hosts where the destination is also a local address).
#
# All bpftool/tc/bpffs work runs in a single `ip netns exec` session:
# this host remounts /sys (and does not keep custom mounts) across
# separate `ip netns exec` invocations.
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "run as root (sudo -E $0)" >&2
  exit 2
fi

# BPF map/program loading can otherwise fail on hosts with a small memlock limit.
ulimit -l unlimited 2>/dev/null || true

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OBJ_DIR="${1:-$ROOT/dist/bpf}"
TC_OBJ="$OBJ_DIR/fluxvm_tc.bpf.o"
XDP_OBJ="$OBJ_DIR/fluxvm_xdp.bpf.o"

for cmd in bpftool tc ip mountpoint python3 ping; do
  command -v "$cmd" >/dev/null || { echo "missing $cmd" >&2; exit 2; }
done
[[ -f "$TC_OBJ" ]] || { echo "missing $TC_OBJ" >&2; exit 2; }
[[ -f "$XDP_OBJ" ]] || { echo "missing $XDP_OBJ" >&2; exit 2; }

SUFFIX="$$"
A="fvmta${SUFFIX}"
B="fvmtb${SUFFIX}"
A="${A:0:15}"
B="${B:0:15}"
NSA="fvm-a-${SUFFIX}"
NSB="fvm-b-${SUFFIX}"
BPFFS="/run/fluxvm-smoke-${SUFFIX}"
PIN="$BPFFS/pins"
TC_PREF=49152
IDENTITY=42
A_IP="10.77.0.1"
B_IP="10.77.0.2"

cleanup() {
  ip netns exec "$NSA" ip link set dev "$A" xdp off 2>/dev/null || true
  ip netns exec "$NSA" tc filter del dev "$A" ingress pref "$TC_PREF" handle 1 bpf 2>/dev/null || true
  ip netns exec "$NSA" tc qdisc del dev "$A" clsact 2>/dev/null || true
  ip netns del "$NSA" 2>/dev/null || true
  ip netns del "$NSB" 2>/dev/null || true
  ip link del "$A" 2>/dev/null || true
  rm -rf "$BPFFS" 2>/dev/null || true
}
trap cleanup EXIT
cleanup

ip netns add "$NSA"
ip netns add "$NSB"
ip link add "$A" type veth peer name "$B"
ip link set "$A" netns "$NSA"
ip link set "$B" netns "$NSB"
ip netns exec "$NSA" ip addr add "$A_IP/24" dev "$A"
ip netns exec "$NSB" ip addr add "$B_IP/24" dev "$B"
ip netns exec "$NSA" ip link set lo up
ip netns exec "$NSB" ip link set lo up
ip netns exec "$NSA" ip link set "$A" up
ip netns exec "$NSB" ip link set "$B" up

# Baseline connectivity (no BPF yet).
ip netns exec "$NSB" ping -q -c 1 -W 2 "$A_IP" >/dev/null

# One persistent netns shell so bpffs mounts and pins stay visible.
ip netns exec "$NSA" env \
  TC_OBJ="$TC_OBJ" XDP_OBJ="$XDP_OBJ" \
  A="$A" NSB="$NSB" A_IP="$A_IP" B_IP="$B_IP" \
  PIN="$PIN" BPFFS="$BPFFS" TC_PREF="$TC_PREF" IDENTITY="$IDENTITY" \
  bash -euo pipefail <<'INNER'
hex_u32() {
  python3 - "$1" <<'PY'
import struct, sys
print(" ".join(f"{b:02x}" for b in struct.pack("=I", int(sys.argv[1]))))
PY
}

iface_value() {
  # identity, default_allow, enforce_cidr, enforce_l4, sample_rate,
  # rate_bytes_per_sec, rate_packets_per_sec
  python3 - "$@" <<'PY'
import struct, sys
identity, default_allow, enforce_cidr, enforce_l4, sample_rate, rate_bytes, rate_packets = [int(x) for x in sys.argv[1:]]
raw = struct.pack("=IIIIIIQQ", identity, default_allow, enforce_cidr, enforce_l4, sample_rate, 0, rate_bytes, rate_packets)
print(" ".join(f"{b:02x}" for b in raw))
PY
}

lpm_key() {
  python3 - "$1" "$2" "$3" <<'PY'
import ipaddress, struct, sys
prefix, identity, ip = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3]
raw = struct.pack("=II", prefix, identity) + ipaddress.IPv4Address(ip).packed
print(" ".join(f"{b:02x}" for b in raw))
PY
}

xdp_lpm_key() {
  python3 - "$1" "$2" <<'PY'
import ipaddress, struct, sys
prefix, ip = int(sys.argv[1]), sys.argv[2]
raw = struct.pack("=I", prefix) + ipaddress.IPv4Address(ip).packed
print(" ".join(f"{b:02x}" for b in raw))
PY
}

expect_ping() {
  ip netns exec "$NSB" ping -q -c 1 -W 2 "$A_IP" >/dev/null
}

expect_no_ping() {
  if ip netns exec "$NSB" ping -q -c 1 -W 1 "$A_IP" >/dev/null; then
    echo "expected ping to be blocked" >&2
    exit 1
  fi
}

mkdir -p "$BPFFS"
mount -t bpf bpf "$BPFFS"
mkdir -p "$PIN/tc/progs" "$PIN/tc/maps" "$PIN/xdp/progs" "$PIN/xdp/maps"

bpftool prog load "$TC_OBJ" "$PIN/tc/progs/fluxvm_egress" \
  type classifier pinmaps "$PIN/tc/maps"
tc qdisc add dev "$A" clsact
tc filter add dev "$A" ingress pref "$TC_PREF" handle 1 bpf da \
  pinned "$PIN/tc/progs/fluxvm_egress"
tc filter show dev "$A" ingress | grep -q 'bpf'

IFINDEX="$(cat "/sys/class/net/$A/ifindex")"
IFKEY="$(hex_u32 "$IFINDEX")"

ALLOW_VALUE="$(iface_value "$IDENTITY" 1 0 0 0 0 0)"
# shellcheck disable=SC2086
bpftool map update pinned "$PIN/tc/maps/fluxvm_id" key hex $IFKEY value hex $ALLOW_VALUE
expect_ping

DENY_VALUE="$(iface_value "$IDENTITY" 0 0 0 0 0 0)"
# shellcheck disable=SC2086
bpftool map update pinned "$PIN/tc/maps/fluxvm_id" key hex $IFKEY value hex $DENY_VALUE
expect_no_ping

CIDR_VALUE="$(iface_value "$IDENTITY" 0 1 0 0 0 0)"
# shellcheck disable=SC2086
bpftool map update pinned "$PIN/tc/maps/fluxvm_id" key hex $IFKEY value hex $CIDR_VALUE
LPMKEY="$(lpm_key 64 "$IDENTITY" "$A_IP")"
ONE="$(hex_u32 1)"
# shellcheck disable=SC2086
bpftool map update pinned "$PIN/tc/maps/fluxvm_v4" key hex $LPMKEY value hex $ONE
expect_ping

bpftool -j map dump pinned "$PIN/tc/maps/fluxvm_stats" | grep -q 'key'
bpftool -j map dump pinned "$PIN/tc/maps/fluxvm_flows" | grep -q 'key'

# Fixed-window PPS limiter: first packet passes, a second packet in the same
# one-second window is dropped, then traffic recovers after the window rolls.
IDKEY="$(hex_u32 "$IDENTITY")"
ZERO_RATE_STATE="$(python3 - <<'PY'
print(" ".join(["00"] * 32))
PY
)"
# shellcheck disable=SC2086
bpftool map update pinned "$PIN/tc/maps/fluxvm_rate" key hex $IDKEY value hex $ZERO_RATE_STATE
RATE_VALUE="$(iface_value "$IDENTITY" 1 0 0 0 0 1)"
# shellcheck disable=SC2086
bpftool map update pinned "$PIN/tc/maps/fluxvm_id" key hex $IFKEY value hex $RATE_VALUE
expect_ping
expect_no_ping
sleep 1.1
expect_ping

tc filter del dev "$A" ingress pref "$TC_PREF" handle 1 bpf

bpftool prog load "$XDP_OBJ" "$PIN/xdp/progs/fluxvm_xdp_guard" \
  type xdp pinmaps "$PIN/xdp/maps"
BLOCKKEY="$(xdp_lpm_key 32 "$B_IP")"
# shellcheck disable=SC2086
bpftool map update pinned "$PIN/xdp/maps/fvm_xdp_block4" key hex $BLOCKKEY value hex $ONE
ip link set dev "$A" xdp pinned "$PIN/xdp/progs/fluxvm_xdp_guard"
ip -d link show dev "$A" | grep -q 'xdp'
expect_no_ping
ip link set dev "$A" xdp off
expect_ping
INNER

echo "FluxVM TC policy/rate-limit/observability + XDP kernel smoke test passed"
