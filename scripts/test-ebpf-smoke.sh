#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "run as root (sudo -E $0)" >&2
  exit 2
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OBJ_DIR="${1:-$ROOT/dist/bpf}"
TC_OBJ="$OBJ_DIR/fluxvm_tc.bpf.o"
XDP_OBJ="$OBJ_DIR/fluxvm_xdp.bpf.o"

for cmd in bpftool tc ip mountpoint python3 ping; do
  command -v "$cmd" >/dev/null || { echo "missing $cmd" >&2; exit 2; }
done
[[ -f "$TC_OBJ" ]] || { echo "missing $TC_OBJ" >&2; exit 2; }
[[ -f "$XDP_OBJ" ]] || { echo "missing $XDP_OBJ" >&2; exit 2; }

mountpoint -q /sys/fs/bpf || mount -t bpf bpf /sys/fs/bpf

SUFFIX="$$"
A="fvmta${SUFFIX}"
B="fvmtb${SUFFIX}"
A="${A:0:15}"
B="${B:0:15}"
PIN="/sys/fs/bpf/fluxvm-smoke-${SUFFIX}"
TC_PREF=49152
IDENTITY=42
A_IP="10.77.0.1"
B_IP="10.77.0.2"

cleanup() {
  ip link set dev "$A" xdp off 2>/dev/null || true
  tc filter del dev "$A" ingress pref "$TC_PREF" handle 1 bpf 2>/dev/null || true
  tc qdisc del dev "$A" clsact 2>/dev/null || true
  ip link del "$A" 2>/dev/null || true
  rm -rf "$PIN" 2>/dev/null || true
}
trap cleanup EXIT
cleanup

hex_u32() {
  python3 - "$1" <<'PY'
import struct, sys
print(" ".join(f"{b:02x}" for b in struct.pack("=I", int(sys.argv[1]))))
PY
}

iface_value() {
  # identity, default_allow, enforce_cidr, enforce_l4, sample_rate
  python3 - "$@" <<'PY'
import struct, sys
vals = [int(x) for x in sys.argv[1:]]
print(" ".join(f"{b:02x}" for b in struct.pack("=IIIII", *vals)))
PY
}

lpm_key() {
  # prefixlen, identity, IPv4 bytes
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
  ping -q -c 1 -W 1 -I "$B" "$A_IP" >/dev/null
}

expect_no_ping() {
  if ping -q -c 1 -W 1 -I "$B" "$A_IP" >/dev/null; then
    echo "expected ping to be blocked" >&2
    exit 1
  fi
}

ip link add "$A" type veth peer name "$B"
ip addr add "$A_IP/24" dev "$A"
ip addr add "$B_IP/24" dev "$B"
ip link set "$A" up
ip link set "$B" up
mkdir -p "$PIN/tc/progs" "$PIN/tc/maps" "$PIN/xdp/progs" "$PIN/xdp/maps"

# ---------------------------------------------------------------------------
# TC verifier/load + real policy behavior
# ---------------------------------------------------------------------------
bpftool prog load "$TC_OBJ" "$PIN/tc/progs/fluxvm_egress" \
  type classifier pinmaps "$PIN/tc/maps"
tc qdisc add dev "$A" clsact
tc filter add dev "$A" ingress pref "$TC_PREF" handle 1 bpf da \
  pinned "$PIN/tc/progs/fluxvm_egress"
tc filter show dev "$A" ingress | grep -q 'bpf'

IFINDEX="$(cat "/sys/class/net/$A/ifindex")"
IFKEY="$(hex_u32 "$IFINDEX")"

# Default allow: connectivity works.
ALLOW_VALUE="$(iface_value "$IDENTITY" 1 0 0 0)"
# shellcheck disable=SC2086
bpftool map update pinned "$PIN/tc/maps/fluxvm_id" key hex $IFKEY value hex $ALLOW_VALUE
expect_ping

# Default deny with no explicit lists: IPv4 data is blocked (ARP stays allowed).
DENY_VALUE="$(iface_value "$IDENTITY" 0 0 0 0)"
# shellcheck disable=SC2086
bpftool map update pinned "$PIN/tc/maps/fluxvm_id" key hex $IFKEY value hex $DENY_VALUE
expect_no_ping

# LPM allowlist: allow just the destination address and connectivity returns.
CIDR_VALUE="$(iface_value "$IDENTITY" 0 1 0 0)"
# shellcheck disable=SC2086
bpftool map update pinned "$PIN/tc/maps/fluxvm_id" key hex $IFKEY value hex $CIDR_VALUE
LPMKEY="$(lpm_key 64 "$IDENTITY" "$A_IP")"
ONE="$(hex_u32 1)"
# shellcheck disable=SC2086
bpftool map update pinned "$PIN/tc/maps/fluxvm_v4" key hex $LPMKEY value hex $ONE
expect_ping

# The program must have populated both stats and flow maps.
bpftool -j map dump pinned "$PIN/tc/maps/fluxvm_stats" | grep -q 'key'
bpftool -j map dump pinned "$PIN/tc/maps/fluxvm_flows" | grep -q 'key'

# Detach TC before XDP behavior test.
tc filter del dev "$A" ingress pref "$TC_PREF" handle 1 bpf

# ---------------------------------------------------------------------------
# XDP verifier/load + source-CIDR drop behavior
# ---------------------------------------------------------------------------
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

echo "FluxVM TC policy/observability + XDP kernel smoke test passed"
