# FluxVM Network Fabric v1

This change turns the existing `fluxvm-network` eBPF hint into a real,
optional VM-edge dataplane while keeping the existing nftables path as the
backwards-compatible default.

## What is implemented

### VM identity and TC/eBPF policy

Every running FluxVM sandbox with a host-visible TAP/veth can get a native TC
classifier. A deterministic identity is derived from the VM UUID and written
to the per-VM `fluxvm_id` map. Policy does not depend on a stable ifindex.

For a namespaced VM, the attach point is the host side of the namespace veth:

```text
VM virtio-net
   |
  TAP
   |
bridge + dnsmasq        (VM network namespace)
   |
namespace veth
   |
======================= namespace boundary
   |
host veth              <-- FluxVM TC/eBPF ingress hook
   |
host routing / Cilium
   |
physical NIC
```

A direct host TAP/macvtap uses that host-visible device as the attach point.

### L3 + L4 zero-trust allowlists

The native program supports:

- IPv4 destination CIDR allowlists through an LPM trie.
- TCP/UDP destination-port allowlists through a hash map.
- CIDR **and** L4 policy together (both must match).
- deny-by-default with `default_allow = false`.
- ARP and DHCP bootstrap traffic.
- fail-closed handling of fragmented IPv4 packets when L4 policy is enabled.

The nftables fallback implements the same CIDR/L4 policy semantics instead of
silently dropping the L4 portion of policy.

### Per-VM policy API

A VM can override the node defaults at runtime. Policies are persisted below
`<state_dir>/network-policy/<uuid>.json`, re-applied after stop/start, and
removed with the VM.

```http
GET  /v1/vms/<uuid>/network/policy
POST /v1/vms/<uuid>/network/policy
```

Example POST body:

```json
{
  "default_allow": false,
  "allow_cidrs": ["10.20.0.0/16", "192.0.2.25/32"],
  "allow_ports": ["tcp/443", "udp/53"],
  "sample_rate": 100
}
```

If both allow lists are non-empty, a packet must match an allowed destination
CIDR and an allowed destination port. If neither list is set,
`default_allow` decides the action.

### Stats + flow table

The TC program maintains:

- `fluxvm_stats`: per-CPU allow/drop packet and byte counters.
- `fluxvm_flows`: LRU IPv4 5-tuple flow records with verdict, packet count,
  byte count, and last-seen monotonic timestamp.
- `fluxvm_events`: ring buffer for drop events plus sampled allowed events.

REST endpoints:

```http
GET /v1/vms/<uuid>/network/stats
GET /v1/vms/<uuid>/network/flows?limit=100
```

Example stats response:

```json
{
  "allowed_packets": 14502,
  "allowed_bytes": 12884421,
  "dropped_packets": 31,
  "dropped_bytes": 2216
}
```

### Cilium coexistence

Use:

```toml
[sandbox.dataplane]
mode = "cilium"
```

Cilium continues to own Kubernetes/node CNI networking. FluxVM only attaches
the VM-edge classifier and pins state below `/sys/fs/bpf/fluxvm`. FluxVM does
**not** modify Cilium's private maps. The loader reuses an existing `clsact`
qdisc instead of replacing it and uses a reserved high TC priority with `add`
semantics, so it refuses a collision instead of overwriting another filter.

The mode verifies `/var/run/cilium/cilium.sock` and bpffs before attaching.
The Kubernetes DaemonSet patch mounts both into the FluxVM container.

This is coexistence, not yet a claim that a FluxVM VM is a native Cilium
endpoint. A later launcher-pod/CNI integration can add first-class Cilium
identities and Hubble attribution without changing the VM-edge policy API.

### Optional standalone XDP guard

`fluxvm_xdp.bpf.o` provides a node-ingress source-CIDR blocklist before the
normal network stack. It refuses to replace an existing XDP program. FluxVM
records the pinned program ID and only detaches XDP when the interface still
reports that exact ID; if another agent replaced it, FluxVM leaves the new
program untouched.

It is intentionally rejected in `mode = "cilium"` because Cilium may already
own XDP on physical interfaces for acceleration.

Example:

```toml
[sandbox.dataplane.xdp]
enabled = true
interface = "eno1"
required = false
block_cidrs = ["198.51.100.0/24", "203.0.113.66/32"]
```

## Node configuration

Standalone eBPF mode:

```toml
[sandbox.dataplane]
mode = "ebpf"                  # legacy | ebpf | cilium
bpf_object = "/usr/lib/fluxvm/bpf/fluxvm_tc.bpf.o"
pin_root = "/sys/fs/bpf/fluxvm"
required = false               # true => VM creation/start fails if attach fails
default_allow = false
allow_cidrs = ["10.0.0.0/8"]
allow_ports = ["tcp/443", "udp/53"]
sample_rate = 100
```

The default remains `mode = "legacy"`, so existing installations do not start
loading eBPF merely by upgrading FluxVM. Native mode requires a Linux kernel
with ring-buffer BPF maps (5.8+); when `required = false`, an unavailable BPF
feature falls back to nftables rather than blocking VM startup.

## Build

Debian/Ubuntu dependencies:

```bash
sudo apt-get install clang llvm libbpf-dev bpftool iproute2 nftables
./scripts/build-ebpf.sh
sudo install -D -m 0644 dist/bpf/fluxvm_tc.bpf.o \
  /usr/lib/fluxvm/bpf/fluxvm_tc.bpf.o
sudo install -D -m 0644 dist/bpf/fluxvm_xdp.bpf.o \
  /usr/lib/fluxvm/bpf/fluxvm_xdp.bpf.o
```

The Dockerfile patch performs those steps automatically.

## Tests

Normal Rust tests:

```bash
cargo fmt --all -- --check
cargo build --workspace --all-targets
cargo test --workspace
cargo clippy --workspace --all-targets
```

BPF compilation and a real kernel attach smoke test:

```bash
./scripts/build-ebpf.sh
sudo -E ./scripts/test-ebpf-smoke.sh
```

The included `Network Fabric` GitHub Actions workflow runs all of the above on
PRs that touch the networking implementation.

## Deliberately not in v1

These should build on this foundation rather than be mixed into the first
merge:

- eBPF service load balancing / Maglev.
- BGP advertisement of VM IPs.
- WireGuard host-to-host VM encryption.
- Cilium launcher-pod identity integration / Hubble enrichment.
- live-migration transfer of policy + conntrack/NAT state.

The v1 map/API boundaries are designed so those can be added without replacing
the basic identity, policy, stats, or flow model.
