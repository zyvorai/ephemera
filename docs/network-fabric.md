# FluxVM Network Fabric v1

This turns the existing `fluxvm-network` eBPF path into a real, optional
VM-edge dataplane while keeping nftables as the backwards-compatible default.

Also see [ebpf-cilium.md](ebpf-cilium.md) for mode details and Cilium coexistence.

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

Detach metadata (iface name) is stored under
`/run/fluxvm/ebpf/vms/<uuid-simple>/` — bpffs cannot hold regular files.
Pins live under `pin_root` (default `/sys/fs/bpf/fluxvm/vms/<uuid-simple>/`).

TC filter uses preference **49152**, handle **1**, program name
`fluxvm_egress`, and `tc filter add` (not replace) so a collision fails closed.

### L3 + L4 zero-trust allowlists

The native program supports:

- IPv4 destination CIDR allowlists through an LPM trie.
- TCP/UDP destination-port allowlists through a hash map (`tcp/443`, `udp/53`).
- Per-VM fixed-window egress **Mbps** and **PPS** ceilings (`max_egress_mbps`,
  `max_egress_pps`) via the `fluxvm_rate` map — native eBPF only; no silent
  nftables fallback when either is set.
- CIDR **and** L4 policy together (both must match when both lists are non-empty).
- deny-by-default with `default_allow = false`.
- ARP and DHCP bootstrap traffic.
- fail-closed handling of fragmented IPv4 packets when L4 policy is enabled.
- `sample_rate`: `0` = off; `N` ≈ 1/N allowed flows emitted on the ring buffer.

The nftables fallback implements the same CIDR/L4 policy semantics instead of
silently dropping the L4 portion of policy.

### Per-VM policy API

A VM can override the node defaults at runtime. Policies are persisted below
`<state_dir>/network-policy/<uuid>.json`, re-applied after stop/start, and
removed with the VM. `POST` requires the **admin** role when auth is enabled;
on apply failure the previous policy is restored.

```http
GET  /v1/vms/<uuid>/network/policy
POST /v1/vms/<uuid>/network/policy
GET  /v1/vms/<uuid>/network/status
```

Example POST body:

```json
{
  "default_allow": false,
  "allow_cidrs": ["10.20.0.0/16", "192.0.2.25/32"],
  "allow_ports": ["tcp/443", "udp/53"],
  "max_egress_mbps": 100,
  "max_egress_pps": 50000,
  "sample_rate": 100
}
```

Live `POST` updates keep the TC program attached and switch the interface to
deny-all while maps are replaced, then publish the final config (fail-closed;
never an allow-all gap). On apply failure the previous policy is restored.

If both allow lists are non-empty, a packet must match an allowed destination
CIDR and an allowed destination port. If neither list is set,
`default_allow` decides the action.

`GET …/network/status` reports mode, whether the TC filter is attached, iface,
identity, pin directory, and effective policy.

### Stats + flow table

The TC program maintains:

- `fluxvm_stats`: per-CPU allow/drop packet and byte counters.
- `fluxvm_flows`: LRU IPv4 5-tuple flow records with verdict, packet count,
  byte count, and last-seen monotonic timestamp.
- `fluxvm_events`: ring buffer for drop events plus sampled allowed events.
- `fluxvm_l4`: destination-port allowlist.

REST endpoints (native `ebpf` / `cilium` modes only; `legacy` returns an error):

```http
GET /v1/vms/<uuid>/network/stats
GET /v1/vms/<uuid>/network/flows?limit=100
```

`limit` defaults to 100 and is capped at 4096.

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
qdisc instead of replacing it and uses reserved TC priority 49152 with `add`
semantics, so it refuses a collision instead of overwriting another filter.

The mode verifies `/var/run/cilium/cilium.sock` and bpffs before attaching.
The Kubernetes DaemonSet mounts both into the FluxVM container.

This is coexistence, not yet a claim that a FluxVM VM is a native Cilium
endpoint. A later launcher-pod/CNI integration can add first-class Cilium
identities and Hubble attribution without changing the VM-edge policy API.

### Optional standalone XDP guard

`fluxvm_xdp.bpf.o` provides a node-ingress source-CIDR blocklist before the
normal network stack. It is initialized once at **daemon startup**
(`VmManager::new`), not per VM.

Ownership / safety:

- Refuses to replace an existing foreign XDP program.
- Records pinned program ID under `/run/fluxvm/xdp/` (`iface`, `prog_id`).
- On teardown, detaches only when the interface still reports that exact ID;
  if another agent replaced it, FluxVM leaves the new program untouched.
- Intentionally rejected in `mode = "cilium"` (Cilium may already own XDP).
- `xdp.enabled = false` (default) is a no-op; `xdp.required = true` fails
  daemon init on attach error.

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
max_egress_mbps = 100          # native only; disables nftables fallback
max_egress_pps = 50000
sample_rate = 100              # 0 = off
```

The default remains `mode = "legacy"`, so upgrades do not start loading eBPF
unless configured. Native mode needs a Linux kernel with ring-buffer BPF maps
(5.8+).

Native attach can run on direct TAP/macvtap **without** a FluxVM-known guest IP;
legacy nftables still needs a guest CIDR. When `required = false`, attach
failures fall back to nftables unless rate limits are configured (those are
native-only and fail closed). In `ebpf`/`cilium` mode, an exhausted fallback
still aborts create/start.

### Memlock / systemd

Loading BPF maps needs raised `RLIMIT_MEMLOCK`. The packaged unit sets
`LimitMEMLOCK=infinity` and `ReadWritePaths` includes `/sys/fs/bpf` and
`/run/fluxvm`. Non-systemd or container runs need the same (or equivalent
capabilities). The DaemonSet grants `SYS_RESOURCE` for this reason.

Tests may override meta roots with `FLUXVM_BPF_META_ROOT`.

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

The Dockerfile builder stage runs these steps automatically.

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
./scripts/validate-network-fabric.sh
FLUXVM_PRIVILEGED_SMOKE=1 ./scripts/validate-network-fabric.sh
# or directly:
sudo -E ./scripts/test-ebpf-smoke.sh
sudo -E ./scripts/test-network-fabric.sh
```

`scripts/test-ebpf-smoke.sh` creates **two network namespaces** and a veth pair
so traffic truly crosses the wire (same-netns `ping -I` is unreliable when the
destination is also a local address). All `bpftool` / `tc` / bpffs work runs in
**one persistent `ip netns exec` session** — on many hosts, separate
`ip netns exec` invocations remount `/sys` and drop custom bpffs mounts under
`/sys/fs/bpf`. The smoke covers TC allow/deny/LPM, **PPS rate limiting**,
stats/flows map dumps, and XDP blocklist attach/detach.

`scripts/test-network-fabric.sh` is the full e2e: unit tests, kernel smoke,
FluxVm create with `tap`+`netns`, TC attach, REST
`policy`/`status`/`stats`/`flows`, live reconfigure with Mbps/PPS, and teardown.

The `Network Fabric` GitHub Actions workflow runs the above on PRs that touch
the networking implementation.

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
