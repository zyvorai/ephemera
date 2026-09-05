# FluxVM eBPF dataplane and Cilium coexistence

FluxVM ships a real TC/eBPF VM-edge dataplane while keeping the existing
nftables path as the **backwards-compatible default**.

## Modes

| Mode | Behavior |
|------|----------|
| `legacy` (default) | Existing per-sandbox nftables SNAT + optional destination allowlist. |
| `ebpf` | Load FluxVM’s TC classifier (`bpf/fluxvm_tc.bpf.c`), pin programs/maps under `pin_root`, attach to the host-visible VM interface. L4/ports, policy API, stats/flows, XDP: [network-fabric.md](network-fabric.md). |
| `cilium` | Same FluxVM VM-edge eBPF path, but only after verifying the Cilium agent socket and bpffs are visible. **Never** writes Cilium private BPF maps. |

Default remains `sandbox.dataplane.mode = "legacy"`. Existing configs that omit
`[sandbox.dataplane]` keep using nftables.

Dataplane apply runs on **FluxVm** (`backend: "flux-vm"`) create/start when a
guest CIDR is known. If `required = false` (default) and eBPF load/attach fails,
FluxVM logs a warning and falls back to nftables. If `required = true`, create/start
fails.

## What the eBPF path provides

- Actual TC classifier source: [`bpf/fluxvm_tc.bpf.c`](../bpf/fluxvm_tc.bpf.c)
- Per-VM pins under `/sys/fs/bpf/fluxvm/vms/<uuid-simple>/` (`progs/`, `maps/`)
- Detach metadata (iface name) under `/run/fluxvm/ebpf/vms/<uuid-simple>/` —
  bpffs cannot store regular files
- Host ifindex → stable FluxVM VM identity map
- IPv4 destination-CIDR policy via an LPM trie
- Per-CPU allow/drop counters and a drop-event ring buffer
- ARP and DHCP always allowed so guests can bootstrap
- Attach point:
  - namespaced TAP → host-side veth `vh<short-id>`
  - direct TAP/macvtap → that host-visible device
- Teardown on VM network cleanup (`remove_sandbox_policy` before netns/tap delete)
- Container image builds/installs the `.o`; DaemonSet mounts host bpffs and
  read-only `/var/run/cilium`

## Why Cilium coexistence (not private-map integration)

FluxVM VM interfaces are **not** first-class Cilium endpoints today. Writing
Cilium’s internal maps would couple FluxVM to Cilium implementation details and
release-specific map layouts.

Ownership boundary:

1. **Cilium** owns Kubernetes/node CNI and its host datapath.
2. **FluxVM** owns the VM TAP/veth edge (pins under `/sys/fs/bpf/fluxvm` only).
3. Both may use bpffs; pin namespaces stay separate.
4. A later launcher-pod/CNI change can make each VM a native Cilium identity
   (Hubble-aware) without replacing the native FluxVM dataplane API.

For the full Network Fabric v1 surface (L4 ports, per-VM policy API, stats/flows,
optional XDP guard), see [docs/network-fabric.md](network-fabric.md).

## Traffic path

Namespaced VM:

```text
VM -> TAP -> bridge -> namespace veth -> host veth [FluxVM TC/eBPF]
  -> host routing -> Cilium/node dataplane
```

Non-namespaced TAP/macvtap: the classifier attaches directly to the host-visible
device.

## Build the BPF object

Debian/Ubuntu:

```bash
sudo apt-get install clang llvm libbpf-dev linux-tools-common \
  "linux-tools-$(uname -r)" iproute2 nftables
./scripts/build-ebpf.sh
sudo install -D -m 0644 dist/bpf/fluxvm_tc.bpf.o \
  /usr/lib/fluxvm/bpf/fluxvm_tc.bpf.o
```

(`bpftool` often ships as `linux-tools-*` rather than a package named `bpftool`.)

The Dockerfile builder stage runs `./scripts/build-ebpf.sh` and installs the
object to `/usr/lib/fluxvm/bpf/fluxvm_tc.bpf.o`. Runtime image includes
`nftables` and `bpftool`. systemd’s `ReadWritePaths` includes `/sys/fs/bpf` so
pins work under `ProtectSystem=strict`.

## Configuration

```toml
[sandbox.dataplane]
mode = "ebpf"                 # legacy | ebpf | cilium
bpf_object = "/usr/lib/fluxvm/bpf/fluxvm_tc.bpf.o"
pin_root = "/sys/fs/bpf/fluxvm"
required = false              # true => fail VM create/start if eBPF cannot attach
default_allow = true          # false = deny-by-default for non-matching IPv4 / non-IPv4
allow_cidrs = ["10.0.0.0/8", "192.0.2.0/24"]
```

Also merge allowlists from `sandbox.egress_allow_domains` (resolved to CIDRs) and
any CIDRs passed at apply time.

Kubernetes node with Cilium present:

```toml
[sandbox.dataplane]
mode = "cilium"
bpf_object = "/usr/lib/fluxvm/bpf/fluxvm_tc.bpf.o"
pin_root = "/sys/fs/bpf/fluxvm"
required = true
default_allow = true
```

The DaemonSet mounts host `/sys/fs/bpf` and read-only `/var/run/cilium` so FluxVM
can pin programs and see `cilium.sock` for coexistence checks. See
[`deploy/k8s/daemonset.yaml`](../deploy/k8s/daemonset.yaml).

## Policy semantics

- IPv4 destination-CIDR egress policy (LPM).
- ARP and DHCP always allowed.
- Non-IPv4 follows `default_allow`; with `default_allow = false`, IPv6 is denied
  until IPv6 policy exists.

Per-VM maps (pinned under each VM’s `maps/` directory):

| Map | Role |
|-----|------|
| `fluxvm_id` | ifindex → FluxVM identity + default action |
| `fluxvm_v4` | LPM: identity + destination IPv4 prefix → allow |
| `fluxvm_stats` | per-CPU allow/drop counters |
| `fluxvm_events` | ring buffer for drop events |

## Validation

```bash
cargo fmt --all -- --check
cargo test -p fluxvm-network
cargo test -p fluxvm-scheduler   # or cargo check -p fluxvm-scheduler on hosts without libhivex
./scripts/build-ebpf.sh
sudo bpftool prog load dist/bpf/fluxvm_tc.bpf.o /sys/fs/bpf/fluxvm-smoke type classifier
sudo rm -f /sys/fs/bpf/fluxvm-smoke
```

Privileged integration smoke (FluxVm + `NetworkSpec::Tap { netns: true }`):

1. Set `[sandbox.dataplane] mode = "ebpf"` (and install the `.o`).
2. Create a FluxVm sandbox with netns networking.
3. Confirm `tc filter show dev vh<short-id> ingress` shows `fluxvm_egress`.
4. Inspect pins under `/sys/fs/bpf/fluxvm/vms/<uuid-simple>/` and meta under
   `/run/fluxvm/ebpf/vms/<uuid-simple>/`.
5. Delete the VM; pins, meta, and the TC filter should be gone.
6. With `required = false` and a missing `.o`, create should warn and fall back
   to nftables.

Netns NAT tables (`fluxvm_netns_*`) remain independent of sandbox dataplane mode
and continue to use nftables helpers (`apply_subnet_masquerade`).
