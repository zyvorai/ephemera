# FluxVM eBPF dataplane and Cilium coexistence

FluxVM supports three sandbox dataplane modes:

- `legacy`: existing nftables policy path.
- `ebpf`: FluxVM loads its own per-VM TC classifier and pins all BPF state under `/sys/fs/bpf/fluxvm`. Detach metadata (iface name) lives under `/run/fluxvm/ebpf` because bpffs cannot store regular files.
- `cilium`: the same FluxVM VM-edge eBPF enforcement, but only after verifying that the host Cilium agent socket and bpffs are visible. FluxVM does **not** write Cilium private BPF maps.

The Cilium mode is intentionally a coexistence mode, not a claim that a FluxVM VM is a native Cilium endpoint. Cilium remains responsible for Kubernetes/node networking; FluxVM owns the VM-edge interface. A future launcher-pod/CNI integration can add first-class Cilium identities without changing the native dataplane API introduced here.

## Traffic path

For a namespaced VM the TC program is attached to the host side of the per-VM veth pair:

```text
VM -> TAP -> bridge -> namespace veth -> host veth [FluxVM TC/eBPF] -> host routing -> Cilium/node dataplane
```

For a non-namespaced TAP VM it attaches directly to the host-visible TAP.

## Build the BPF object

Debian/Ubuntu prerequisites:

```bash
sudo apt-get install clang llvm libbpf-dev bpftool iproute2
./scripts/build-ebpf.sh
sudo install -D -m 0644 dist/bpf/fluxvm_tc.bpf.o \
  /usr/lib/fluxvm/bpf/fluxvm_tc.bpf.o
```

The container image builds and installs the object automatically.

## Configuration

```toml
[sandbox.dataplane]
mode = "ebpf"
bpf_object = "/usr/lib/fluxvm/bpf/fluxvm_tc.bpf.o"
pin_root = "/sys/fs/bpf/fluxvm"
required = false
default_allow = false
allow_cidrs = ["10.0.0.0/8", "192.0.2.0/24"]
```

`required = false` falls back to nftables if loading or attaching eBPF fails. Set it to `true` when a missing dataplane must fail VM network setup.

For a Kubernetes node already running Cilium:

```toml
[sandbox.dataplane]
mode = "cilium"
bpf_object = "/usr/lib/fluxvm/bpf/fluxvm_tc.bpf.o"
pin_root = "/sys/fs/bpf/fluxvm"
required = true
default_allow = true
```

The Kubernetes DaemonSet mounts `/sys/fs/bpf` and `/var/run/cilium` from the host so FluxVM can pin its own programs and verify Cilium presence.

## Policy semantics

The first program implements IPv4 destination-CIDR egress policy. ARP and DHCP are always allowed so a VM can bootstrap networking. Non-IPv4 traffic follows `default_allow`; with `default_allow = false`, IPv6 is denied until IPv6 policy support is added.

The BPF object contains four per-VM maps:

- `fluxvm_id`: host interface index -> FluxVM identity/default action.
- `fluxvm_v4`: LPM trie keyed by FluxVM identity + destination IPv4 prefix.
- `fluxvm_stats`: per-CPU allow/drop counters.
- `fluxvm_events`: ring buffer for dropped-flow events.

Each VM gets its own pinned program/maps directory, which makes teardown simple and avoids sharing mutable Cilium internals.

## Cilium boundary

This change deliberately avoids calling `cilium-dbg bpf ...` or editing maps under Cilium's pin namespace. Those maps are implementation details and may change between Cilium releases. The safe integration boundary is:

1. Cilium owns Kubernetes/node CNI and its host datapath.
2. FluxVM owns the VM TAP/veth edge.
3. Both use bpffs but separate pin namespaces.
4. A later CNI/launcher-pod implementation can make each VM a first-class Cilium endpoint and add Hubble identity-aware flows.
