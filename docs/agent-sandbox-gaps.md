# AI-agent sandbox gaps

FluxVM is a **multi-VMM disposable-VM control plane** (QEMU, Cloud Hypervisor,
Firecracker, and the in-tree **FluxVM hypervisor**) with CLI/REST, warm pools,
and Kubernetes CRDs — a host-local libvirt/virsh-style lifecycle layer.

The FluxVM hypervisor track (`backend: "flux-vm"`) is the AI-agent sandbox path.

## Implemented on the FluxVm track

| Feature | Status |
|---------|--------|
| `BackendKind::FluxVm` + `fluxvm-hypervisor` UDS control API | Yes |
| Real guest boot via Firecracker engine under FluxVM control | Yes |
| **`fluxvm_engine = "kvm"`** — pure in-tree KVM (no Firecracker child) | Yes (opt-in) |
| Pause / resume / shutdown (proxied to guest engine) | Yes |
| **Memory+disk snapshot** (Firecracker `/snapshot/create` + FICLONE) | Yes |
| **Fast restore** via `/snapshot/load` (cold-boot fallback) | Yes |
| `/v1/sandboxes` + fs/process APIs | Yes |
| **Guest HTTP reverse proxy** (`/sandbox/{id}/…`, AutoResume) | Yes |
| **Multi-port proxy defaults** on sandbox create (`http_proxy_port(s)`) | Yes |
| AutoPause + activity tracking + wake-on-request | Yes |
| Egress allowlist + credential vault + live L7 proxy | Yes |
| **Sandbox dataplane** — Network Fabric **v3**: `legacy` nftables (default), `ebpf` TC IPv4/IPv6 L3+L4 + rate limits, `cilium` coexistence, policy/status/stats/flows API, optional XDP, schema/fingerprint repair | Yes — [docs/network-fabric.md](network-fabric.md) |
| OCI → template export | Yes |
| **Redis shared sandbox index** (`FLUXVM_SANDBOX_STATE_URL`) | Yes |
| `/console` ops UI | Yes |
| **Benchmarks** — `scripts/bench-sandbox.sh`, [docs/benchmarks/README.md](../benchmarks/README.md) | Yes |

### Dataplane (summary)

- **Default:** `sandbox.dataplane.mode = "legacy"` (nftables) — no config change required.
- **`ebpf`:** TC program from `bpf/fluxvm_tc.bpf.c`; pins under `/sys/fs/bpf/fluxvm`;
  iface/schema/fingerprint meta under `/run/fluxvm/ebpf`; IPv4/IPv6 L3+L4
  allowlists (`allow_cidrs`, `allow_ports`); Mbps/PPS limits; stats/flows/events;
  ARP/DHCP/NDP bootstrap always allowed; fallback to nftables unless
  `required = true` (IPv6/rate never silently downgrade). Optional node XDP
  (`bpf/fluxvm_xdp.bpf.c`, meta under `/run/fluxvm/xdp/`) — disabled by default
  and refused in `cilium` mode.
- **`cilium`:** same FluxVM edge attach after verifying `/var/run/cilium/cilium.sock` +
  bpffs; **does not** write Cilium private maps (coexistence, not Cilium endpoint identity).
- **REST:** `GET/POST /v1/vms/{id}/network/policy`, `GET …/status`, `GET …/stats`,
  `GET …/flows` (native modes only; `POST` needs admin when auth is enabled).
- **v3:** dual-stack, pre-attach maps, prog-ID ownership, reconcile heal + orphan GC,
  NDJSON flow exporter.

Applied on FluxVm create/start/restart on the host-visible interface (guest CIDR
optional for native). See [network-fabric.md](network-fabric.md) and README
[eBPF / Cilium sandbox dataplane](../README.md#ebpf--cilium-sandbox-dataplane)
plus [architecture](../README.md#network-fabric-architecture-how-it-works).

## Remaining (optional hardening)

- Production-grade in-tree KVM guests (virtio-blk from rootfs, vsock, snapshots without Firecracker)
- Published density/cold-start numbers from your lab hardware
- Cilium-native VM endpoints / identity-aware Hubble (beyond coexistence mode)

## Host config

```toml
# config.toml
fluxvm_engine = "firecracker"   # default
# fluxvm_engine = "kvm"         # no Firecracker child — in-tree KVM thread

[sandbox]
http_proxy_default_port = 8080

# [sandbox.dataplane]
# mode = "legacy"               # or "ebpf" / "cilium"
# bpf_object = "/usr/lib/fluxvm/bpf/fluxvm_tc.bpf.o"
# pin_root = "/sys/fs/bpf/fluxvm"
# required = false
# default_allow = true
# allow_cidrs = ["10.0.0.0/8", "2001:db8:1234::/48"]
# allow_ports = ["tcp/443", "udp/53"]
# max_egress_mbps = 100
# max_egress_pps = 50000
# sample_rate = 100             # 0 = off
# [sandbox.dataplane.xdp]       # leave disabled with mode = "cilium"
# enabled = false
# block_cidrs = ["198.51.100.0/24", "2001:db8:bad::/48"]
```

## Where FluxVM is ahead or different

- Three+ VMM backends and richer storage (LVM thin, NBD, Ceph RBD)
- virtiofs, macvtap, per-VM netns, image catalog Ed25519 signing
- Native TC/eBPF + safe Cilium coexistence without CNI lock-in
- Suite fit: GuestKit → FluxVM → h2kvm / Ragnarok
