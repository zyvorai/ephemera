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
| **Sandbox dataplane** — `legacy` nftables (default), `ebpf` TC L3+L4, `cilium` coexistence, policy/stats/flows API, optional XDP | Yes — [docs/network-fabric.md](network-fabric.md) |
| OCI → template export | Yes |
| **Redis shared sandbox index** (`FLUXVM_SANDBOX_STATE_URL`) | Yes |
| `/console` ops UI | Yes |
| **Benchmarks** — `scripts/bench-sandbox.sh`, [docs/benchmarks/README.md](../benchmarks/README.md) | Yes |

### Dataplane (summary)

- **Default:** `sandbox.dataplane.mode = "legacy"` (nftables) — no config change required.
- **`ebpf`:** real TC program from `bpf/fluxvm_tc.bpf.c`; pins under `/sys/fs/bpf/fluxvm`;
  iface meta under `/run/fluxvm/ebpf`; LPM IPv4 allowlist; ARP/DHCP always allowed;
  fallback to nftables unless `required = true`.
- **`cilium`:** same FluxVM edge attach after verifying `/var/run/cilium/cilium.sock` +
  bpffs; **does not** write Cilium private maps (coexistence, not Cilium endpoint identity).

Applied on FluxVm create/start when a guest CIDR is known. See README
[eBPF / Cilium sandbox dataplane](../README.md#ebpf--cilium-sandbox-dataplane).

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
# allow_cidrs = ["10.0.0.0/8"]
```

## Where FluxVM is ahead or different

- Three+ VMM backends and richer storage (LVM thin, NBD, Ceph RBD)
- virtiofs, macvtap, per-VM netns, image catalog Ed25519 signing
- Native TC/eBPF + safe Cilium coexistence without CNI lock-in
- Suite fit: GuestKit → FluxVM → h2kvm / Ragnarok
