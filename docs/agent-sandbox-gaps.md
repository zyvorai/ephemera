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
| **nftables + native TC/eBPF dataplane** (`legacy` / `ebpf` / `cilium`) | Yes — see [docs/ebpf-cilium.md](ebpf-cilium.md) |
| OCI → template export | Yes |
| **Redis shared sandbox index** (`FLUXVM_SANDBOX_STATE_URL`) | Yes |
| `/console` ops UI | Yes |
| **Benchmarks** — `scripts/bench-sandbox.sh`, [docs/benchmarks/README.md](../benchmarks/README.md) | Yes |

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
# dataplane.mode = "legacy"   # or "ebpf" / "cilium" — see docs/ebpf-cilium.md
```

## Where FluxVM is ahead or different

- Three+ VMM backends and richer storage (LVM thin, NBD, Ceph RBD)
- virtiofs, macvtap, per-VM netns, image catalog Ed25519 signing
- Suite fit: GuestKit → FluxVM → h2kvm / Ragnarok
