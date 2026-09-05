# FluxVM TC classifier / XDP objects

- `fluxvm_tc.bpf.c` — VM-edge TC dataplane (`ebpf` / `cilium` modes): L3+L4
  allowlists, stats, flows, sampled events
- `fluxvm_xdp.bpf.c` — optional node-ingress XDP source-CIDR blocklist
  (disabled by default; refused in `cilium` mode)

Build:

```bash
./scripts/build-ebpf.sh
# outputs: dist/bpf/fluxvm_tc.bpf.o  dist/bpf/fluxvm_xdp.bpf.o
```

Kernel smoke (dual netns; needs root + bpftool/tc):

```bash
sudo -E ../scripts/test-ebpf-smoke.sh
```

Docs: [docs/network-fabric.md](../docs/network-fabric.md),
[docs/ebpf-cilium.md](../docs/ebpf-cilium.md)
