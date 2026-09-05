# FluxVM TC classifier / XDP objects

- `fluxvm_tc.bpf.c` — VM-edge TC dataplane (`ebpf` / `cilium` modes): L3+L4
  allowlists, Mbps/PPS rate limits, stats, flows, sampled events
- `fluxvm_xdp.bpf.c` — optional node-ingress XDP source-CIDR blocklist
  (disabled by default; refused in `cilium` mode)

Build:

```bash
./scripts/build-ebpf.sh
# outputs: dist/bpf/fluxvm_tc.bpf.o  dist/bpf/fluxvm_xdp.bpf.o
```

Validate (syntax + optional build/tests/smoke):

```bash
../scripts/validate-network-fabric.sh
FLUXVM_PRIVILEGED_SMOKE=1 ../scripts/validate-network-fabric.sh
```

Docs: [docs/network-fabric.md](../docs/network-fabric.md),
[docs/ebpf-cilium.md](../docs/ebpf-cilium.md)
