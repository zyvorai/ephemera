# FluxVM TC classifier / XDP objects

- `fluxvm_tc.bpf.c` — VM-edge TC dataplane (`ebpf` / `cilium` modes)
- `fluxvm_xdp.bpf.c` — optional node-ingress XDP blocklist

Build: `./scripts/build-ebpf.sh`  
Docs: [docs/network-fabric.md](../docs/network-fabric.md), [docs/ebpf-cilium.md](../docs/ebpf-cilium.md)
