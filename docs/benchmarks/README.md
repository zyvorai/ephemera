# FluxVM sandbox benchmarks

Reproduce rough cold-start numbers for the FluxVM hypervisor (`backend: flux-vm`) track.

## Prerequisites

- Linux x86_64 host with `/dev/kvm`
- `fluxvm serve` running (default `127.0.0.1:7788`)
- A bootable sandbox rootfs/kernel referenced in the create spec (adjust the script for your lab image)

## Run

```bash
chmod +x scripts/bench-sandbox.sh
FLUXVM_API=http://127.0.0.1:7788 BENCH_N=10 ./scripts/bench-sandbox.sh
```

## Engine comparison

Set the host config engine before `serve`:

```toml
fluxvm_engine = "firecracker"   # default — Firecracker child under fluxvm-hypervisor
# fluxvm_engine = "kvm"         # pure in-tree KVM (no Firecracker child)
```

Restart `fluxvm serve` between runs and compare `avg_create_ms`.

## Placeholder results (no CI KVM)

| Engine        | avg create (ms) | Notes                          |
|---------------|-----------------|--------------------------------|
| firecracker   | ~TBD            | Lab measurement required       |
| kvm           | ~TBD            | In-tree engine; lab only       |

Record your numbers here after running on real hardware.
