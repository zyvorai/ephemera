# FluxVM

A **lightweight KVM Virtual Machine Monitor** in Rust.

This is a *design + starter implementation*, not a drop-in replacement for QEMU.
A production VMM (Firecracker / Cloud Hypervisor class) is 50k–100k+ lines.
FluxVM shows the architecture you should actually build if the goal is
**faster boot, smaller attack surface, and near-native runtime vs QEMU**.

## Honest performance claim

| Layer | Who is faster than QEMU? |
|---|---|
| Guest CPU after boot | Neither. Both use KVM VT-x / AMD-V. Same silicon. |
| Cold boot + memory overhead | Yes, if you skip BIOS/UEFI, PCI, VGA, USB, floppy, ACPI bloat. |
| Device I/O | Yes, with virtio + vhost-net / io_uring, not emulated e1000/IDE. |
| Pure software CPU emulation | **No.** QEMU TCG will beat a homemade emulator. Do not go there. |

**Do not write a CPU emulator.** Drive KVM. Emulate only virtio + a tiny
machine model.

## What this repo contains

- Architecture and machine model (`DESIGN.md`)
- Working KVM bootstrap: open `/dev/kvm`, create VM, map guest RAM, create vCPU
- Exit-handling skeleton (`KVM_RUN` loop)
- Linux bzImage / ELF load path (interface)
- Windows / UEFI boot path (interface + requirements)
- virtio-net TAP + vhost-net design
- virtio-blk, serial console, vsock, balloon interfaces
- Rate limiting, seccomp, jailer notes

## Host requirements

- Linux x86_64 (primary). aarch64 is the same design with different boot.
- `/dev/kvm` accessible (`kvm` group or root)
- Intel VT-x or AMD-V
- For Windows guests: Cloud Hypervisor–style ACPI + virtio-win drivers

```bash
# check KVM
ls -l /dev/kvm
egrep -c '(vmx|svm)' /proc/cpuinfo
```

## Build

```bash
cd fluxvm
cargo build --release
# needs a host with KVM to actually run a guest
```

## Next real projects to study (do not reinvent)

- [rust-vmm](https://github.com/rust-vmm)
- [Firecracker](https://github.com/firecracker-microvm/firecracker) — microVMs, Linux only
- [Cloud Hypervisor](https://github.com/cloud-hypervisor/cloud-hypervisor) — Linux + Windows
- [libkrun](https://github.com/containers/libkrun) — embeddable VMM
