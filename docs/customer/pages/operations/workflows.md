# Workflows

## Purpose

Day-to-day create / exec / pause / TTL / warm-pool jobs.

## How to get there

- Topic id: `workflows`
- Section: **Operations → Workflows**

## Guide

| Workflow | Steps |
|----------|-------|
| CI/sandbox VM | `ephemera create` with `ttl_seconds` set → `ephemera exec` the build/test command → let the TTL reaper delete it, or `ephemera delete` explicitly |
| Warm pool for fast handoff | `ephemera pool create` with a template + size → `ephemera pool claim` hands back an already-booted, paused VM in roughly resume time |
| Multi-host fleet | Run `ephemera-agent central` once, `ephemera-agent node` on every host, then `POST /fleet/vms` with no target node for load-aware placement |
| Kubernetes-native | Apply the `DisposableVm` CRD, run `ephemera-kube` per node, then create/delete VMs as ordinary Kubernetes objects |
| Image build | `ephemera build-image --spec examples/build-image.json` — download, verify SHA-256, resize, and customize a base image once, reuse it for every VM. See [Building custom OS images](build-image-tutorial.md) for a per-distro walkthrough (apt/dnf/pacman). |

For full command references, see the [technical docs](/docs/ephemera) and the project's own [README](https://github.com/zyvorai/ephemera#readme). See also: [Use cases](use-cases.md).

## Related pages

- [Getting Started](../../getting-started.md)
- [Page index](../../PAGE_INDEX.md)
