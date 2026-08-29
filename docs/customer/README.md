# Ephemera — Customer Documentation

A standalone, minimal-dependency disposable-VM control plane — QEMU/KVM, Cloud Hypervisor, and Firecracker behind one API.

| You want to… | Open |
|--------------|------|
| Install and boot your first VM | [Getting Started](getting-started.md) |
| Configure backends, storage, auth | [Configuration](configuration.md) |
| Run common jobs | [Workflows](workflows.md) |
| Deploy, systemd, ports | [Admin basics](admin-basics.md) |
| Run as a Kubernetes DaemonSet | [Kubernetes deployment](kubernetes-deployment.md) |
| Use with Ragnarok (UI + SSO) | [Ragnarok integration](ragnarok-integration.md) |
| Build a custom OS image | [Building custom OS images](build-image-tutorial.md) |
| See what it's actually used for | [Use cases](use-cases.md) |
| Full topic index | [PAGE_INDEX.md](PAGE_INDEX.md) |

## Printable PDFs

```bash
node scripts/customer-docs/build-customer-pdfs.mjs
```

Output lands in [`pdf/`](pdf/):

- `Ephemera-Customer-README.pdf`
- `Ephemera-Getting-Started.pdf`
- `Ephemera-Page-by-Page.pdf`
- `Ephemera-Admin-Basics.pdf`

Also available: [using the CLI & API](using-the-dashboard.md).

**→ Product page:** https://zyvor.dev/ephemera · **GitHub:** https://github.com/zyvorai/ephemera
