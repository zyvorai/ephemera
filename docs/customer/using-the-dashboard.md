# Using Ephemera (CLI & API)

Ephemera is primarily a **CLI + REST** control plane (no first-party web console). Day-to-day work uses `ephemera` on the host, or the HTTP API the same binary serves.

## CLI essentials

```bash
ephemera create --spec examples/qemu.json
ephemera list
ephemera exec <id> -- echo hello
ephemera delete <id>
```

## REST surface

The control plane exposes HTTP endpoints for create/list/get/delete/exec and related lifecycle calls. Point clients (including Ragnarok and Zyvor Fabric) at the configured listen address.

## Where to go next

| Job | Doc |
|-----|-----|
| First VM | [Getting Started](getting-started.md) |
| Backend & storage | [Configuration](configuration.md) |
| Common jobs | [Workflows](workflows.md) |
| Host / systemd | [Admin Basics](admin-basics.md) |
| Full topic index | [PAGE_INDEX.md](PAGE_INDEX.md) |
