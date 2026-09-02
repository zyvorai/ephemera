# Build Custom Images

## Purpose

Build and customize guest OS images for disposable VMs.

## How to get there

- Topic id: `build-image-tutorial`
- Section: **Images → Build Custom Images**

## Guide

`fluxvm build-image` takes a base disk image and applies customizations —
hostname, package installs, arbitrary commands, SSH-key injection, file
copy-in, and systemd service enablement — to produce a new, ready-to-boot
image. It does this through [GuestKit](/guestkit) mounting the image
directly with `qemu-nbd` and running commands in a `chroot`. There's no
libguestfs appliance and **no VM boot involved**, which means `build-image`
doesn't need `/dev/kvm` at all — only root and the `nbd` kernel module.

This page walks through the three package-manager families `build-image`
supports: Debian/Ubuntu (`apt`), RHEL-family (`dnf`/`tdnf`/`yum`), and Arch
Linux (`pacman`). Every example here is real-hardware-verified and covered
by an automated CI job that runs the same checks against fresh Ubuntu,
Rocky Linux, and Arch cloud images on every commit — see
[`scripts/test-image-customize.sh`](https://github.com/zyvorai/fluxvm/blob/main/scripts/test-image-customize.sh)
in the repo.

## How it works, briefly

| Field | What it does | Needs network? |
|---|---|---|
| `hostname` | Writes `/etc/hostname` | No |
| `packages` | Detects the guest's package manager, installs via it | **Yes** |
| `commands` | Runs each string via `sh -c` inside the chroot | Depends on the command |
| `ssh_key` | Appends to `/root/.ssh/authorized_keys`, `0600` perms | No |
| `copy_in` | Copies a host file into the image at the given path | No |
| `enable_services` | Runs `systemctl enable <name>` for each unit | No |

`packages` is the one field that needs real outbound networking — the
guest's package manager has to actually reach its repositories.
`build-image` handles this for you: it stages a working `/etc/resolv.conf`
into the guest for the duration of the install (a stock cloud image's own
`resolv.conf` is usually a dangling symlink that only resolves under a
running systemd instance) and removes it again afterward.

Package-manager detection execs `command -v <tool>` inside the chroot and
checks what's actually there, in this order: `apt-get → tdnf → dnf → yum →
pacman`. If none are found, `packages` fails with a clear error telling you
to use an equivalent `commands` entry instead.

## Prerequisites

```bash
sudo modprobe nbd max_part=16
```

`scripts/bootstrap-host.sh` does this for you as part of general host setup.
You need root (for the `qemu-nbd` mount) and enough free disk for a copy of
the base image plus the output image — no VMM, no `/dev/kvm`.

## Debian / Ubuntu

```json
{
  "source": "/var/lib/fluxvm/images/ubuntu-noble.qcow2",
  "output": "/var/lib/fluxvm/images/ubuntu-dev.qcow2",
  "format": "qcow2",
  "hostname": "ubuntu-dev",
  "packages": ["tree", "jq", "qemu-guest-agent"],
  "commands": ["touch /etc/provisioned-by-fluxvm"],
  "ssh_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... you@example.com",
  "enable_services": ["qemu-guest-agent", "cron"]
}
```

```bash
sudo fluxvm build-image --spec ubuntu-dev.json
```

Ubuntu's stock cloud image enables the `universe` component by default, so
most common CLI tools install with no extra repo configuration. The system
cron daemon's unit is `cron.service` — not `crond` (that's the RHEL-family
name).

## Rocky Linux, AlmaLinux, Fedora (`dnf`)

```json
{
  "source": "/var/lib/fluxvm/images/rocky9.qcow2",
  "output": "/var/lib/fluxvm/images/rocky9-dev.qcow2",
  "format": "qcow2",
  "hostname": "rocky-dev",
  "packages": ["tree", "jq"],
  "commands": ["touch /etc/provisioned-by-fluxvm"],
  "enable_services": ["crond"]
}
```

```bash
sudo fluxvm build-image --spec rocky-dev.json
```

Rocky's `GenericCloud` image ships `cronie` (providing `crond.service`)
pre-installed — `enable_services: ["crond"]` works without needing
`packages` to install it first. Photon OS (`tdnf`) and older RHEL/CentOS 7
(`yum`) images go through the exact same code path.

## Arch Linux (`pacman`)

```json
{
  "source": "/var/lib/fluxvm/images/arch.qcow2",
  "output": "/var/lib/fluxvm/images/arch-dev.qcow2",
  "format": "qcow2",
  "hostname": "arch-dev",
  "packages": ["tree", "jq"],
  "commands": ["touch /etc/provisioned-by-fluxvm"],
  "enable_services": ["sshd"]
}
```

```bash
sudo fluxvm build-image --spec arch-dev.json
```

Arch needs two things every other distro here doesn't — both handled for
you automatically:

1. **Empty keyring.** A fresh Arch image ships with no trusted pacman
   keyring, so `build-image` runs `pacman-key --init` and `pacman-key
   --populate archlinux` before the actual install. This takes a few extra
   seconds the first time.
2. **No `/etc/mtab`.** `pacman` refuses to run without a readable
   `/etc/mtab` — on a real system that's a symlink to `/proc/self/mounts`,
   which doesn't exist in this bare chroot. `build-image` stages a minimal
   synthetic one for the duration of the install.

Arch's official cloud image doesn't ship cron by default, so this example
enables `sshd` (which *is* preinstalled) instead — add `"cronie"` to
`packages` and use `enable_services: ["cronie"]` if you want cron.

## Verifying an image without booting it

Since `build-image` never boots a VM, you can sanity-check the output by
mounting it directly, the same way it was built:

```bash
sudo modprobe nbd max_part=16
sudo qemu-nbd -c /dev/nbd0 /var/lib/fluxvm/images/ubuntu-dev.qcow2
sudo partprobe /dev/nbd0 && sudo udevadm settle
sudo mount /dev/nbd0p1 /mnt   # partition number varies by image layout
cat /mnt/etc/hostname
sudo umount /mnt
sudo qemu-nbd -d /dev/nbd0
```

## Troubleshooting

- **"cannot install packages: no supported package manager found"** — the
  image's package manager isn't apt/dnf/tdnf/yum/pacman (e.g. Alpine's
  `apk`). Use `commands` to install packages manually.
- **A package install fails with a DNS/network-looking error** — check the
  *host's* own network/DNS first; `packages` needs the host to have real
  outbound connectivity.
- **`enable_services` fails with "unit does not exist"** — the service name
  is distro-specific (`cron` vs `crond`, `ssh` vs `sshd`), or the package
  providing it isn't installed yet.

## Next steps

- [Common workflows](../operations/workflows.md)
- [Use cases](../onboarding/use-cases.md)
- [Technical docs](/docs/fluxvm)

## Operate from the console (UX)

1. Open this route from the nav or command palette and wait for live API data.
2. Use filters/search when present; drill into a row for detail.
3. For mutating actions: confirm role gates and impact before applying.
4. **Empty / fail:** Check service health, auth, and that required CRDs/backends for this domain are installed.
5. **Success:** Live data loads; created/updated objects appear without error toasts.

## Related pages

- [Getting Started](../../getting-started.md)
- [Page index](../../PAGE_INDEX.md)
