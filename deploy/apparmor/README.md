# AppArmor / SELinux

FluxVM ships an AppArmor profile at `deploy/apparmor/fluxvm`, installed by
`scripts/bootstrap-host.sh` when AppArmor is present.

On SELinux hosts, run FluxVM under a confined domain of your choosing (e.g.
`container_t` / custom `fluxvm_t`) with access to `/dev/kvm`, `/dev/net/tun`,
`/var/lib/fluxvm`, and `CAP_NET_ADMIN` / `CAP_SYS_ADMIN` as required by
netns/cgroup setup. A full reference policy is out of scope for this tree;
document your site policy beside `/etc/fluxvm.toml`.
