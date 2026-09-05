// Copyright 2026 Zyvor
// SPDX-License-Identifier: Apache-2.0

//! Native FluxVM eBPF dataplane loader.
//!
//! The actual TC classifier is compiled from `bpf/fluxvm_tc.bpf.c`. This
//! userspace module deliberately talks to the kernel through `bpftool` and
//! `tc` instead of linking libbpf into the FluxVM daemon. That keeps the
//! normal Rust build dependency-free while still giving FluxVM a real,
//! pinned, per-VM eBPF dataplane.

use anyhow::{Context, Result, bail};
use fluxvm_core::config::DataplaneConfig;
use std::{
    fs,
    net::Ipv4Addr,
    path::{Path, PathBuf},
    process::Command,
};
use tracing::info;
use uuid::Uuid;

const TC_PRIORITY: &str = "50";
const TC_HANDLE: &str = "1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Ipv4Cidr {
    network: Ipv4Addr,
    prefix: u8,
}

pub fn apply(cfg: &DataplaneConfig, id: Uuid, iface: &str, allow_cidrs: &[String]) -> Result<()> {
    if iface.is_empty() {
        bail!("cannot attach eBPF dataplane without a host-visible interface");
    }
    if !cfg.bpf_object.exists() {
        bail!(
            "FluxVM eBPF object does not exist at {}",
            cfg.bpf_object.display()
        );
    }

    require_command("bpftool")?;
    require_command("tc")?;

    // Remove stale pins from a prior crash/restart before loading a fresh
    // instance. The interface itself is per-VM, so replacing our TC filter
    // is safe and deterministic.
    let _ = remove(id);

    let vm_dir = vm_pin_dir(&cfg.pin_root, id);
    let prog_dir = vm_dir.join("progs");
    let map_dir = vm_dir.join("maps");
    fs::create_dir_all(&prog_dir)
        .with_context(|| format!("creating eBPF program pin dir {}", prog_dir.display()))?;
    fs::create_dir_all(&map_dir)
        .with_context(|| format!("creating eBPF map pin dir {}", map_dir.display()))?;
    // bpffs only accepts BPF objects — keep the detach sidecar on a normal fs.
    let meta_dir = vm_meta_dir(id);
    fs::create_dir_all(&meta_dir)
        .with_context(|| format!("creating eBPF meta dir {}", meta_dir.display()))?;
    fs::write(meta_dir.join("iface"), iface)
        .with_context(|| format!("recording eBPF interface {iface}"))?;

    let prog_pin = prog_dir.join("fluxvm_egress");
    run(
        "bpftool",
        &[
            "prog".into(),
            "load".into(),
            cfg.bpf_object.display().to_string(),
            prog_pin.display().to_string(),
            "type".into(),
            "classifier".into(),
            "pinmaps".into(),
            map_dir.display().to_string(),
        ],
    )
    .context("loading FluxVM TC program")?;

    run(
        "tc",
        &[
            "qdisc".into(),
            "replace".into(),
            "dev".into(),
            iface.into(),
            "clsact".into(),
        ],
    )
    .context("installing clsact qdisc")?;
    run(
        "tc",
        &[
            "filter".into(),
            "replace".into(),
            "dev".into(),
            iface.into(),
            "ingress".into(),
            "pref".into(),
            TC_PRIORITY.into(),
            "handle".into(),
            TC_HANDLE.into(),
            "bpf".into(),
            "da".into(),
            "pinned".into(),
            prog_pin.display().to_string(),
        ],
    )
    .context("attaching FluxVM TC program")?;

    let ifindex = read_ifindex(iface)?;
    let identity = identity_for(id);
    update_iface_config(
        &map_dir.join("fluxvm_id"),
        ifindex,
        identity,
        cfg.default_allow,
    )?;

    let mut cidrs = cfg.allow_cidrs.clone();
    cidrs.extend_from_slice(allow_cidrs);
    cidrs.sort();
    cidrs.dedup();
    for cidr in cidrs {
        let parsed =
            parse_ipv4_cidr(&cidr).with_context(|| format!("invalid eBPF allow CIDR {cidr:?}"))?;
        update_ipv4_allow(&map_dir.join("fluxvm_v4"), identity, parsed)?;
    }

    info!(
        %id,
        %iface,
        identity,
        default_allow = cfg.default_allow,
        "attached FluxVM native eBPF dataplane"
    );
    Ok(())
}

pub fn remove(id: Uuid) -> Result<()> {
    let iface = read_recorded_iface(id);
    if let Some(iface) = iface {
        let _ = run(
            "tc",
            &[
                "filter".into(),
                "del".into(),
                "dev".into(),
                iface,
                "ingress".into(),
                "pref".into(),
                TC_PRIORITY.into(),
            ],
        );
    }

    for vm_dir in candidate_pin_roots(id) {
        if vm_dir.exists() {
            let _ = fs::remove_dir_all(&vm_dir);
        }
    }
    let meta = vm_meta_dir(id);
    if meta.exists() {
        let _ = fs::remove_dir_all(&meta);
    }
    Ok(())
}

fn read_recorded_iface(id: Uuid) -> Option<String> {
    let meta = vm_meta_dir(id).join("iface");
    if let Ok(iface) = fs::read_to_string(&meta) {
        let iface = iface.trim();
        if !iface.is_empty() {
            return Some(iface.to_string());
        }
    }
    // Legacy path from earlier builds that attempted to store iface on bpffs.
    for vm_dir in candidate_pin_roots(id) {
        if let Ok(iface) = fs::read_to_string(vm_dir.join("iface")) {
            let iface = iface.trim();
            if !iface.is_empty() {
                return Some(iface.to_string());
            }
        }
    }
    None
}

/// `remove` does not receive Config because it is also called from network
/// teardown after a failed create. Check the conventional default pin root
/// and the optional runtime override FluxVM documents for custom installs.
fn candidate_pin_roots(id: Uuid) -> Vec<PathBuf> {
    let mut roots = vec![vm_pin_dir(Path::new("/sys/fs/bpf/fluxvm"), id)];
    if let Ok(root) = std::env::var("FLUXVM_BPF_PIN_ROOT") {
        let p = vm_pin_dir(Path::new(&root), id);
        if !roots.contains(&p) {
            roots.push(p);
        }
    }
    roots
}

fn vm_pin_dir(root: &Path, id: Uuid) -> PathBuf {
    root.join("vms").join(id.simple().to_string())
}

fn vm_meta_dir(id: Uuid) -> PathBuf {
    if let Ok(root) = std::env::var("FLUXVM_BPF_META_ROOT") {
        return PathBuf::from(root)
            .join("vms")
            .join(id.simple().to_string());
    }
    PathBuf::from("/run/fluxvm/ebpf/vms").join(id.simple().to_string())
}

fn identity_for(id: Uuid) -> u32 {
    // Stable for the VM lifetime and deterministic across daemon restarts.
    // Zero is kept unused to make accidental/uninitialized identity entries
    // distinguishable in BPF maps and diagnostics.
    let raw = (id.as_u128() as u32) ^ ((id.as_u128() >> 64) as u32);
    raw.max(1)
}

fn read_ifindex(iface: &str) -> Result<u32> {
    let raw = fs::read_to_string(format!("/sys/class/net/{iface}/ifindex"))
        .with_context(|| format!("reading ifindex for {iface}"))?;
    raw.trim()
        .parse::<u32>()
        .with_context(|| format!("parsing ifindex for {iface}"))
}

fn update_iface_config(map: &Path, ifindex: u32, identity: u32, default_allow: bool) -> Result<()> {
    let mut key = Vec::with_capacity(4);
    key.extend_from_slice(&ifindex.to_ne_bytes());
    let mut value = Vec::with_capacity(8);
    value.extend_from_slice(&identity.to_ne_bytes());
    value.extend_from_slice(&(default_allow as u32).to_ne_bytes());
    bpftool_map_update(map, &key, &value)
}

fn update_ipv4_allow(map: &Path, identity: u32, cidr: Ipv4Cidr) -> Result<()> {
    // LPM data is: exact 32-bit VM identity followed by the IPv4 prefix.
    // `prefixlen` therefore includes those first 32 identity bits.
    let lpm_prefix = 32u32 + u32::from(cidr.prefix);
    let mut key = Vec::with_capacity(12);
    key.extend_from_slice(&lpm_prefix.to_ne_bytes());
    key.extend_from_slice(&identity.to_ne_bytes());
    key.extend_from_slice(&cidr.network.octets());
    bpftool_map_update(map, &key, &1u32.to_ne_bytes())
}

fn bpftool_map_update(map: &Path, key: &[u8], value: &[u8]) -> Result<()> {
    let mut args = vec![
        "map".into(),
        "update".into(),
        "pinned".into(),
        map.display().to_string(),
        "key".into(),
        "hex".into(),
    ];
    args.extend(hex_args(key));
    args.push("value".into());
    args.push("hex".into());
    args.extend(hex_args(value));
    run("bpftool", &args)
}

fn hex_args(bytes: &[u8]) -> Vec<String> {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn parse_ipv4_cidr(raw: &str) -> Result<Ipv4Cidr> {
    let (ip, prefix) = raw
        .split_once('/')
        .with_context(|| format!("CIDR {raw:?} must include /prefix"))?;
    let ip: Ipv4Addr = ip.parse().with_context(|| format!("invalid IPv4 {ip:?}"))?;
    let prefix: u8 = prefix
        .parse()
        .with_context(|| format!("invalid prefix in {raw:?}"))?;
    if prefix > 32 {
        bail!("IPv4 prefix must be <= 32, got {prefix}");
    }
    let raw_ip = u32::from(ip);
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    Ok(Ipv4Cidr {
        network: Ipv4Addr::from(raw_ip & mask),
        prefix,
    })
}

fn require_command(name: &str) -> Result<()> {
    // iproute2's `tc` accepts `-V` / `-Version`, not GNU-style `--version`.
    let probes: &[&[&str]] = if name == "tc" {
        &[&["-V"], &["-Version"], &["--version"]]
    } else {
        &[&["--version"], &["-V"]]
    };
    let mut last_err: Option<String> = None;
    for args in probes {
        match Command::new(name).args(*args).status() {
            Ok(s) if s.success() => return Ok(()),
            Ok(s) => last_err = Some(format!("{name} {} exited with {s}", args.join(" "))),
            Err(e) => {
                return Err(e).with_context(|| format!("{name} is required for the eBPF dataplane"));
            }
        }
    }
    bail!(
        "{}",
        last_err.unwrap_or_else(|| format!("{name} version probe failed"))
    );
}

fn run(program: &str, args: &[String]) -> Result<()> {
    let out = Command::new(program)
        .args(args)
        .output()
        .with_context(|| format!("running {program}"))?;
    if !out.status.success() {
        bail!(
            "{} {} failed: {}",
            program,
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cidr_is_network_normalized() {
        let c = parse_ipv4_cidr("10.20.30.99/24").unwrap();
        assert_eq!(c.network, Ipv4Addr::new(10, 20, 30, 0));
        assert_eq!(c.prefix, 24);
    }

    #[test]
    fn cidr_zero_prefix_is_supported() {
        let c = parse_ipv4_cidr("203.0.113.7/0").unwrap();
        assert_eq!(c.network, Ipv4Addr::UNSPECIFIED);
        assert_eq!(c.prefix, 0);
    }

    #[test]
    fn invalid_prefix_is_rejected() {
        assert!(parse_ipv4_cidr("10.0.0.1/33").is_err());
    }

    #[test]
    fn bytes_are_bpftool_hex_tokens() {
        assert_eq!(hex_args(&[0, 1, 0xfe]), ["00", "01", "fe"]);
    }
}
