// Copyright 2026 Zyvor
// SPDX-License-Identifier: Apache-2.0

//! Optional standalone-node XDP guard.
//!
//! This is intentionally disabled in Cilium coexistence mode because Cilium
//! may own XDP on the physical interface for acceleration. FluxVM refuses to
//! replace any pre-existing third-party XDP program.

use anyhow::{Context, Result, bail};
use fluxvm_core::config::{DataplaneConfig, DataplaneMode, XdpConfig};
use serde_json::Value;
use std::{
    fs,
    net::Ipv4Addr,
    path::{Path, PathBuf},
    process::Command,
};
use tracing::info;

#[derive(Debug, Clone, Copy)]
struct Ipv4Cidr {
    network: Ipv4Addr,
    prefix: u8,
}

pub fn ensure(cfg: &DataplaneConfig) -> Result<()> {
    if !cfg.xdp.enabled {
        return Ok(());
    }
    if cfg.mode == DataplaneMode::Cilium {
        bail!(
            "FluxVM XDP guard is disabled in dataplane.mode=cilium to avoid replacing Cilium XDP; use Cilium's node XDP features instead"
        );
    }
    apply(&cfg.xdp)
}

pub fn apply(cfg: &XdpConfig) -> Result<()> {
    let iface = cfg
        .interface
        .as_deref()
        .context("xdp.enabled=true requires xdp.interface")?;
    if !cfg.bpf_object.exists() {
        bail!("XDP object does not exist at {}", cfg.bpf_object.display());
    }
    require_bpftool()?;
    require_ip()?;
    crate::ebpf::raise_memlock()?;

    // Remove only our own prior attachment (identified by our state marker),
    // then refuse to stomp on any remaining external XDP program.
    let _ = remove(cfg);
    if interface_xdp_state(iface)?.0 {
        bail!("interface {iface} already has an XDP program; FluxVM will not replace it");
    }

    let root = cfg.pin_root.join("xdp");
    let prog_dir = root.join("progs");
    let map_dir = root.join("maps");
    fs::create_dir_all(&prog_dir)?;
    fs::create_dir_all(&map_dir)?;
    // bpffs cannot store regular files — ownership markers live on a normal fs.
    let meta = xdp_meta_dir();
    fs::create_dir_all(&meta)?;
    fs::write(meta.join("iface"), iface)?;

    let prog = prog_dir.join("fluxvm_xdp_guard");
    let result = (|| -> Result<()> {
        run(
            "bpftool",
            &[
                "prog".into(),
                "load".into(),
                cfg.bpf_object.display().to_string(),
                prog.display().to_string(),
                "type".into(),
                "xdp".into(),
                "pinmaps".into(),
                map_dir.display().to_string(),
            ],
        )?;
        let program_id = pinned_program_id(&prog)?;
        fs::write(meta.join("prog_id"), program_id.to_string())?;

        for cidr in &cfg.block_cidrs {
            let c = parse_ipv4_cidr(cidr)?;
            let mut key = Vec::with_capacity(8);
            key.extend_from_slice(&(c.prefix as u32).to_ne_bytes());
            key.extend_from_slice(&c.network.octets());
            bpftool_map_update(&map_dir.join("fvm_xdp_block4"), &key, &1u32.to_ne_bytes())?;
        }
        run(
            "ip",
            &[
                "link".into(),
                "set".into(),
                "dev".into(),
                iface.into(),
                "xdp".into(),
                "pinned".into(),
                prog.display().to_string(),
            ],
        )?;
        info!(%iface, blocks = cfg.block_cidrs.len(), "attached FluxVM XDP node guard");
        Ok(())
    })();

    if result.is_err() {
        let _ = remove(cfg);
    }
    result
}

pub fn remove(cfg: &XdpConfig) -> Result<()> {
    let root = cfg.pin_root.join("xdp");
    let meta = xdp_meta_dir();
    if !root.exists() && !meta.exists() {
        return Ok(());
    }

    let iface_raw = read_xdp_marker(&meta, &root, "iface")?;
    let iface = iface_raw.trim();
    let owned_id: u32 = read_xdp_marker(&meta, &root, "prog_id")?
        .trim()
        .parse()
        .context("parsing FluxVM XDP program id")?;

    if !iface.is_empty() {
        let (attached, current_id) = interface_xdp_state(iface)?;
        match (attached, current_id) {
            (false, _) => {}
            (true, Some(id)) if id == owned_id => {
                run(
                    "ip",
                    &[
                        "link".into(),
                        "set".into(),
                        "dev".into(),
                        iface.into(),
                        "xdp".into(),
                        "off".into(),
                    ],
                )
                .context("detaching FluxVM-owned XDP program")?;
            }
            (true, Some(id)) => {
                // Another agent replaced us. Never detach it. Our old pinned
                // program can still be safely unpinned below.
                tracing::warn!(
                    %iface,
                    fluxvm_program_id = owned_id,
                    current_program_id = id,
                    "XDP attachment is no longer FluxVM-owned; leaving it untouched"
                );
            }
            (true, None) => {
                bail!(
                    "interface {iface} has XDP attached but its program id cannot be determined; refusing unsafe detach"
                );
            }
        }
    }

    if root.exists() {
        fs::remove_dir_all(&root)
            .with_context(|| format!("removing XDP pin directory {}", root.display()))?;
    }
    if meta.exists() {
        let _ = fs::remove_dir_all(&meta);
    }
    Ok(())
}

fn xdp_meta_dir() -> PathBuf {
    if let Ok(root) = std::env::var("FLUXVM_BPF_META_ROOT") {
        return PathBuf::from(root).join("xdp");
    }
    PathBuf::from("/run/fluxvm/xdp")
}

fn read_xdp_marker(meta: &Path, pin_root: &Path, name: &str) -> Result<String> {
    let meta_path = meta.join(name);
    if meta_path.exists() {
        return fs::read_to_string(&meta_path)
            .with_context(|| format!("reading XDP ownership marker {}", meta_path.display()));
    }
    let legacy = pin_root.join(name);
    fs::read_to_string(&legacy)
        .with_context(|| format!("reading XDP ownership marker {}", legacy.display()))
}

/// Returns `(attached, program_id)`. Modern iproute2 emits
/// `xdp.prog.id`; older releases may expose `prog_id`.
fn interface_xdp_state(iface: &str) -> Result<(bool, Option<u32>)> {
    let out = Command::new("ip")
        .args(["-j", "-d", "link", "show", "dev", iface])
        .output()
        .context("querying link XDP state")?;
    if !out.status.success() {
        bail!(
            "ip link show {iface} failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    let value: Value = serde_json::from_slice(&out.stdout).context("parsing ip -j link output")?;
    let Some(xdp) = value
        .as_array()
        .and_then(|a| a.first())
        .and_then(|v| v.get("xdp"))
        .filter(|v| !v.is_null())
    else {
        return Ok((false, None));
    };

    let id = xdp
        .get("prog")
        .and_then(|p| p.get("id"))
        .and_then(Value::as_u64)
        .or_else(|| xdp.get("prog_id").and_then(Value::as_u64))
        .and_then(|n| u32::try_from(n).ok());
    let attached = id.is_some()
        || xdp.get("attached").is_some()
        || xdp.get("mode").is_some()
        || xdp.as_object().is_some_and(|o| !o.is_empty());
    Ok((attached, id))
}

fn pinned_program_id(path: &Path) -> Result<u32> {
    let out = Command::new("bpftool")
        .args(["-j", "prog", "show", "pinned"])
        .arg(path)
        .output()
        .context("querying pinned XDP program")?;
    if !out.status.success() {
        bail!(
            "bpftool prog show pinned {} failed: {}",
            path.display(),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    let json: Value =
        serde_json::from_slice(&out.stdout).context("parsing bpftool program JSON")?;
    let object = if let Some(array) = json.as_array() {
        array
            .first()
            .context("bpftool returned an empty program array")?
    } else {
        &json
    };
    let id = object
        .get("id")
        .and_then(Value::as_u64)
        .context("bpftool program JSON is missing id")?;
    u32::try_from(id).context("BPF program id does not fit u32")
}

fn parse_ipv4_cidr(raw: &str) -> Result<Ipv4Cidr> {
    let (ip, prefix) = raw
        .split_once('/')
        .context("XDP CIDR must include /prefix")?;
    let ip: Ipv4Addr = ip.parse()?;
    let prefix: u8 = prefix.parse()?;
    if prefix > 32 {
        bail!("IPv4 prefix must be <= 32");
    }
    let raw = u32::from(ip);
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    Ok(Ipv4Cidr {
        network: Ipv4Addr::from(raw & mask),
        prefix,
    })
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
    args.extend(key.iter().map(|b| format!("{b:02x}")));
    args.push("value".into());
    args.push("hex".into());
    args.extend(value.iter().map(|b| format!("{b:02x}")));
    run("bpftool", &args)
}

fn require_bpftool() -> Result<()> {
    require_version("bpftool", &["version"])
}

fn require_ip() -> Result<()> {
    require_version("ip", &["-V"])
}

fn require_version(name: &str, args: &[&str]) -> Result<()> {
    match Command::new(name).args(args).status() {
        Ok(s) if s.success() => Ok(()),
        Ok(s) => bail!("{} {} exited with {s}", name, args.join(" ")),
        Err(e) => Err(e).with_context(|| format!("{name} is required")),
    }
}

fn run(program: &str, args: &[String]) -> Result<()> {
    let out = Command::new(program).args(args).output()?;
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
    fn cidr_normalization() {
        let c = parse_ipv4_cidr("198.51.100.99/24").unwrap();
        assert_eq!(c.network, Ipv4Addr::new(198, 51, 100, 0));
        assert_eq!(c.prefix, 24);
    }

    #[test]
    fn modern_iproute2_xdp_shape_is_understood() {
        let json = serde_json::json!({"xdp":{"mode":2,"prog":{"id":77,"name":"guard"}}});
        let xdp = &json["xdp"];
        let id = xdp
            .get("prog")
            .and_then(|p| p.get("id"))
            .and_then(Value::as_u64);
        assert_eq!(id, Some(77));
    }
}
