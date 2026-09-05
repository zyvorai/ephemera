// Copyright 2026 Zyvor
// SPDX-License-Identifier: Apache-2.0

//! VM dataplane dispatch, policy persistence, and observability.
//!
//! `legacy` keeps nftables. `ebpf` uses FluxVM-owned TC programs/maps.
//! `cilium` keeps Cilium as the node/Kubernetes dataplane while FluxVM owns
//! only the VM-edge TC program and its private `/sys/fs/bpf/fluxvm` pins.

use anyhow::{Context, Result};
use fluxvm_core::config::{Config, DataplaneMode};
use serde::{Deserialize, Serialize};
use std::{fs, path::PathBuf, process::Command};
use tracing::{info, warn};
use uuid::Uuid;

pub use crate::ebpf::{DataplaneStats, FlowRecord};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct VmNetworkPolicy {
    /// Action when no CIDR/L4 allowlist is configured. Once either allowlist
    /// is non-empty it becomes an explicit allowlist and unmatched traffic
    /// is denied, regardless of this value.
    pub default_allow: bool,
    pub allow_cidrs: Vec<String>,
    /// Entries are `tcp/443`, `udp/53`, etc. If CIDRs and ports are both
    /// configured, a packet must match both dimensions.
    pub allow_ports: Vec<String>,
    /// 0 disables allow-event sampling. N emits about 1/N allowed packets
    /// to the BPF ring buffer; drop flows are always represented in maps.
    pub sample_rate: u32,
}

impl Default for VmNetworkPolicy {
    fn default() -> Self {
        Self {
            default_allow: true,
            allow_cidrs: Vec::new(),
            allow_ports: Vec::new(),
            sample_rate: 0,
        }
    }
}

pub fn default_policy(cfg: &Config) -> VmNetworkPolicy {
    let dp = &cfg.sandbox.dataplane;
    VmNetworkPolicy {
        default_allow: dp.default_allow,
        allow_cidrs: dp.allow_cidrs.clone(),
        allow_ports: dp.allow_ports.clone(),
        sample_rate: dp.sample_rate,
    }
}

pub fn effective_policy(cfg: &Config, id: Uuid) -> Result<VmNetworkPolicy> {
    Ok(load_policy(cfg, id)?.unwrap_or_else(|| default_policy(cfg)))
}

pub fn load_policy(cfg: &Config, id: Uuid) -> Result<Option<VmNetworkPolicy>> {
    let path = policy_path(cfg, id);
    if !path.exists() {
        return Ok(None);
    }
    let raw = fs::read_to_string(&path)
        .with_context(|| format!("reading VM network policy {}", path.display()))?;
    let policy: VmNetworkPolicy = serde_json::from_str(&raw)
        .with_context(|| format!("parsing VM network policy {}", path.display()))?;
    crate::ebpf::validate_policy(&policy)?;
    Ok(Some(policy))
}

pub fn save_policy(cfg: &Config, id: Uuid, policy: &VmNetworkPolicy) -> Result<()> {
    crate::ebpf::validate_policy(policy)?;
    let path = policy_path(cfg, id);
    let parent = path.parent().context("network policy path has no parent")?;
    fs::create_dir_all(parent)
        .with_context(|| format!("creating network policy directory {}", parent.display()))?;
    let tmp = path.with_extension("json.tmp");
    fs::write(&tmp, serde_json::to_vec_pretty(policy)?)
        .with_context(|| format!("writing temporary network policy {}", tmp.display()))?;
    fs::rename(&tmp, &path)
        .with_context(|| format!("committing network policy {}", path.display()))?;
    Ok(())
}

pub fn delete_policy(cfg: &Config, id: Uuid) -> Result<()> {
    let path = policy_path(cfg, id);
    match fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e).with_context(|| format!("deleting network policy {}", path.display())),
    }
}

fn policy_path(cfg: &Config, id: Uuid) -> PathBuf {
    cfg.state_dir
        .join("network-policy")
        .join(format!("{id}.json"))
}

pub fn apply_sandbox_policy(
    cfg: &Config,
    id: Uuid,
    iface: Option<&str>,
    guest_cidr: &str,
    extra_allow_cidrs: &[String],
) -> Result<()> {
    let dp = &cfg.sandbox.dataplane;
    let mut policy = effective_policy(cfg, id)?;
    policy.allow_cidrs.extend_from_slice(extra_allow_cidrs);
    policy.allow_cidrs.sort();
    policy.allow_cidrs.dedup();

    match dp.mode {
        DataplaneMode::Legacy => apply_nftables(id, guest_cidr, &policy),
        DataplaneMode::Ebpf | DataplaneMode::Cilium => {
            let native = (|| -> Result<()> {
                if dp.mode == DataplaneMode::Cilium {
                    crate::cilium::validate_host()?;
                }
                let iface = iface.context("eBPF dataplane needs a host-visible VM interface")?;
                crate::ebpf::apply(dp, &policy, id, iface)
            })();

            match native {
                Ok(()) => Ok(()),
                Err(e) if dp.required => Err(e),
                Err(e) => {
                    warn!(
                        %id,
                        error = %e,
                        "native eBPF dataplane unavailable; falling back to nftables"
                    );
                    apply_nftables(id, guest_cidr, &policy)
                }
            }
        }
    }
}

pub fn remove_sandbox_policy(cfg: &Config, id: Uuid) -> Result<()> {
    remove_nftables(id);
    if let Err(e) = crate::ebpf::remove(&cfg.sandbox.dataplane, id) {
        warn!(%id, error = %e, "eBPF dataplane cleanup failed");
    }
    Ok(())
}

/// Used by low-level network teardown which historically has no Config
/// argument. Scheduler paths perform config-aware cleanup first.
pub fn remove_sandbox_policy_best_effort(id: Uuid) -> Result<()> {
    remove_nftables(id);
    let _ = crate::ebpf::remove_best_effort(id);
    Ok(())
}

pub fn stats(cfg: &Config, id: Uuid) -> Result<DataplaneStats> {
    ensure_native_mode(cfg)?;
    crate::ebpf::stats(&cfg.sandbox.dataplane, id)
}

pub fn flows(cfg: &Config, id: Uuid, limit: usize) -> Result<Vec<FlowRecord>> {
    ensure_native_mode(cfg)?;
    crate::ebpf::flows(&cfg.sandbox.dataplane, id, limit)
}

fn ensure_native_mode(cfg: &Config) -> Result<()> {
    if cfg.sandbox.dataplane.mode == DataplaneMode::Legacy {
        anyhow::bail!("network stats/flows require sandbox.dataplane.mode=ebpf or cilium");
    }
    Ok(())
}

/// Install POSTROUTING masquerade for a source subnet. Kept public because
/// `netns.rs` uses it for the namespace transport NAT table independently
/// of the per-VM security policy table.
pub fn apply_subnet_masquerade(table: &str, source_cidr: &str) -> Result<()> {
    let _ = run_nft(&["delete", "table", "inet", table]);
    run_nft(&["add", "table", "inet", table])?;
    run_nft(&[
        "add",
        "chain",
        "inet",
        table,
        "postrouting",
        "{",
        "type",
        "nat",
        "hook",
        "postrouting",
        "priority",
        "srcnat;",
        "}",
    ])?;
    run_nft(&[
        "add",
        "rule",
        "inet",
        table,
        "postrouting",
        "ip",
        "saddr",
        source_cidr,
        "masquerade",
    ])?;
    Ok(())
}

fn apply_nftables(id: Uuid, guest_cidr: &str, policy: &VmNetworkPolicy) -> Result<()> {
    let table = format!("fluxvm_{}", id.simple());
    apply_subnet_masquerade(&table, guest_cidr)?;

    let has_cidrs = !policy.allow_cidrs.is_empty();
    let has_ports = !policy.allow_ports.is_empty();
    let enforce = has_cidrs || has_ports || !policy.default_allow;
    if enforce {
        run_nft(&[
            "add", "chain", "inet", &table, "forward", "{", "type", "filter", "hook", "forward",
            "priority", "filter;", "policy", "drop;", "}",
        ])?;

        match (has_cidrs, has_ports) {
            (true, true) => {
                for cidr in &policy.allow_cidrs {
                    for rule in &policy.allow_ports {
                        let (proto, port) = parse_nft_port_rule(rule)?;
                        let port = port.to_string();
                        run_nft(&[
                            "add", "rule", "inet", &table, "forward", "ip", "saddr", guest_cidr,
                            "ip", "daddr", cidr, proto, "dport", &port, "accept",
                        ])?;
                    }
                }
            }
            (true, false) => {
                for cidr in &policy.allow_cidrs {
                    run_nft(&[
                        "add", "rule", "inet", &table, "forward", "ip", "saddr", guest_cidr, "ip",
                        "daddr", cidr, "accept",
                    ])?;
                }
            }
            (false, true) => {
                for rule in &policy.allow_ports {
                    let (proto, port) = parse_nft_port_rule(rule)?;
                    let port = port.to_string();
                    run_nft(&[
                        "add", "rule", "inet", &table, "forward", "ip", "saddr", guest_cidr, proto,
                        "dport", &port, "accept",
                    ])?;
                }
            }
            (false, false) => {}
        }

        if has_cidrs || has_ports {
            run_nft(&[
                "add",
                "rule",
                "inet",
                &table,
                "forward",
                "ct",
                "state",
                "established,related",
                "accept",
            ])?;
        }
    }

    info!(
        %id,
        %guest_cidr,
        cidrs = policy.allow_cidrs.len(),
        ports = policy.allow_ports.len(),
        default_allow = policy.default_allow,
        "applied nftables sandbox policy"
    );
    Ok(())
}

fn parse_nft_port_rule(raw: &str) -> Result<(&'static str, u16)> {
    let (proto, port) = raw
        .split_once('/')
        .with_context(|| format!("port rule {raw:?} must be tcp/PORT or udp/PORT"))?;
    let proto = match proto.trim().to_ascii_lowercase().as_str() {
        "tcp" => "tcp",
        "udp" => "udp",
        other => anyhow::bail!("unsupported L4 protocol {other:?}; use tcp or udp"),
    };
    let port: u16 = port.trim().parse()?;
    if port == 0 {
        anyhow::bail!("port must be 1..65535");
    }
    Ok((proto, port))
}

fn remove_nftables(id: Uuid) {
    let table = format!("fluxvm_{}", id.simple());
    let _ = remove_nft_table(&table);
}

pub fn remove_nft_table(table: &str) -> Result<()> {
    match run_nft(&["delete", "table", "inet", table]) {
        Ok(()) => Ok(()),
        Err(e) => {
            warn!(%table, error = %e, "nftables table delete (may not exist)");
            Ok(())
        }
    }
}

pub fn run_nft(args: &[&str]) -> Result<()> {
    let out = Command::new("nft")
        .args(args)
        .output()
        .context("running nft (install nftables)")?;
    if !out.status.success() {
        anyhow::bail!(
            "nft {} failed: {}",
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
    fn default_policy_is_permissive() {
        let p = VmNetworkPolicy::default();
        assert!(p.default_allow);
        assert!(p.allow_cidrs.is_empty());
        assert!(p.allow_ports.is_empty());
    }

    #[test]
    fn policy_round_trip_is_atomic_and_validated() {
        let tmp = tempfile::tempdir().unwrap();
        let mut cfg = Config::default();
        cfg.state_dir = tmp.path().to_path_buf();
        let id = Uuid::new_v4();
        let policy = VmNetworkPolicy {
            default_allow: false,
            allow_cidrs: vec!["10.0.0.0/8".into()],
            allow_ports: vec!["tcp/443".into()],
            sample_rate: 10,
        };
        save_policy(&cfg, id, &policy).unwrap();
        assert_eq!(load_policy(&cfg, id).unwrap(), Some(policy.clone()));
        delete_policy(&cfg, id).unwrap();
        assert_eq!(load_policy(&cfg, id).unwrap(), None);
    }

    #[test]
    fn bad_l4_policy_is_rejected_before_persist() {
        let tmp = tempfile::tempdir().unwrap();
        let mut cfg = Config::default();
        cfg.state_dir = tmp.path().to_path_buf();
        let id = Uuid::new_v4();
        let policy = VmNetworkPolicy {
            allow_ports: vec!["sctp/443".into()],
            ..VmNetworkPolicy::default()
        };
        assert!(save_policy(&cfg, id, &policy).is_err());
        assert!(!policy_path(&cfg, id).exists());
    }
}
