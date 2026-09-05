// Copyright 2026 Zyvor
// SPDX-License-Identifier: Apache-2.0
//! Per-sandbox dataplane dispatch.
//!
//! `legacy` keeps the existing nftables path. `ebpf` attaches FluxVM's
//! native TC classifier. `cilium` validates that a Cilium node dataplane is
//! present and then attaches the same VM-edge classifier in FluxVM's own BPF
//! pin namespace, without touching Cilium private maps.

use anyhow::{Context, Result};
use fluxvm_core::config::{Config, DataplaneMode};
use std::process::Command;
use tracing::{info, warn};
use uuid::Uuid;

pub fn apply_sandbox_policy(
    cfg: &Config,
    id: Uuid,
    iface: Option<&str>,
    guest_cidr: &str,
    allow_cidrs: &[String],
) -> Result<()> {
    let dp = &cfg.sandbox.dataplane;
    let mut effective_allow = dp.allow_cidrs.clone();
    effective_allow.extend_from_slice(allow_cidrs);
    effective_allow.sort();
    effective_allow.dedup();

    match dp.mode {
        DataplaneMode::Legacy => apply_nftables(id, guest_cidr, &effective_allow),
        DataplaneMode::Ebpf | DataplaneMode::Cilium => {
            let native = (|| -> Result<()> {
                if dp.mode == DataplaneMode::Cilium {
                    crate::cilium::validate_host()?;
                }
                let iface = iface.context("eBPF dataplane needs a host-visible VM interface")?;
                crate::ebpf::apply(dp, id, iface, &effective_allow)
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
                    apply_nftables(id, guest_cidr, &effective_allow)
                }
            }
        }
    }
}

pub fn remove_sandbox_policy(id: Uuid) -> Result<()> {
    let _ = remove_nft_table(&format!("fluxvm_{}", id.simple()));
    if let Err(e) = crate::ebpf::remove(id) {
        warn!(%id, error = %e, "eBPF dataplane cleanup failed");
    }
    Ok(())
}

/// Install POSTROUTING masquerade for traffic sourced from `source_cidr`.
/// Used by netns IPAM NAT (`fluxvm_netns_*` tables) independent of sandbox mode.
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

fn apply_nftables(id: Uuid, guest_cidr: &str, allow_cidrs: &[String]) -> Result<()> {
    let table = format!("fluxvm_{}", id.simple());
    apply_subnet_masquerade(&table, guest_cidr)?;

    if !allow_cidrs.is_empty() {
        run_nft(&[
            "add", "chain", "inet", &table, "forward", "{", "type", "filter", "hook", "forward",
            "priority", "filter;", "policy", "drop;", "}",
        ])?;
        for cidr in allow_cidrs {
            run_nft(&[
                "add", "rule", "inet", &table, "forward", "ip", "saddr", guest_cidr, "ip", "daddr",
                cidr, "accept",
            ])?;
        }
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

    info!(%id, %guest_cidr, allows = allow_cidrs.len(), "applied nftables sandbox policy");
    Ok(())
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
            String::from_utf8_lossy(&out.stderr)
        );
    }
    Ok(())
}
