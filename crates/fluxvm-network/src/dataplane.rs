// Copyright 2026 Zyvor
// SPDX-License-Identifier: Apache-2.0
//! Per-sandbox nftables dataplane: SNAT + optional domain-derived IP allow
//! hooks. Full eBPF (TC) programs are optional on Linux when `bpf` tooling
//! is present; nftables is the always-available path.

use anyhow::{Context, Result};
use std::process::Command;
use tracing::{info, warn};
use uuid::Uuid;

/// Install a basic per-sandbox egress table that masquerades traffic from
/// `guest_cidr` and optionally drops non-allowlisted destinations when
/// `allow_cidrs` is non-empty.
/// Install POSTROUTING masquerade for traffic sourced from `source_cidr`.
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

pub fn apply_sandbox_policy(id: Uuid, guest_cidr: &str, allow_cidrs: &[String]) -> Result<()> {
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
        // Always allow established/related return traffic.
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
    let _ = try_load_ebpf_hint(id);
    Ok(())
}

pub fn remove_sandbox_policy(id: Uuid) -> Result<()> {
    remove_nft_table(&format!("fluxvm_{}", id.simple()))
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

/// Optional eBPF/TC attach — runs `scripts/load-sandbox-tc.sh` when found,
/// otherwise logs when `bpftool` is available.
fn try_load_ebpf_hint(id: Uuid) -> Result<()> {
    if let Some(script) = find_tc_script() {
        match Command::new("sh").arg(&script).arg(id.to_string()).status() {
            Ok(s) if s.success() => {
                info!(%id, script = %script.display(), "loaded sandbox TC stub");
                return Ok(());
            }
            Ok(s) => warn!(%id, code = ?s.code(), "load-sandbox-tc.sh exited non-zero"),
            Err(e) => warn!(%id, error = %e, "failed to run load-sandbox-tc.sh"),
        }
    }
    let status = Command::new("bpftool").args(["version"]).status();
    match status {
        Ok(s) if s.success() => {
            info!(%id, "bpftool present — eBPF TC filters can be layered on sandbox TAPs");
        }
        _ => {}
    }
    Ok(())
}

fn find_tc_script() -> Option<std::path::PathBuf> {
    if let Ok(dir) = std::env::var("FLUXVM_SCRIPTS_DIR") {
        let p = std::path::PathBuf::from(dir).join("load-sandbox-tc.sh");
        if p.exists() {
            return Some(p);
        }
    }
    for p in [
        std::path::PathBuf::from("scripts/load-sandbox-tc.sh"),
        std::path::PathBuf::from("/usr/share/fluxvm/scripts/load-sandbox-tc.sh"),
    ] {
        if p.exists() {
            return Some(p);
        }
    }
    None
}
