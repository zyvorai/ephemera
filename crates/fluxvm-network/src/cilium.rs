// Copyright 2026 Zyvor
// SPDX-License-Identifier: Apache-2.0

//! Safe Cilium coexistence checks.
//!
//! FluxVM intentionally does not write Cilium's private BPF maps. In
//! `dataplane.mode = "cilium"`, Cilium remains the Kubernetes/node CNI and
//! FluxVM attaches its own per-VM TC program only to the VM-edge interface,
//! pinning maps under `/sys/fs/bpf/fluxvm`. This avoids depending on Cilium
//! internal map layouts while allowing both dataplanes to coexist.

use anyhow::{Context, Result, bail};
use std::path::Path;

pub fn validate_host() -> Result<()> {
    let socket = Path::new("/var/run/cilium/cilium.sock");
    if !socket.exists() {
        bail!(
            "Cilium coexistence mode requested but {} is not visible; mount /var/run/cilium into the FluxVM container or install Cilium on the host",
            socket.display()
        );
    }

    let bpffs = Path::new("/sys/fs/bpf");
    if !bpffs.exists() {
        bail!("Cilium coexistence mode requires bpffs at /sys/fs/bpf");
    }

    std::fs::metadata(bpffs).with_context(|| format!("reading {} metadata", bpffs.display()))?;
    Ok(())
}
