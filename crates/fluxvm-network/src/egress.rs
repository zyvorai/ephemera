// Copyright 2026 Zyvor
// SPDX-License-Identifier: Apache-2.0
//! Egress allowlist + credential vault helpers for FluxVm sandboxes.

use fluxvm_core::config::{CredentialInject, SandboxConfig};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EgressDecision {
    pub allow: bool,
    pub inject_authorization: Option<String>,
    pub reason: String,
}

/// Decide whether an outbound HTTP(S) request to `host` is allowed and whether
/// to inject a vault credential. Empty allowlist = allow all (no L7 filter).
pub fn decide(cfg: &SandboxConfig, host: &str) -> EgressDecision {
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    let inject = cfg
        .credential_vault
        .iter()
        .find(|c| host_matches(&c.host, &host))
        .map(|c| c.authorization.clone());

    if cfg.egress_allow_domains.is_empty() {
        return EgressDecision {
            allow: true,
            inject_authorization: inject,
            reason: "no allowlist configured".into(),
        };
    }
    let allowed = cfg.egress_allow_domains.iter().any(|d| host_matches(d, &host));
    EgressDecision {
        allow: allowed,
        inject_authorization: if allowed { inject } else { None },
        reason: if allowed {
            "host matched allowlist".into()
        } else {
            format!("host {host} not in egress allowlist")
        },
    }
}

fn host_matches(pattern: &str, host: &str) -> bool {
    let p = pattern.trim().trim_start_matches('.').to_ascii_lowercase();
    host == p || host.ends_with(&format!(".{p}"))
}

/// Render nftables snippets that DNAT egress through a local L7 proxy port.
pub fn nftables_redirect_snippet(proxy_port: u16) -> String {
    format!(
        "table inet fluxvm_egress {{\n  chain output {{\n    type nat hook output priority -100;\n    meta skuid != 0 tcp dport {{ 80, 443 }} redirect to :{proxy_port}\n  }}\n}}\n"
    )
}

/// Evaluate vault entries for documentation / API.
pub fn vault_hosts(cfg: &SandboxConfig) -> Vec<&CredentialInject> {
    cfg.credential_vault.iter().collect()
}
