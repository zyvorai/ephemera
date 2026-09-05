// Copyright 2026 Zyvor
// SPDX-License-Identifier: Apache-2.0

//! FluxVM-owned TC/eBPF dataplane loader and observability reader.
//!
//! The kernel programs live in `bpf/`.  The daemon intentionally uses
//! `bpftool` + `tc` rather than linking libbpf into every FluxVM binary: the
//! normal Rust dependency graph stays small and distro packages provide the
//! privileged kernel plumbing.  Each VM gets its own pin directory.

use anyhow::{Context, Result, bail};
use fluxvm_core::config::DataplaneConfig;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    fs,
    net::Ipv4Addr,
    path::{Path, PathBuf},
    process::Command,
};
use tracing::info;
use uuid::Uuid;

use crate::dataplane::VmNetworkPolicy;

const TC_PRIORITY: &str = "49152";
const TC_HANDLE: &str = "1";
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Ipv4Cidr {
    network: Ipv4Addr,
    prefix: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PortRule {
    protocol: u8,
    port: u16,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct DataplaneStats {
    pub allowed_packets: u64,
    pub allowed_bytes: u64,
    pub dropped_packets: u64,
    pub dropped_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FlowRecord {
    pub identity: u32,
    pub source: Ipv4Addr,
    pub destination: Ipv4Addr,
    pub source_port: u16,
    pub destination_port: u16,
    pub protocol: u8,
    pub verdict: String,
    pub packets: u64,
    pub bytes: u64,
    pub last_seen_ns: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NativeAttachmentStatus {
    pub attached: bool,
    pub interface: Option<String>,
    pub identity: u32,
    pub pin_dir: String,
}

pub fn apply(cfg: &DataplaneConfig, policy: &VmNetworkPolicy, id: Uuid, iface: &str) -> Result<()> {
    if iface.is_empty() {
        bail!("cannot attach eBPF dataplane without a host-visible interface");
    }
    if !cfg.bpf_object.exists() {
        bail!(
            "FluxVM eBPF object does not exist at {}",
            cfg.bpf_object.display()
        );
    }
    require_bpftool()?;
    require_tc()?;
    raise_memlock()?;

    validate_policy(policy)?;
    let _ = remove(cfg, id);

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
    if let Err(e) = run(
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
    ) {
        let _ = fs::remove_dir_all(&vm_dir);
        let _ = fs::remove_dir_all(&meta_dir);
        return Err(e).context("loading FluxVM TC program");
    }

    let attach = (|| -> Result<()> {
        ensure_clsact(iface).context("installing clsact qdisc")?;
        // `add`, not `replace`: if another component already owns this
        // reserved pref/handle, fail closed instead of overwriting it.
        run(
            "tc",
            &[
                "filter".into(),
                "add".into(),
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
        configure_maps(&map_dir, ifindex, identity, policy, false)?;

        info!(
            %id,
            %iface,
            identity,
            default_allow = policy.default_allow,
            cidrs = policy.allow_cidrs.len(),
            ports = policy.allow_ports.len(),
            max_egress_mbps = ?policy.max_egress_mbps,
            max_egress_pps = ?policy.max_egress_pps,
            sample_rate = policy.sample_rate,
            "attached FluxVM native eBPF dataplane"
        );
        Ok(())
    })();

    if attach.is_err() {
        let _ = remove(cfg, id);
    }
    attach
}

pub fn remove(cfg: &DataplaneConfig, id: Uuid) -> Result<()> {
    remove_vm_dir(&vm_pin_dir(&cfg.pin_root, id), id)?;
    let meta = vm_meta_dir(id);
    if meta.exists() {
        let _ = fs::remove_dir_all(&meta);
    }
    Ok(())
}

/// Update a running VM in place. The TC program stays attached for the whole
/// operation. We first switch its interface config to deny-all, then replace
/// policy maps, then publish the final config. A failed update therefore
/// creates at worst a short over-deny window, never an allow-all gap.
pub fn reconfigure(cfg: &DataplaneConfig, policy: &VmNetworkPolicy, id: Uuid) -> Result<()> {
    require_bpftool()?;
    require_tc()?;
    validate_policy(policy)?;
    let vm_dir = vm_pin_dir(&cfg.pin_root, id);
    let map_dir = vm_dir.join("maps");
    let prog_pin = vm_dir.join("progs/fluxvm_egress");
    if !prog_pin.exists() {
        bail!("FluxVM eBPF program is not attached for VM {id}");
    }
    let iface = read_recorded_iface(id).context("reading VM eBPF interface marker")?;
    let ifindex = read_ifindex(&iface)?;
    let identity = identity_for(id);
    configure_maps(&map_dir, ifindex, identity, policy, true)?;
    info!(
        %id,
        %iface,
        identity,
        cidrs = policy.allow_cidrs.len(),
        ports = policy.allow_ports.len(),
        max_egress_mbps = ?policy.max_egress_mbps,
        max_egress_pps = ?policy.max_egress_pps,
        "updated FluxVM eBPF policy in place"
    );
    Ok(())
}

pub fn attachment_status(cfg: &DataplaneConfig, id: Uuid) -> Result<NativeAttachmentStatus> {
    let vm_dir = vm_pin_dir(&cfg.pin_root, id);
    let iface = read_recorded_iface(id);
    let prog_pin = vm_dir.join("progs/fluxvm_egress");
    let attached = if let Some(iface) = iface.as_deref() {
        prog_pin.exists() && tc_filter_attached(iface).unwrap_or(false)
    } else {
        false
    };
    Ok(NativeAttachmentStatus {
        attached,
        interface: iface,
        identity: identity_for(id),
        pin_dir: vm_dir.display().to_string(),
    })
}

/// Cleanup fallback for callers that do not have Config. Config-aware
/// scheduler paths call `remove()`; this catches the normal default and an
/// operator-supplied environment override after crashes/partial failures.
pub fn remove_best_effort(id: Uuid) -> Result<()> {
    let mut dirs = vec![vm_pin_dir(Path::new("/sys/fs/bpf/fluxvm"), id)];
    if let Ok(root) = std::env::var("FLUXVM_BPF_PIN_ROOT") {
        let p = vm_pin_dir(Path::new(&root), id);
        if !dirs.contains(&p) {
            dirs.push(p);
        }
    }
    for dir in dirs {
        let _ = remove_vm_dir(&dir, id);
    }
    let meta = vm_meta_dir(id);
    if meta.exists() {
        let _ = fs::remove_dir_all(&meta);
    }
    Ok(())
}

fn remove_vm_dir(vm_dir: &Path, id: Uuid) -> Result<()> {
    if let Some(iface) = read_recorded_iface(id) {
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
                "handle".into(),
                TC_HANDLE.into(),
                "bpf".into(),
            ],
        );
    }
    if vm_dir.exists() {
        fs::remove_dir_all(vm_dir)
            .with_context(|| format!("removing eBPF pin dir {}", vm_dir.display()))?;
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
    // Legacy path from builds that attempted to store iface on bpffs.
    for root in [
        PathBuf::from("/sys/fs/bpf/fluxvm"),
        std::env::var("FLUXVM_BPF_PIN_ROOT")
            .ok()
            .map(PathBuf::from)
            .unwrap_or_default(),
    ] {
        if root.as_os_str().is_empty() {
            continue;
        }
        if let Ok(iface) = fs::read_to_string(vm_pin_dir(&root, id).join("iface")) {
            let iface = iface.trim();
            if !iface.is_empty() {
                return Some(iface.to_string());
            }
        }
    }
    None
}

fn vm_meta_dir(id: Uuid) -> PathBuf {
    if let Ok(root) = std::env::var("FLUXVM_BPF_META_ROOT") {
        return PathBuf::from(root)
            .join("vms")
            .join(id.simple().to_string());
    }
    PathBuf::from("/run/fluxvm/ebpf/vms").join(id.simple().to_string())
}

pub fn stats(cfg: &DataplaneConfig, id: Uuid) -> Result<DataplaneStats> {
    let map = vm_pin_dir(&cfg.pin_root, id).join("maps/fluxvm_stats");
    let json = bpftool_json_dump(&map)?;
    parse_stats_json(&json)
}

pub fn flows(cfg: &DataplaneConfig, id: Uuid, limit: usize) -> Result<Vec<FlowRecord>> {
    let map = vm_pin_dir(&cfg.pin_root, id).join("maps/fluxvm_flows");
    let json = bpftool_json_dump(&map)?;
    let mut records = parse_flows_json(&json)?;
    records.sort_by(|a, b| b.last_seen_ns.cmp(&a.last_seen_ns));
    records.truncate(limit.clamp(1, 4096));
    Ok(records)
}

pub fn validate_policy(policy: &VmNetworkPolicy) -> Result<()> {
    for cidr in &policy.allow_cidrs {
        parse_ipv4_cidr(cidr).with_context(|| format!("invalid eBPF allow CIDR {cidr:?}"))?;
    }
    for rule in &policy.allow_ports {
        parse_port_rule(rule).with_context(|| format!("invalid eBPF L4 rule {rule:?}"))?;
    }
    if let Some(mbps) = policy.max_egress_mbps {
        let _ = mbps_to_bytes_per_second(mbps)?;
    }
    if policy.max_egress_pps == Some(0) {
        bail!("max_egress_pps must be greater than zero when set");
    }
    Ok(())
}

fn vm_pin_dir(root: &Path, id: Uuid) -> PathBuf {
    root.join("vms").join(id.simple().to_string())
}

pub fn identity_for(id: Uuid) -> u32 {
    // Mix all 128 UUID bits down to a stable non-zero u32. Map state is
    // private per VM, so this identity is primarily useful in telemetry and
    // survives interface recreation without relying on ifindex/IP.
    let n = id.as_u128();
    let raw = (n as u32) ^ ((n >> 32) as u32) ^ ((n >> 64) as u32) ^ ((n >> 96) as u32);
    raw.max(1)
}

fn read_ifindex(iface: &str) -> Result<u32> {
    let raw = fs::read_to_string(format!("/sys/class/net/{iface}/ifindex"))
        .with_context(|| format!("reading ifindex for {iface}"))?;
    raw.trim()
        .parse::<u32>()
        .with_context(|| format!("parsing ifindex for {iface}"))
}

fn configure_maps(
    map_dir: &Path,
    ifindex: u32,
    identity: u32,
    policy: &VmNetworkPolicy,
    fail_closed_first: bool,
) -> Result<()> {
    let id_map = map_dir.join("fluxvm_id");
    let cidr_map = map_dir.join("fluxvm_v4");
    let l4_map = map_dir.join("fluxvm_l4");
    let rate_map = map_dir.join("fluxvm_rate");

    if fail_closed_first {
        // Publish deny-all first, before deleting any old allowlist keys.
        update_iface_config(&id_map, ifindex, identity, false, false, false, 0, 0, 0)?;
    }

    clear_map(&cidr_map)?;
    clear_map(&l4_map)?;
    clear_map(&rate_map)?;

    for cidr in &policy.allow_cidrs {
        update_ipv4_allow(&cidr_map, identity, parse_ipv4_cidr(cidr)?)?;
    }
    for rule in &policy.allow_ports {
        update_l4_allow(&l4_map, identity, parse_port_rule(rule)?)?;
    }

    let rate_bytes = policy
        .max_egress_mbps
        .map(mbps_to_bytes_per_second)
        .transpose()?
        .unwrap_or(0);
    let rate_packets = policy.max_egress_pps.map(u64::from).unwrap_or(0);
    update_rate_state(&rate_map, identity)?;

    update_iface_config(
        &id_map,
        ifindex,
        identity,
        policy.default_allow,
        !policy.allow_cidrs.is_empty(),
        !policy.allow_ports.is_empty(),
        policy.sample_rate,
        rate_bytes,
        rate_packets,
    )
}

fn update_iface_config(
    map: &Path,
    ifindex: u32,
    identity: u32,
    default_allow: bool,
    enforce_cidr: bool,
    enforce_l4: bool,
    sample_rate: u32,
    rate_bytes_per_sec: u64,
    rate_packets_per_sec: u64,
) -> Result<()> {
    let mut key = Vec::with_capacity(4);
    key.extend_from_slice(&ifindex.to_ne_bytes());

    // Must match struct iface_config in bpf/fluxvm_tc.bpf.c exactly:
    // 6 x u32 followed by 2 x u64.
    let mut value = Vec::with_capacity(40);
    value.extend_from_slice(&identity.to_ne_bytes());
    value.extend_from_slice(&(default_allow as u32).to_ne_bytes());
    value.extend_from_slice(&(enforce_cidr as u32).to_ne_bytes());
    value.extend_from_slice(&(enforce_l4 as u32).to_ne_bytes());
    value.extend_from_slice(&sample_rate.to_ne_bytes());
    value.extend_from_slice(&0u32.to_ne_bytes());
    value.extend_from_slice(&rate_bytes_per_sec.to_ne_bytes());
    value.extend_from_slice(&rate_packets_per_sec.to_ne_bytes());
    bpftool_map_update(map, &key, &value)
}

fn update_rate_state(map: &Path, identity: u32) -> Result<()> {
    // struct rate_state = bpf_spin_lock (u32), pad (u32), then three u64s.
    let key = identity.to_ne_bytes();
    let value = [0u8; 32];
    bpftool_map_update(map, &key, &value)
}

fn mbps_to_bytes_per_second(mbps: u32) -> Result<u64> {
    if mbps == 0 {
        bail!("max_egress_mbps must be greater than zero when set");
    }
    u64::from(mbps)
        .checked_mul(1_000_000)
        .map(|bits| bits / 8)
        .context("max_egress_mbps is too large")
}

fn clear_map(map: &Path) -> Result<()> {
    let root = bpftool_json_dump(map)?;
    let entries = root
        .as_array()
        .context("bpftool map dump must be an array")?;
    for entry in entries {
        let key = json_bytes(&entry["key"])?;
        let mut args = vec![
            "map".into(),
            "delete".into(),
            "pinned".into(),
            map.display().to_string(),
            "key".into(),
            "hex".into(),
        ];
        args.extend(hex_args(&key));
        run("bpftool", &args)?;
    }
    Ok(())
}

fn update_ipv4_allow(map: &Path, identity: u32, cidr: Ipv4Cidr) -> Result<()> {
    let lpm_prefix = 32u32 + u32::from(cidr.prefix);
    let mut key = Vec::with_capacity(12);
    key.extend_from_slice(&lpm_prefix.to_ne_bytes());
    key.extend_from_slice(&identity.to_ne_bytes());
    // iph->daddr is network order in packet memory, so octets are the
    // correct map-key bytes regardless of host endianness.
    key.extend_from_slice(&cidr.network.octets());
    bpftool_map_update(map, &key, &1u32.to_ne_bytes())
}

fn update_l4_allow(map: &Path, identity: u32, rule: PortRule) -> Result<()> {
    let mut key = Vec::with_capacity(8);
    key.extend_from_slice(&identity.to_ne_bytes());
    key.extend_from_slice(&rule.port.to_ne_bytes());
    key.push(rule.protocol);
    key.push(0);
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

fn bpftool_json_dump(map: &Path) -> Result<Value> {
    if !map.exists() {
        bail!("FluxVM eBPF map is not pinned at {}", map.display());
    }
    let out = Command::new("bpftool")
        .args(["-j", "map", "dump", "pinned"])
        .arg(map)
        .output()
        .context("running bpftool map dump")?;
    if !out.status.success() {
        bail!(
            "bpftool map dump pinned {} failed: {}",
            map.display(),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    serde_json::from_slice(&out.stdout).context("parsing bpftool JSON")
}

fn parse_stats_json(root: &Value) -> Result<DataplaneStats> {
    let entries = root
        .as_array()
        .context("bpftool stats JSON must be an array")?;
    let mut out = DataplaneStats::default();
    for entry in entries {
        let key = json_bytes(&entry["key"])?;
        if key.len() < 8 {
            continue;
        }
        let verdict = u32::from_ne_bytes(key[4..8].try_into().unwrap());

        let mut packets = 0u64;
        let mut bytes = 0u64;
        if let Some(values) = entry.get("values").and_then(Value::as_array) {
            for cpu in values {
                let raw = json_bytes(&cpu["value"])?;
                if raw.len() >= 16 {
                    packets =
                        packets.saturating_add(u64::from_ne_bytes(raw[0..8].try_into().unwrap()));
                    bytes =
                        bytes.saturating_add(u64::from_ne_bytes(raw[8..16].try_into().unwrap()));
                }
            }
        } else if let Some(value) = entry.get("value") {
            let raw = json_bytes(value)?;
            if raw.len() >= 16 {
                packets = u64::from_ne_bytes(raw[0..8].try_into().unwrap());
                bytes = u64::from_ne_bytes(raw[8..16].try_into().unwrap());
            }
        }

        if verdict == 1 {
            out.allowed_packets = out.allowed_packets.saturating_add(packets);
            out.allowed_bytes = out.allowed_bytes.saturating_add(bytes);
        } else {
            out.dropped_packets = out.dropped_packets.saturating_add(packets);
            out.dropped_bytes = out.dropped_bytes.saturating_add(bytes);
        }
    }
    Ok(out)
}

fn parse_flows_json(root: &Value) -> Result<Vec<FlowRecord>> {
    let entries = root
        .as_array()
        .context("bpftool flow JSON must be an array")?;
    let mut out = Vec::with_capacity(entries.len());
    for entry in entries {
        let key = json_bytes(&entry["key"])?;
        let value = json_bytes(&entry["value"])?;
        if key.len() < 20 || value.len() < 24 {
            continue;
        }
        let identity = u32::from_ne_bytes(key[0..4].try_into().unwrap());
        let source = Ipv4Addr::new(key[4], key[5], key[6], key[7]);
        let destination = Ipv4Addr::new(key[8], key[9], key[10], key[11]);
        let source_port = u16::from_ne_bytes(key[12..14].try_into().unwrap());
        let destination_port = u16::from_ne_bytes(key[14..16].try_into().unwrap());
        let protocol = key[16];
        let verdict = if key[17] == 1 { "allow" } else { "drop" }.to_string();
        let packets = u64::from_ne_bytes(value[0..8].try_into().unwrap());
        let bytes = u64::from_ne_bytes(value[8..16].try_into().unwrap());
        let last_seen_ns = u64::from_ne_bytes(value[16..24].try_into().unwrap());
        out.push(FlowRecord {
            identity,
            source,
            destination,
            source_port,
            destination_port,
            protocol,
            verdict,
            packets,
            bytes,
            last_seen_ns,
        });
    }
    Ok(out)
}

fn json_bytes(v: &Value) -> Result<Vec<u8>> {
    if let Some(a) = v.as_array() {
        return a
            .iter()
            .map(|x| {
                if let Some(n) = x.as_u64().filter(|n| *n <= 255) {
                    return Ok(n as u8);
                }
                if let Some(n) = x.as_i64().filter(|n| (0..=255).contains(n)) {
                    return Ok(n as u8);
                }
                if let Some(s) = x.as_str() {
                    let s = s.trim().trim_start_matches("0x");
                    return u8::from_str_radix(s, 16)
                        .with_context(|| format!("invalid bpftool hex byte {s:?}"));
                }
                bail!("bpftool JSON byte must be 0..255 or hex string, got {x}")
            })
            .collect();
    }
    if let Some(s) = v.as_str() {
        let normalized = s.replace(':', " ").replace(',', " ");
        return normalized
            .split_whitespace()
            .map(|x| u8::from_str_radix(x.trim_start_matches("0x"), 16).context("invalid hex byte"))
            .collect();
    }
    bail!("unsupported bpftool JSON byte representation: {v}")
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

fn parse_port_rule(raw: &str) -> Result<PortRule> {
    let (proto, port) = raw
        .split_once('/')
        .with_context(|| format!("port rule {raw:?} must be tcp/PORT or udp/PORT"))?;
    let protocol = match proto.trim().to_ascii_lowercase().as_str() {
        "tcp" => IPPROTO_TCP,
        "udp" => IPPROTO_UDP,
        other => bail!("unsupported L4 protocol {other:?}; use tcp or udp"),
    };
    let port: u16 = port
        .trim()
        .parse()
        .with_context(|| format!("invalid port in {raw:?}"))?;
    if port == 0 {
        bail!("port must be 1..65535");
    }
    Ok(PortRule { protocol, port })
}

fn require_bpftool() -> Result<()> {
    require_version("bpftool", &["version"])
}

fn require_tc() -> Result<()> {
    require_version("tc", &["-V"])
}

fn require_version(name: &str, args: &[&str]) -> Result<()> {
    let status = Command::new(name).args(args).status();
    match status {
        Ok(s) if s.success() => Ok(()),
        Ok(s) => bail!("{} {} exited with {s}", name, args.join(" ")),
        Err(e) => Err(e).with_context(|| format!("{name} is required for the eBPF dataplane")),
    }
}

pub(crate) fn raise_memlock() -> Result<()> {
    let limit = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    // SAFETY: `limit` is a valid rlimit structure for the duration of the
    // call. CAP_SYS_RESOURCE is only necessary when the current hard limit
    // would otherwise prevent the raise; new kernels charge BPF memory to
    // memcg, but this keeps older kernels working too.
    let rc = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &limit) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error()).context("raising RLIMIT_MEMLOCK for BPF");
    }
    Ok(())
}

fn ensure_clsact(iface: &str) -> Result<()> {
    let out = Command::new("tc")
        .args(["qdisc", "show", "dev", iface])
        .output()
        .context("querying tc qdisc")?;
    if !out.status.success() {
        bail!(
            "tc qdisc show dev {iface} failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    if String::from_utf8_lossy(&out.stdout)
        .split_whitespace()
        .any(|token| token == "clsact")
    {
        return Ok(());
    }
    run(
        "tc",
        &[
            "qdisc".into(),
            "add".into(),
            "dev".into(),
            iface.into(),
            "clsact".into(),
        ],
    )
}

fn tc_filter_attached(iface: &str) -> Result<bool> {
    let out = Command::new("tc")
        .args([
            "filter",
            "show",
            "dev",
            iface,
            "ingress",
            "pref",
            TC_PRIORITY,
        ])
        .output()
        .context("querying FluxVM TC filter")?;
    if !out.status.success() {
        return Ok(false);
    }
    let text = String::from_utf8_lossy(&out.stdout);
    Ok(text.contains("bpf") && text.contains(TC_PRIORITY))
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
    use serde_json::json;

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
    fn l4_rules_parse() {
        assert_eq!(
            parse_port_rule("tcp/443").unwrap(),
            PortRule {
                protocol: 6,
                port: 443
            }
        );
        assert_eq!(
            parse_port_rule("UDP/53").unwrap(),
            PortRule {
                protocol: 17,
                port: 53
            }
        );
        assert!(parse_port_rule("icmp/8").is_err());
        assert!(parse_port_rule("tcp/0").is_err());
    }

    #[test]
    fn bytes_are_bpftool_hex_tokens() {
        assert_eq!(hex_args(&[0, 1, 0xfe]), ["00", "01", "fe"]);
    }

    #[test]
    fn json_bytes_accepts_numeric_and_hex_string_arrays() {
        let numeric = serde_json::json!([205, 13, 100]);
        assert_eq!(json_bytes(&numeric).unwrap(), vec![205, 13, 100]);

        let hex = serde_json::json!(["0xcd", "0x0d", "0x64"]);
        assert_eq!(json_bytes(&hex).unwrap(), vec![0xcd, 0x0d, 0x64]);
    }

    #[test]
    fn mbps_rate_is_converted_to_bytes_per_second() {
        assert_eq!(mbps_to_bytes_per_second(1).unwrap(), 125_000);
        assert_eq!(mbps_to_bytes_per_second(100).unwrap(), 12_500_000);
        assert!(mbps_to_bytes_per_second(0).is_err());
    }

    #[test]
    fn zero_pps_is_rejected() {
        let policy = VmNetworkPolicy {
            max_egress_pps: Some(0),
            ..VmNetworkPolicy::default()
        };
        assert!(validate_policy(&policy).is_err());
    }

    #[test]
    fn stats_parser_aggregates_per_cpu_values() {
        fn u32b(v: u32) -> Vec<u8> {
            v.to_ne_bytes().to_vec()
        }
        fn statv(packets: u64, bytes: u64) -> Vec<u8> {
            [packets.to_ne_bytes(), bytes.to_ne_bytes()].concat()
        }
        let mut allow_key = u32b(99);
        allow_key.extend(u32b(1));
        let mut drop_key = u32b(99);
        drop_key.extend(u32b(0));
        let doc = json!([
            {"key": allow_key, "values": [
                {"cpu":0,"value":statv(2,200)},
                {"cpu":1,"value":statv(3,300)}
            ]},
            {"key": drop_key, "values": [
                {"cpu":0,"value":statv(1,64)}
            ]}
        ]);
        let s = parse_stats_json(&doc).unwrap();
        assert_eq!(s.allowed_packets, 5);
        assert_eq!(s.allowed_bytes, 500);
        assert_eq!(s.dropped_packets, 1);
        assert_eq!(s.dropped_bytes, 64);
    }

    #[test]
    fn flow_parser_decodes_packet_order_addresses() {
        let identity = 7u32;
        let mut key = identity.to_ne_bytes().to_vec();
        key.extend([10, 0, 0, 2]);
        key.extend([1, 1, 1, 1]);
        key.extend(43210u16.to_ne_bytes());
        key.extend(443u16.to_ne_bytes());
        key.push(6);
        key.push(1);
        key.extend([0, 0]);
        let value = [
            4u64.to_ne_bytes(),
            2048u64.to_ne_bytes(),
            12345u64.to_ne_bytes(),
        ]
        .concat();
        let doc = json!([{"key":key,"value":value}]);
        let flows = parse_flows_json(&doc).unwrap();
        assert_eq!(flows.len(), 1);
        assert_eq!(flows[0].source, Ipv4Addr::new(10, 0, 0, 2));
        assert_eq!(flows[0].destination, Ipv4Addr::new(1, 1, 1, 1));
        assert_eq!(flows[0].destination_port, 443);
        assert_eq!(flows[0].verdict, "allow");
        assert_eq!(flows[0].bytes, 2048);
    }
}
