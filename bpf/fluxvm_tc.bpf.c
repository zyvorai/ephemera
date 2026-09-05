// Copyright 2026 Zyvor
// SPDX-License-Identifier: GPL-2.0-only
//
// FluxVM VM-edge TC dataplane.
//
// Attaches to the host-visible VM interface (host veth for namespaced TAP,
// otherwise TAP/macvtap).  The userspace loader creates a private set of
// pinned maps per VM, so identities/policies cannot collide across VMs and
// FluxVM never needs to mutate Cilium's private BPF maps.

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/pkt_cls.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define FLUXVM_VERDICT_DROP  0
#define FLUXVM_VERDICT_ALLOW 1

struct iface_config {
    __u32 identity;
    __u32 default_allow;
    __u32 enforce_cidr;
    __u32 enforce_l4;
    // 0 = do not sample allowed flows; N = emit roughly 1/N allows.
    __u32 sample_rate;
    __u32 pad;
    // Zero disables the corresponding limiter. Userspace converts Mbps to
    // bytes/second before writing this structure.
    __u64 rate_bytes_per_sec;
    __u64 rate_packets_per_sec;
};

// LPM prefix covers an exact 32-bit FluxVM identity followed by an IPv4
// destination prefix. Userspace inserts prefixlen = 32 + ipv4_prefix.
struct ipv4_lpm_key {
    __u32 prefixlen;
    __u32 identity;
    __u32 addr;
};

struct l4_key {
    __u32 identity;
    __u16 port;
    __u8 protocol;
    __u8 pad;
};

struct stat_key {
    __u32 identity;
    __u32 verdict;
};

struct stat_value {
    __u64 packets;
    __u64 bytes;
};

// Kept intentionally compact so dumping this LRU map is cheap enough for a
// REST endpoint. IPv4 addresses are stored in packet byte order, while ports
// are host order because they are produced by bpf_ntohs().
struct flow_key {
    __u32 identity;
    __u32 src;
    __u32 dst;
    __u16 sport;
    __u16 dport;
    __u8 protocol;
    __u8 verdict;
    __u16 pad;
};

struct flow_value {
    __u64 packets;
    __u64 bytes;
    __u64 last_seen_ns;
};

struct rate_state {
    struct bpf_spin_lock lock;
    __u32 pad;
    __u64 window_start_ns;
    __u64 bytes;
    __u64 packets;
};

struct flow_event {
    __u64 timestamp_ns;
    __u32 identity;
    __u32 ifindex;
    __u32 src;
    __u32 dst;
    __u32 bytes;
    __u16 sport;
    __u16 dport;
    __u8 protocol;
    __u8 verdict;
    __u16 pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8);
    __type(key, __u32);
    __type(value, struct iface_config);
} fluxvm_id SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(max_entries, 4096);
    __type(key, struct ipv4_lpm_key);
    __type(value, __u32);
} fluxvm_v4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, struct l4_key);
    __type(value, __u32);
} fluxvm_l4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8);
    __type(key, __u32);
    __type(value, struct rate_state);
} fluxvm_rate SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, 32);
    __type(key, struct stat_key);
    __type(value, struct stat_value);
} fluxvm_stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key, struct flow_key);
    __type(value, struct flow_value);
} fluxvm_flows SEC(".maps");

// Ring buffer is useful for a future streaming collector. The REST API in
// this patch uses fluxvm_flows instead, so losing ringbuf events cannot make
// observability state disappear.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} fluxvm_events SEC(".maps");

static __always_inline void count(__u32 identity, __u32 verdict, __u32 bytes)
{
    struct stat_key key = {
        .identity = identity,
        .verdict = verdict,
    };
    struct stat_value *value = bpf_map_lookup_elem(&fluxvm_stats, &key);
    if (value) {
        value->packets += 1;
        value->bytes += bytes;
        return;
    }
    struct stat_value initial = {
        .packets = 1,
        .bytes = bytes,
    };
    bpf_map_update_elem(&fluxvm_stats, &key, &initial, BPF_NOEXIST);
}

static __always_inline int parse_ports(
    struct iphdr *iph,
    void *data_end,
    __u16 *sport,
    __u16 *dport)
{
    void *l4 = (void *)iph + (iph->ihl * 4);

    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = l4;
        if ((void *)(tcp + 1) > data_end)
            return -1;
        *sport = bpf_ntohs(tcp->source);
        *dport = bpf_ntohs(tcp->dest);
        return 1;
    }

    if (iph->protocol == IPPROTO_UDP) {
        struct udphdr *udp = l4;
        if ((void *)(udp + 1) > data_end)
            return -1;
        *sport = bpf_ntohs(udp->source);
        *dport = bpf_ntohs(udp->dest);
        return 1;
    }

    *sport = 0;
    *dport = 0;
    return 0;
}

static __always_inline int is_dhcp(__u8 protocol, __u16 sport, __u16 dport)
{
    if (protocol != IPPROTO_UDP)
        return 0;
    return (sport == 67 && dport == 68) || (sport == 68 && dport == 67);
}

#define FLUXVM_RATE_WINDOW_NS 1000000000ULL

static __always_inline int rate_allowed(
    const struct iface_config *cfg,
    __u32 bytes)
{
    __u64 byte_limit = cfg->rate_bytes_per_sec;
    __u64 packet_limit = cfg->rate_packets_per_sec;
    if (byte_limit == 0 && packet_limit == 0)
        return 1;

    __u32 identity = cfg->identity;
    struct rate_state *state = bpf_map_lookup_elem(&fluxvm_rate, &identity);
    // Userspace creates the state before enabling limits in iface_config.
    // Missing state therefore means an incomplete configuration: fail closed.
    if (!state)
        return 0;

    __u64 now = bpf_ktime_get_ns();
    int allowed = 1;
    bpf_spin_lock(&state->lock);

    if (state->window_start_ns == 0 ||
        now - state->window_start_ns >= FLUXVM_RATE_WINDOW_NS) {
        state->window_start_ns = now;
        state->bytes = 0;
        state->packets = 0;
    }

    if (byte_limit > 0) {
        if (state->bytes >= byte_limit ||
            (__u64)bytes > byte_limit - state->bytes)
            allowed = 0;
    }
    if (packet_limit > 0 && state->packets >= packet_limit)
        allowed = 0;

    if (allowed) {
        state->bytes += bytes;
        state->packets += 1;
    }
    bpf_spin_unlock(&state->lock);
    return allowed;
}

static __always_inline int cidr_allowed(__u32 identity, __u32 daddr)
{
    struct ipv4_lpm_key key = {
        .prefixlen = 64,
        .identity = identity,
        .addr = daddr,
    };
    __u32 *allow = bpf_map_lookup_elem(&fluxvm_v4, &key);
    return allow && *allow;
}

static __always_inline int l4_allowed(__u32 identity, __u8 protocol, __u16 port)
{
    struct l4_key key = {
        .identity = identity,
        .port = port,
        .protocol = protocol,
        .pad = 0,
    };
    __u32 *allow = bpf_map_lookup_elem(&fluxvm_l4, &key);
    return allow && *allow;
}

static __always_inline void record_flow(
    struct __sk_buff *skb,
    __u32 identity,
    struct iphdr *iph,
    __u16 sport,
    __u16 dport,
    __u8 verdict,
    __u32 sample_rate)
{
    struct flow_key key = {
        .identity = identity,
        .src = iph->saddr,
        .dst = iph->daddr,
        .sport = sport,
        .dport = dport,
        .protocol = iph->protocol,
        .verdict = verdict,
        .pad = 0,
    };
    struct flow_value *value = bpf_map_lookup_elem(&fluxvm_flows, &key);
    if (value) {
        // Atomic packet/byte counters avoid losing increments when the same
        // VM interface is processed by multiple CPUs.
        __sync_fetch_and_add(&value->packets, 1);
        __sync_fetch_and_add(&value->bytes, skb->len);
        value->last_seen_ns = bpf_ktime_get_ns();
    } else {
        struct flow_value initial = {
            .packets = 1,
            .bytes = skb->len,
            .last_seen_ns = bpf_ktime_get_ns(),
        };
        bpf_map_update_elem(&fluxvm_flows, &key, &initial, BPF_NOEXIST);
    }

    int emit = verdict == FLUXVM_VERDICT_DROP;
    if (!emit && sample_rate > 0)
        emit = (bpf_get_prandom_u32() % sample_rate) == 0;
    if (!emit)
        return;

    struct flow_event *event = bpf_ringbuf_reserve(&fluxvm_events, sizeof(*event), 0);
    if (!event)
        return;
    event->timestamp_ns = bpf_ktime_get_ns();
    event->identity = identity;
    event->ifindex = skb->ifindex;
    event->src = iph->saddr;
    event->dst = iph->daddr;
    event->bytes = skb->len;
    event->sport = sport;
    event->dport = dport;
    event->protocol = iph->protocol;
    event->verdict = verdict;
    event->pad = 0;
    bpf_ringbuf_submit(event, 0);
}

SEC("tc")
int fluxvm_egress(struct __sk_buff *skb)
{
    __u32 ifindex = skb->ifindex;
    struct iface_config *cfg = bpf_map_lookup_elem(&fluxvm_id, &ifindex);
    if (!cfg)
        return TC_ACT_OK;

    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_SHOT;

    __u16 eth_proto = bpf_ntohs(eth->h_proto);
    if (eth_proto == ETH_P_ARP) {
        count(cfg->identity, FLUXVM_VERDICT_ALLOW, skb->len);
        return TC_ACT_OK;
    }

    if (eth_proto != ETH_P_IP) {
        __u8 verdict = cfg->default_allow ? FLUXVM_VERDICT_ALLOW : FLUXVM_VERDICT_DROP;
        count(cfg->identity, verdict, skb->len);
        return verdict == FLUXVM_VERDICT_ALLOW ? TC_ACT_OK : TC_ACT_SHOT;
    }

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end || iph->ihl < 5)
        return TC_ACT_SHOT;
    if ((void *)iph + (iph->ihl * 4) > data_end)
        return TC_ACT_SHOT;

    __u16 sport = 0;
    __u16 dport = 0;
    __u16 frag = bpf_ntohs(iph->frag_off);
    int fragmented = (frag & 0x3fff) != 0; // MF flag or non-zero fragment offset
    int parsed_l4 = 0;
    if (!fragmented) {
        parsed_l4 = parse_ports(iph, data_end, &sport, &dport);
        if (parsed_l4 < 0)
            return TC_ACT_SHOT;
    }

    // An L4 allowlist cannot safely classify later IP fragments because they
    // do not carry TCP/UDP ports. Fail closed instead of allowing a fragment
    // based only on the first packet's destination.
    if (fragmented && cfg->enforce_l4) {
        count(cfg->identity, FLUXVM_VERDICT_DROP, skb->len);
        record_flow(skb, cfg->identity, iph, 0, 0, FLUXVM_VERDICT_DROP, cfg->sample_rate);
        return TC_ACT_SHOT;
    }

    // DHCP is infrastructure bootstrap traffic. Blocking it here would make
    // a deny-by-default VM unable to obtain the very address policy uses.
    if (is_dhcp(iph->protocol, sport, dport)) {
        count(cfg->identity, FLUXVM_VERDICT_ALLOW, skb->len);
        record_flow(
            skb,
            cfg->identity,
            iph,
            sport,
            dport,
            FLUXVM_VERDICT_ALLOW,
            cfg->sample_rate);
        return TC_ACT_OK;
    }

    int has_policy = cfg->enforce_cidr || cfg->enforce_l4;
    int allowed = has_policy ? 1 : (cfg->default_allow != 0);
    if (cfg->enforce_cidr)
        allowed = allowed && cidr_allowed(cfg->identity, iph->daddr);
    if (cfg->enforce_l4) {
        int port_ok = parsed_l4 > 0 && l4_allowed(cfg->identity, iph->protocol, dport);
        allowed = allowed && port_ok;
    }

    if (allowed && !rate_allowed(cfg, skb->len))
        allowed = 0;

    __u8 verdict = allowed ? FLUXVM_VERDICT_ALLOW : FLUXVM_VERDICT_DROP;
    count(cfg->identity, verdict, skb->len);
    record_flow(skb, cfg->identity, iph, sport, dport, verdict, cfg->sample_rate);
    return allowed ? TC_ACT_OK : TC_ACT_SHOT;
}

char LICENSE[] SEC("license") = "GPL";
