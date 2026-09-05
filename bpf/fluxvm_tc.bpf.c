// Copyright 2026 Zyvor
// SPDX-License-Identifier: Apache-2.0

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/pkt_cls.h>
#include <linux/udp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct iface_config {
    __u32 identity;
    __u32 default_allow;
};

struct ipv4_lpm_key {
    __u32 prefixlen;
    __u32 identity;
    __u32 addr;
};

struct stat_key {
    __u32 identity;
    __u32 verdict;
};

struct drop_event {
    __u64 timestamp_ns;
    __u32 identity;
    __u32 ifindex;
    __u32 src;
    __u32 dst;
    __u8 protocol;
    __u8 pad[3];
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
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, 32);
    __type(key, struct stat_key);
    __type(value, __u64);
} fluxvm_stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} fluxvm_events SEC(".maps");

static __always_inline void count(__u32 identity, __u32 verdict)
{
    struct stat_key key = {
        .identity = identity,
        .verdict = verdict,
    };
    __u64 *value = bpf_map_lookup_elem(&fluxvm_stats, &key);
    if (value) {
        *value += 1;
        return;
    }
    __u64 one = 1;
    bpf_map_update_elem(&fluxvm_stats, &key, &one, BPF_NOEXIST);
}

static __always_inline int allow_dhcp(struct iphdr *iph, void *data_end)
{
    if (iph->protocol != IPPROTO_UDP)
        return 0;

    struct udphdr *udp = (void *)iph + (iph->ihl * 4);
    if ((void *)(udp + 1) > data_end)
        return 0;

    __u16 sport = bpf_ntohs(udp->source);
    __u16 dport = bpf_ntohs(udp->dest);
    return (sport == 67 && dport == 68) || (sport == 68 && dport == 67);
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

    __u16 proto = bpf_ntohs(eth->h_proto);
    if (proto == ETH_P_ARP) {
        count(cfg->identity, 1);
        return TC_ACT_OK;
    }

    if (proto != ETH_P_IP) {
        int verdict = cfg->default_allow ? TC_ACT_OK : TC_ACT_SHOT;
        count(cfg->identity, verdict == TC_ACT_OK ? 1 : 0);
        return verdict;
    }

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end || iph->ihl < 5)
        return TC_ACT_SHOT;
    if ((void *)iph + (iph->ihl * 4) > data_end)
        return TC_ACT_SHOT;

    // DHCP must work before an allowlist can possibly be useful to the
    // guest, so it is infrastructure traffic and always permitted.
    if (allow_dhcp(iph, data_end)) {
        count(cfg->identity, 1);
        return TC_ACT_OK;
    }

    struct ipv4_lpm_key key = {
        .prefixlen = 64,
        .identity = cfg->identity,
        .addr = iph->daddr,
    };
    __u32 *allow = bpf_map_lookup_elem(&fluxvm_v4, &key);
    if (allow && *allow) {
        count(cfg->identity, 1);
        return TC_ACT_OK;
    }

    if (cfg->default_allow) {
        count(cfg->identity, 1);
        return TC_ACT_OK;
    }

    count(cfg->identity, 0);
    struct drop_event *event = bpf_ringbuf_reserve(&fluxvm_events, sizeof(*event), 0);
    if (event) {
        event->timestamp_ns = bpf_ktime_get_ns();
        event->identity = cfg->identity;
        event->ifindex = ifindex;
        event->src = iph->saddr;
        event->dst = iph->daddr;
        event->protocol = iph->protocol;
        __builtin_memset(event->pad, 0, sizeof(event->pad));
        bpf_ringbuf_submit(event, 0);
    }
    return TC_ACT_SHOT;
}

char LICENSE[] SEC("license") = "GPL";
