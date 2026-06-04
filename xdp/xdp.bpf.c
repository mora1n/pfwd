//go:build ignore

#include "xdp_bpf.h"

char __license[] SEC("license") = "Dual MIT/GPL";

enum pfwd_stat_index {
    PFWD_STAT_PASSED = 0,
    PFWD_STAT_DROPPED = 1,
    PFWD_STAT_FORWARDED = 2,
    PFWD_STAT_QUOTA_DROPPED = 3,
    PFWD_STAT_WHITELIST_DROPPED = 4,
    PFWD_STAT_PROTOCOL_DROPPED = 5,
    PFWD_STAT_PARSE_SKIPPED = 6,
    PFWD_STAT_TCP_PREWARMED = 7,
    PFWD_STAT_TCP_ESTABLISHED = 8,
    PFWD_STAT_HOST_EGRESS_DROPPED = 9,
    PFWD_STAT_MAX = 10,
};

enum pfwd_snat_mode {
    PFWD_SNAT_MASQUERADE = 0,
    PFWD_SNAT_FIXED = 1,
};

enum pfwd_mss_mode {
    PFWD_MSS_NONE = 0,
    PFWD_MSS_CLAMP = 1,
    PFWD_MSS_SET = 2,
};

enum pfwd_rule_flags {
    PFWD_RULE_F_XDP_DISABLED = 1U << 0,
    PFWD_RULE_F_NEEDS_COUNTER = 1U << 1,
    PFWD_RULE_F_NEEDS_QUOTA = 1U << 2,
    PFWD_RULE_F_NEEDS_GUARD = 1U << 3,
    PFWD_RULE_F_NEEDS_ALLOW = 1U << 4,
    PFWD_RULE_F_SNAT_FIXED = 1U << 5,
    PFWD_RULE_F_MSS_ENABLED = 1U << 6,
    PFWD_RULE_F_HAS_SKIP_PORTS = 1U << 7,
    PFWD_RULE_F_BLOCK_HTTP = 1U << 8,
    PFWD_RULE_F_BLOCK_TLS = 1U << 9,
    PFWD_RULE_F_BLOCK_SOCKS = 1U << 10,
    PFWD_RULE_F_ALLOW_CUSTOM = 1U << 11,
    PFWD_RULE_F_ALLOW_GEO = 1U << 12,
};

enum pfwd_rule_flag_groups {
    PFWD_RULE_F_NEEDS_POLICY = PFWD_RULE_F_NEEDS_COUNTER |
                               PFWD_RULE_F_NEEDS_QUOTA |
                               PFWD_RULE_F_NEEDS_GUARD |
                               PFWD_RULE_F_NEEDS_ALLOW,
};

enum pfwd_inspect_result {
    PFWD_INSPECT_ALLOW = 0,
    PFWD_INSPECT_DROP = 1,
    PFWD_INSPECT_NEED_MORE = 2,
};

enum pfwd_cache_verdict {
    PFWD_CACHE_UNKNOWN = 0,
    PFWD_CACHE_ALLOW = 1,
    PFWD_CACHE_DROP = 2,
};

enum pfwd_conn_state {
    PFWD_CONN_STATE_NONE = 0,
    PFWD_CONN_STATE_TCP_SYN_PENDING = 1,
    PFWD_CONN_STATE_TCP_ESTABLISHED = 2,
};

struct pfwd_settings {
    __u8 whitelist_enabled;
    __u8 block_http;
    __u8 block_tls;
    __u8 block_socks;
    __u8 guard_enabled;
    __u8 has_skip_ports;
    __u8 egress_whitelist_custom;
    __u8 egress_whitelist_geo;
    __u8 pad[4];
    __u32 external_ifindex;
    __u32 loopback_ifindex;
};

struct pfwd_rule_key {
    __u8 family;
    __u8 protocol;
    __u16 listen_port;
    __u8 listen_addr[16];
};

struct pfwd_rule_val {
    __u32 rule_id;
    __u32 user_id;
    __u8 target_addr[16];
    __u16 target_port;
    __u8 snat_mode;
    __u8 mss_mode;
    __u8 snat_addr[16];
    __u16 mss_value;
    __u16 flags;
    __u64 rule_limit_bytes;
    __u64 user_limit_bytes;
    __u64 traffic_ratio_scaled;
    __u64 rule_billing_used_base_bytes;
    __u64 user_billing_used_base_bytes;
    __u8 traffic_mode;
    __u8 user_limit_enabled;
    __u8 billing_enabled;
    __u8 pad[5];
};

static __always_inline int rule_xdp_disabled(const struct pfwd_rule_val *rule) {
    return rule && (rule->flags & PFWD_RULE_F_XDP_DISABLED);
}

static __always_inline int rule_needs_guard(const struct pfwd_rule_val *rule) {
    return rule && (rule->flags & PFWD_RULE_F_NEEDS_GUARD);
}

static __always_inline int rule_needs_allow(const struct pfwd_rule_val *rule) {
    return rule && (rule->flags & PFWD_RULE_F_NEEDS_ALLOW);
}

static __always_inline int rule_snat_fixed(const struct pfwd_rule_val *rule) {
    return rule && (rule->flags & PFWD_RULE_F_SNAT_FIXED);
}

static __always_inline int rule_mss_enabled(const struct pfwd_rule_val *rule) {
    return rule && (rule->flags & PFWD_RULE_F_MSS_ENABLED);
}

struct pfwd_conn_key {
    __u8 family;
    __u8 protocol;
    __u16 client_port;
    __u16 listen_port;
    __u16 target_port;
    __u8 client_addr[16];
    __u8 listen_addr[16];
    __u8 target_addr[16];
};

struct pfwd_conn_val {
    __u32 rule_id;
    __u32 user_id;
    __u8 client_addr[16];
    __u8 listen_addr[16];
    __u8 source_addr[16];
    __u16 client_port;
    __u16 source_port;
    __u16 listen_port;
    __u16 pad16;
    __u64 traffic_ratio_scaled;
    __u8 traffic_mode;
    __u8 user_limit_enabled;
    __u8 billing_enabled;
    __u8 state;
    __u8 pad8[4];
    __u64 packets;
    __u64 bytes;
};

struct pfwd_reverse_key {
    __u8 family;
    __u8 protocol;
    __u16 source_port;
    __u16 target_port;
    __u16 pad16;
    __u8 source_addr[16];
    __u8 target_addr[16];
};

struct pfwd_counter {
    __u64 input_bytes;
    __u64 output_bytes;
    __u64 input_packets;
    __u64 output_packets;
    __u64 billing_bytes;
};

struct pfwd_user_counter {
    __u64 billing_bytes;
};

struct pfwd_reply_counter {
    __u64 output_bytes;
    __u64 output_packets;
    __u64 billing_bytes;
};

struct pfwd_drop_counter {
    __u64 dropped_bytes;
    __u64 dropped_packets;
};

struct pfwd_counter_plan {
    struct pfwd_counter *rule_counter;
    struct pfwd_user_counter *user_counter;
    __u64 billed;
    __u16 flags;
};

struct pfwd_whitelist_key_v4 {
    __u32 prefixlen;
    __u32 addr;
};

struct pfwd_whitelist_key_v6 {
    __u32 prefixlen;
    __u8 addr[16];
};

struct pfwd_geo_bucket {
    __u32 start;
    __u32 count;
};

struct pfwd_geo_prefix_key_v4 {
    __u32 prefixlen;
    __u32 addr;
};

struct pfwd_geo_prefix_key_v6 {
    __u32 prefixlen;
    __u8 addr[16];
};

struct pfwd_geo_prefix_val {
    __u16 province_id;
    __u8 policy_flags;
    __u8 pad;
};

struct pfwd_geo_province_policy {
    __u8 flags;
    __u8 pad[3];
};

struct pfwd_flow_key {
    __u8 family;
    __u8 protocol;
    __u16 sport;
    __u16 dport;
    __u8 saddr[16];
    __u8 daddr[16];
};

struct pfwd_guard_prefix_val {
    __u8 seen_len;
    __u8 pad[7];
    __u8 prefix[8];
};

struct pfwd_whitelist_cache_key_v6 {
    __u8 addr[16];
};

struct pfwd_scratch {
    struct pfwd_conn_val conn;
    struct pfwd_reverse_key reverse_key;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct pfwd_settings);
} pfwd_settings SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, PFWD_MAX_RULES);
    __type(key, struct pfwd_rule_key);
    __type(value, struct pfwd_rule_val);
} pfwd_rules SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 262144);
    __type(key, struct pfwd_conn_key);
    __type(value, struct pfwd_conn_val);
} pfwd_connections SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 262144);
    __type(key, struct pfwd_reverse_key);
    __type(value, struct pfwd_conn_val);
} pfwd_reverse SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, PFWD_MAX_RULES);
    __type(key, __u32);
    __type(value, struct pfwd_counter);
} pfwd_rule_counters SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, PFWD_MAX_RULES);
    __type(key, __u32);
    __type(value, struct pfwd_reply_counter);
} pfwd_rule_reply_counters SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, PFWD_MAX_RULES);
    __type(key, __u32);
    __type(value, struct pfwd_drop_counter);
} pfwd_rule_drop_counters SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, PFWD_MAX_USERS);
    __type(key, __u32);
    __type(value, struct pfwd_user_counter);
} pfwd_user_counters SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, PFWD_STAT_MAX);
    __type(key, __u32);
    __type(value, __u64);
} pfwd_stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 65536);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct pfwd_whitelist_key_v4);
    __type(value, __u8);
} pfwd_whitelist_v4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 65536);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct pfwd_whitelist_key_v6);
    __type(value, __u8);
} pfwd_whitelist_v6 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, __be32);
    __type(value, __u8);
} pfwd_whitelist_cache_v4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct pfwd_whitelist_cache_key_v6);
    __type(value, __u8);
} pfwd_whitelist_cache_v6 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 65536);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct pfwd_whitelist_key_v4);
    __type(value, __u8);
} pfwd_egress_whitelist_v4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 65536);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct pfwd_whitelist_key_v6);
    __type(value, __u8);
} pfwd_egress_whitelist_v6 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, __be32);
    __type(value, __u8);
} pfwd_egress_whitelist_cache_v4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct pfwd_whitelist_cache_key_v6);
    __type(value, __u8);
} pfwd_egress_whitelist_cache_v6 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 65536);
    __type(key, __u32);
    __type(value, struct pfwd_geo_bucket);
} pfwd_geo_bucket_v4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 65536);
    __type(key, __u32);
    __type(value, struct pfwd_geo_bucket);
} pfwd_geo_bucket_v6 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 131072);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct pfwd_geo_prefix_key_v4);
    __type(value, struct pfwd_geo_prefix_val);
} pfwd_geo_segments_v4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 32768);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct pfwd_geo_prefix_key_v6);
    __type(value, struct pfwd_geo_prefix_val);
} pfwd_geo_segments_v6 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 256);
    __type(key, __u32);
    __type(value, struct pfwd_geo_province_policy);
} pfwd_geo_province_policy SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct pfwd_flow_key);
    __type(value, __u8);
} pfwd_allowed_flows SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct pfwd_flow_key);
    __type(value, __u8);
} pfwd_host_egress_flows SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct pfwd_flow_key);
    __type(value, struct pfwd_guard_prefix_val);
} pfwd_guard_prefixes SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 65536);
    __type(key, __u32);
    __type(value, __u8);
} pfwd_protocol_skip_ports SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct pfwd_scratch);
} pfwd_scratch SEC(".maps");

static __always_inline void stat_inc(__u32 index) {
    __u64 *value = bpf_map_lookup_elem(&pfwd_stats, &index);
    if (value) {
        *value += 1;
    }
}

static __always_inline int tcp_syn_only(const struct tcphdr_min *tcp) {
    __u8 flags;

    if (!tcp) {
        return 0;
    }
    flags = tcp->flags;
    return (flags & 0x02) && !(flags & 0x15);
}

static __always_inline void record_new_tcp_state(struct pfwd_conn_val *conn, __u8 state) {
    if (!conn) {
        return;
    }
    conn->state = state;
    if (state == PFWD_CONN_STATE_TCP_SYN_PENDING) {
        stat_inc(PFWD_STAT_TCP_PREWARMED);
    } else if (state == PFWD_CONN_STATE_TCP_ESTABLISHED) {
        stat_inc(PFWD_STAT_TCP_ESTABLISHED);
    }
}

static __always_inline void mark_tcp_established(struct pfwd_conn_val *conn) {
    if (!conn) {
        return;
    }
    if (conn->state != PFWD_CONN_STATE_TCP_ESTABLISHED) {
        conn->state = PFWD_CONN_STATE_TCP_ESTABLISHED;
        stat_inc(PFWD_STAT_TCP_ESTABLISHED);
    }
}

static __always_inline int tc_pull_data_min(struct __sk_buff *skb, __u32 len) {
    if (!skb) {
        return -1;
    }
    if (skb->len <= len) {
        return bpf_skb_pull_data(skb, skb->len);
    }
    return bpf_skb_pull_data(skb, len);
}

static __always_inline int tc_load_tcp_min(
    struct __sk_buff *skb,
    __u32 offset,
    struct tcphdr_min *tcp
) {
    if (!skb || !tcp) {
        return -1;
    }
    return bpf_skb_load_bytes(skb, offset, tcp, sizeof(*tcp));
}

static __always_inline int tc_load_udp_min(
    struct __sk_buff *skb,
    __u32 offset,
    struct udphdr_min *udp
) {
    if (!skb || !udp) {
        return -1;
    }
    return bpf_skb_load_bytes(skb, offset, udp, sizeof(*udp));
}

static __always_inline void set_ipv4_in16(__u8 dst[16], __be32 addr) {
    *(__be32 *)&dst[0] = addr;
    *(__u32 *)&dst[4] = 0;
    *(__u32 *)&dst[8] = 0;
    *(__u32 *)&dst[12] = 0;
}

static __always_inline __be32 ipv4_from16(const __u8 addr[16]) {
    const __be32 *value = (const __be32 *)addr;
    return *value;
}

static __always_inline void fill_conn_key_v4(
    struct pfwd_conn_key *key,
    __u8 protocol,
    __be32 client_addr,
    __be32 listen_addr,
    __be16 client_port,
    __be16 listen_port,
    __be16 target_port,
    const __u8 target_addr[16]
) {
    key->family = 4;
    key->protocol = protocol;
    key->client_port = client_port;
    key->listen_port = listen_port;
    key->target_port = target_port;
    set_ipv4_in16(key->client_addr, client_addr);
    set_ipv4_in16(key->listen_addr, listen_addr);
    pfwd_memcpy16(key->target_addr, target_addr);
}

static __always_inline void fill_conn_key_v6(
    struct pfwd_conn_key *key,
    __u8 protocol,
    const __u8 client_addr[16],
    const __u8 listen_addr[16],
    __be16 client_port,
    __be16 listen_port,
    __be16 target_port,
    const __u8 target_addr[16]
) {
    key->family = 6;
    key->protocol = protocol;
    key->client_port = client_port;
    key->listen_port = listen_port;
    key->target_port = target_port;
    pfwd_memcpy16(key->client_addr, client_addr);
    pfwd_memcpy16(key->listen_addr, listen_addr);
    pfwd_memcpy16(key->target_addr, target_addr);
}

static __always_inline void fill_reverse_lookup_key_v4(
    struct pfwd_reverse_key *key,
    __u8 protocol,
    __be32 source_addr,
    __be32 target_addr,
    __be16 source_port,
    __be16 target_port
) {
    key->family = 4;
    key->protocol = protocol;
    key->source_port = source_port;
    key->target_port = target_port;
    key->pad16 = 0;
    set_ipv4_in16(key->source_addr, source_addr);
    set_ipv4_in16(key->target_addr, target_addr);
}

static __always_inline void fill_reverse_lookup_key_v6(
    struct pfwd_reverse_key *key,
    __u8 protocol,
    const __u8 source_addr[16],
    const __u8 target_addr[16],
    __be16 source_port,
    __be16 target_port
) {
    key->family = 6;
    key->protocol = protocol;
    key->source_port = source_port;
    key->target_port = target_port;
    key->pad16 = 0;
    pfwd_memcpy16(key->source_addr, source_addr);
    pfwd_memcpy16(key->target_addr, target_addr);
}

static __always_inline void init_reverse_alloc_key_v4(
    struct pfwd_reverse_key *key,
    __u8 protocol,
    __be16 target_port,
    __be32 source_addr,
    const __u8 target_addr[16]
) {
    key->family = 4;
    key->protocol = protocol;
    key->target_port = target_port;
    key->pad16 = 0;
    set_ipv4_in16(key->source_addr, source_addr);
    pfwd_memcpy16(key->target_addr, target_addr);
}

static __always_inline void init_reverse_alloc_key_v6(
    struct pfwd_reverse_key *key,
    __u8 protocol,
    __be16 target_port,
    const __u8 source_addr[16],
    const __u8 target_addr[16]
) {
    key->family = 6;
    key->protocol = protocol;
    key->target_port = target_port;
    key->pad16 = 0;
    pfwd_memcpy16(key->source_addr, source_addr);
    pfwd_memcpy16(key->target_addr, target_addr);
}

static __always_inline void adjust_tcp_mss(struct tcphdr_min *tcp, void *data_end, __u16 value);

static __always_inline __u16 csum_replace_addr16(__u16 csum, const __u8 old_addr[16], const __u8 new_addr[16]) {
    const __u32 *old32 = (const __u32 *)old_addr;
    const __u32 *new32 = (const __u32 *)new_addr;
#pragma unroll
    for (int i = 0; i < 4; i++) {
        csum = csum_replace32(csum, old32[i], new32[i]);
    }
    return csum;
}

static __always_inline void rewrite_l4_forward_v4(
    struct ipv4hdr_min *ip4,
    __u32 ihl,
    __u8 protocol,
    __be32 old_saddr,
    __be32 old_daddr,
    __be16 old_sport,
    __be16 old_dport,
    __be32 new_saddr,
    __be32 new_daddr,
    __be16 new_sport,
    __be16 new_dport,
    void *data_end,
    const struct pfwd_rule_val *rule
) {
    ip4->saddr = new_saddr;
    ip4->daddr = new_daddr;
    ip4->check = csum_replace32(ip4->check, old_saddr, new_saddr);
    ip4->check = csum_replace32(ip4->check, old_daddr, new_daddr);
    if (protocol == IPPROTO_TCP) {
        struct tcphdr_min *tcp = (void *)ip4 + ihl;
        tcp->source = new_sport;
        tcp->dest = new_dport;
        tcp->check = csum_replace32(tcp->check, old_saddr, new_saddr);
        tcp->check = csum_replace32(tcp->check, old_daddr, new_daddr);
        tcp->check = csum_replace16(tcp->check, old_sport, new_sport);
        tcp->check = csum_replace16(tcp->check, old_dport, new_dport);
        if (rule_mss_enabled(rule)) {
            adjust_tcp_mss(tcp, data_end, rule->mss_value);
        }
        return;
    }
    {
        struct udphdr_min *udp = (void *)ip4 + ihl;
        udp->source = new_sport;
        udp->dest = new_dport;
        if (udp->check) {
            udp->check = csum_replace32(udp->check, old_saddr, new_saddr);
            udp->check = csum_replace32(udp->check, old_daddr, new_daddr);
            udp->check = csum_replace16(udp->check, old_sport, new_sport);
            udp->check = csum_replace16(udp->check, old_dport, new_dport);
        }
    }
}

static __always_inline void rewrite_l4_reply_v4(
    struct ipv4hdr_min *ip4,
    __u32 ihl,
    __u8 protocol,
    __be32 old_saddr,
    __be32 old_daddr,
    __be32 new_saddr,
    __be32 new_daddr,
    __be16 old_sport,
    __be16 old_dport,
    __be16 new_sport,
    __be16 new_dport
) {
    ip4->saddr = new_saddr;
    ip4->daddr = new_daddr;
    ip4->check = csum_replace32(ip4->check, old_saddr, new_saddr);
    ip4->check = csum_replace32(ip4->check, old_daddr, new_daddr);
    if (protocol == IPPROTO_TCP) {
        struct tcphdr_min *tcp = (void *)ip4 + ihl;
        tcp->source = new_sport;
        tcp->dest = new_dport;
        tcp->check = csum_replace32(tcp->check, old_saddr, new_saddr);
        tcp->check = csum_replace32(tcp->check, old_daddr, new_daddr);
        tcp->check = csum_replace16(tcp->check, old_sport, new_sport);
        tcp->check = csum_replace16(tcp->check, old_dport, new_dport);
        return;
    }
    {
        struct udphdr_min *udp = (void *)ip4 + ihl;
        udp->source = new_sport;
        udp->dest = new_dport;
        if (udp->check) {
            udp->check = csum_replace32(udp->check, old_saddr, new_saddr);
            udp->check = csum_replace32(udp->check, old_daddr, new_daddr);
            udp->check = csum_replace16(udp->check, old_sport, new_sport);
            udp->check = csum_replace16(udp->check, old_dport, new_dport);
        }
    }
}

static __always_inline void rewrite_l4_forward_v6(
    struct ipv6hdr_min *ip6,
    __u8 protocol,
    const __u8 old_saddr[16],
    const __u8 old_daddr[16],
    __be16 old_sport,
    __be16 old_dport,
    const __u8 new_saddr[16],
    const __u8 new_daddr[16],
    __be16 new_sport,
    __be16 new_dport,
    void *data_end,
    const struct pfwd_rule_val *rule
) {
    if (protocol == IPPROTO_TCP) {
        struct tcphdr_min *tcp = (void *)(ip6 + 1);
        tcp->source = new_sport;
        tcp->dest = new_dport;
        tcp->check = csum_replace_addr16(tcp->check, old_saddr, new_saddr);
        tcp->check = csum_replace_addr16(tcp->check, old_daddr, new_daddr);
        tcp->check = csum_replace16(tcp->check, old_sport, new_sport);
        tcp->check = csum_replace16(tcp->check, old_dport, new_dport);
        if (rule_mss_enabled(rule)) {
            adjust_tcp_mss(tcp, data_end, rule->mss_value);
        }
        return;
    }
    {
        struct udphdr_min *udp = (void *)(ip6 + 1);
        udp->source = new_sport;
        udp->dest = new_dport;
        if (udp->check) {
            udp->check = csum_replace_addr16(udp->check, old_saddr, new_saddr);
            udp->check = csum_replace_addr16(udp->check, old_daddr, new_daddr);
            udp->check = csum_replace16(udp->check, old_sport, new_sport);
            udp->check = csum_replace16(udp->check, old_dport, new_dport);
        }
    }
    pfwd_memcpy16(ip6->saddr, new_saddr);
    pfwd_memcpy16(ip6->daddr, new_daddr);
}

static __always_inline void rewrite_l4_reply_v6(
    struct ipv6hdr_min *ip6,
    __u8 protocol,
    const __u8 old_saddr[16],
    const __u8 old_daddr[16],
    const __u8 new_saddr[16],
    const __u8 new_daddr[16],
    __be16 old_sport,
    __be16 old_dport,
    __be16 new_sport,
    __be16 new_dport
) {
    if (protocol == IPPROTO_TCP) {
        struct tcphdr_min *tcp = (void *)(ip6 + 1);
        tcp->source = new_sport;
        tcp->dest = new_dport;
        tcp->check = csum_replace_addr16(tcp->check, old_saddr, new_saddr);
        tcp->check = csum_replace_addr16(tcp->check, old_daddr, new_daddr);
        tcp->check = csum_replace16(tcp->check, old_sport, new_sport);
        tcp->check = csum_replace16(tcp->check, old_dport, new_dport);
        return;
    }
    {
        struct udphdr_min *udp = (void *)(ip6 + 1);
        udp->source = new_sport;
        udp->dest = new_dport;
        if (udp->check) {
            udp->check = csum_replace_addr16(udp->check, old_saddr, new_saddr);
            udp->check = csum_replace_addr16(udp->check, old_daddr, new_daddr);
            udp->check = csum_replace16(udp->check, old_sport, new_sport);
            udp->check = csum_replace16(udp->check, old_dport, new_dport);
        }
    }
    pfwd_memcpy16(ip6->saddr, new_saddr);
    pfwd_memcpy16(ip6->daddr, new_daddr);
}

static __always_inline int ipv4_is_loopback(__be32 addr) {
    return (bpf_ntohl(addr) & 0xff000000U) == 0x7f000000U;
}

static __always_inline int ipv6_is_loopback(const __u8 addr[16]) {
    int i;
#pragma unroll
    for (i = 0; i < 15; i++) {
        if (addr[i] != 0) {
            return 0;
        }
    }
    return addr[15] == 1;
}

static __always_inline int rule_target_is_loopback(__u8 family, const struct pfwd_rule_val *rule) {
    if (family == 4) {
        return ipv4_is_loopback(ipv4_from16(rule->target_addr));
    }
    if (family == 6) {
        return ipv6_is_loopback(rule->target_addr);
    }
    return 0;
}

static __always_inline int whitelist_match_v4(__be32 addr) {
    struct pfwd_whitelist_key_v4 key = {
        .prefixlen = 32,
        .addr = addr,
    };
    __u8 *value = bpf_map_lookup_elem(&pfwd_whitelist_v4, &key);
    return value != 0;
}

static __always_inline int whitelist_cache_hit_v4(__be32 addr) {
    __u8 *value = bpf_map_lookup_elem(&pfwd_whitelist_cache_v4, &addr);
    if (!value) {
        return PFWD_CACHE_UNKNOWN;
    }
    return *value == PFWD_CACHE_DROP ? PFWD_CACHE_DROP : PFWD_CACHE_ALLOW;
}

static __always_inline void whitelist_cache_store_v4(__be32 addr, __u8 verdict) {
    __u8 value = verdict;
    bpf_map_update_elem(&pfwd_whitelist_cache_v4, &addr, &value, BPF_ANY);
}

static __always_inline int whitelist_match_v6(const __u8 addr[16]) {
    struct pfwd_whitelist_key_v6 key = {
        .prefixlen = 128,
    };
    __u8 *value;
    pfwd_memcpy16(key.addr, addr);
    value = bpf_map_lookup_elem(&pfwd_whitelist_v6, &key);
    return value != 0;
}

static __always_inline int whitelist_cache_hit_v6(const __u8 addr[16]) {
    struct pfwd_whitelist_cache_key_v6 key = {};
    __u8 *value;
    pfwd_memcpy16(key.addr, addr);
    value = bpf_map_lookup_elem(&pfwd_whitelist_cache_v6, &key);
    if (!value) {
        return PFWD_CACHE_UNKNOWN;
    }
    return *value == PFWD_CACHE_DROP ? PFWD_CACHE_DROP : PFWD_CACHE_ALLOW;
}

static __always_inline void whitelist_cache_store_v6(const __u8 addr[16], __u8 verdict) {
    struct pfwd_whitelist_cache_key_v6 key = {};
    __u8 value = verdict;
    pfwd_memcpy16(key.addr, addr);
    bpf_map_update_elem(&pfwd_whitelist_cache_v6, &key, &value, BPF_ANY);
}

static __always_inline int geo_match_v4(__be32 addr, __u8 policy_flag) {
    struct pfwd_geo_prefix_key_v4 key = {
        .prefixlen = 32,
        .addr = addr,
    };
    struct pfwd_geo_prefix_val *value = bpf_map_lookup_elem(&pfwd_geo_segments_v4, &key);
    return value && ((value->policy_flags & policy_flag) != 0);
}

static __always_inline int geo_match_v6(const __u8 addr[16], __u8 policy_flag) {
    struct pfwd_geo_prefix_key_v6 key = {
        .prefixlen = 128,
    };
    struct pfwd_geo_prefix_val *value;
    pfwd_memcpy16(key.addr, addr);
    value = bpf_map_lookup_elem(&pfwd_geo_segments_v6, &key);
    return value && ((value->policy_flags & policy_flag) != 0);
}

static __always_inline int whitelist_allowed_v4(__be32 addr, const struct pfwd_rule_val *rule) {
    int verdict = whitelist_cache_hit_v4(addr);
    int custom;
    int geo;

    if (verdict != PFWD_CACHE_UNKNOWN) {
        return verdict == PFWD_CACHE_ALLOW;
    }
    if (!rule) {
        return 0;
    }
    custom = rule->flags & PFWD_RULE_F_ALLOW_CUSTOM;
    geo = rule->flags & PFWD_RULE_F_ALLOW_GEO;
    if (geo) {
        verdict = (geo_match_v4(addr, 1) || (custom && whitelist_match_v4(addr))) ? PFWD_CACHE_ALLOW : PFWD_CACHE_DROP;
    } else {
        verdict = (custom && whitelist_match_v4(addr)) ? PFWD_CACHE_ALLOW : PFWD_CACHE_DROP;
    }
    whitelist_cache_store_v4(addr, verdict);
    return verdict == PFWD_CACHE_ALLOW;
}

static __always_inline int whitelist_allowed_v6(const __u8 addr[16], const struct pfwd_rule_val *rule) {
    int verdict = whitelist_cache_hit_v6(addr);
    int custom;
    int geo;

    if (verdict != PFWD_CACHE_UNKNOWN) {
        return verdict == PFWD_CACHE_ALLOW;
    }
    if (!rule) {
        return 0;
    }
    custom = rule->flags & PFWD_RULE_F_ALLOW_CUSTOM;
    geo = rule->flags & PFWD_RULE_F_ALLOW_GEO;
    if (geo) {
        verdict = (geo_match_v6(addr, 1) || (custom && whitelist_match_v6(addr))) ? PFWD_CACHE_ALLOW : PFWD_CACHE_DROP;
    } else {
        verdict = (custom && whitelist_match_v6(addr)) ? PFWD_CACHE_ALLOW : PFWD_CACHE_DROP;
    }
    whitelist_cache_store_v6(addr, verdict);
    return verdict == PFWD_CACHE_ALLOW;
}

static __always_inline int egress_whitelist_match_v4(__be32 addr) {
    struct pfwd_whitelist_key_v4 key = {
        .prefixlen = 32,
        .addr = addr,
    };
    __u8 *value = bpf_map_lookup_elem(&pfwd_egress_whitelist_v4, &key);
    return value != 0;
}

static __always_inline int egress_whitelist_cache_hit_v4(__be32 addr) {
    __u8 *value = bpf_map_lookup_elem(&pfwd_egress_whitelist_cache_v4, &addr);
    if (!value) {
        return PFWD_CACHE_UNKNOWN;
    }
    return *value == PFWD_CACHE_DROP ? PFWD_CACHE_DROP : PFWD_CACHE_ALLOW;
}

static __always_inline void egress_whitelist_cache_store_v4(__be32 addr, __u8 verdict) {
    __u8 value = verdict;
    bpf_map_update_elem(&pfwd_egress_whitelist_cache_v4, &addr, &value, BPF_ANY);
}

static __always_inline int egress_whitelist_match_v6(const __u8 addr[16]) {
    struct pfwd_whitelist_key_v6 key = {
        .prefixlen = 128,
    };
    __u8 *value;
    pfwd_memcpy16(key.addr, addr);
    value = bpf_map_lookup_elem(&pfwd_egress_whitelist_v6, &key);
    return value != 0;
}

static __always_inline int egress_whitelist_cache_hit_v6(const __u8 addr[16]) {
    struct pfwd_whitelist_cache_key_v6 key = {};
    __u8 *value;
    pfwd_memcpy16(key.addr, addr);
    value = bpf_map_lookup_elem(&pfwd_egress_whitelist_cache_v6, &key);
    if (!value) {
        return PFWD_CACHE_UNKNOWN;
    }
    return *value == PFWD_CACHE_DROP ? PFWD_CACHE_DROP : PFWD_CACHE_ALLOW;
}

static __always_inline void egress_whitelist_cache_store_v6(const __u8 addr[16], __u8 verdict) {
    struct pfwd_whitelist_cache_key_v6 key = {};
    __u8 value = verdict;
    pfwd_memcpy16(key.addr, addr);
    bpf_map_update_elem(&pfwd_egress_whitelist_cache_v6, &key, &value, BPF_ANY);
}

static __always_inline int egress_whitelist_allowed_v4(__be32 addr, const struct pfwd_settings *settings) {
    int verdict = egress_whitelist_cache_hit_v4(addr);
    int custom;
    int geo;

    if (verdict != PFWD_CACHE_UNKNOWN) {
        return verdict == PFWD_CACHE_ALLOW;
    }
    if (!settings) {
        return 0;
    }
    custom = settings->egress_whitelist_custom;
    geo = settings->egress_whitelist_geo;
    if (geo) {
        verdict = (geo_match_v4(addr, 2) || (custom && egress_whitelist_match_v4(addr))) ? PFWD_CACHE_ALLOW : PFWD_CACHE_DROP;
    } else {
        verdict = (custom && egress_whitelist_match_v4(addr)) ? PFWD_CACHE_ALLOW : PFWD_CACHE_DROP;
    }
    egress_whitelist_cache_store_v4(addr, verdict);
    return verdict == PFWD_CACHE_ALLOW;
}

static __always_inline int egress_whitelist_allowed_v6(const __u8 addr[16], const struct pfwd_settings *settings) {
    int verdict = egress_whitelist_cache_hit_v6(addr);
    int custom;
    int geo;

    if (verdict != PFWD_CACHE_UNKNOWN) {
        return verdict == PFWD_CACHE_ALLOW;
    }
    if (!settings) {
        return 0;
    }
    custom = settings->egress_whitelist_custom;
    geo = settings->egress_whitelist_geo;
    if (geo) {
        verdict = (geo_match_v6(addr, 2) || (custom && egress_whitelist_match_v6(addr))) ? PFWD_CACHE_ALLOW : PFWD_CACHE_DROP;
    } else {
        verdict = (custom && egress_whitelist_match_v6(addr)) ? PFWD_CACHE_ALLOW : PFWD_CACHE_DROP;
    }
    egress_whitelist_cache_store_v6(addr, verdict);
    return verdict == PFWD_CACHE_ALLOW;
}

static __always_inline __u64 rule_counter_billing_total(struct pfwd_counter *counter, __u64 base) {
    if (!counter) {
        return base;
    }
    return base + counter->billing_bytes;
}

static __always_inline __u64 reply_counter_billing_total(struct pfwd_reply_counter *counter) {
    if (!counter) {
        return 0;
    }
    return counter->billing_bytes;
}

static __always_inline __u64 user_counter_billing_total(struct pfwd_user_counter *counter, __u64 base) {
    if (!counter) {
        return base;
    }
    return base + counter->billing_bytes;
}

static __always_inline __u64 scaled_bytes(__u64 bytes, __u64 ratio) {
    if (ratio == 0 || ratio == PFWD_RATIO_SCALE) {
        return bytes;
    }
    return (bytes * ratio) / PFWD_RATIO_SCALE;
}

static __always_inline __u64 billed_delta_for_rule(const struct pfwd_rule_val *rule, __u64 input_delta, __u64 output_delta) {
    __u64 billed_delta;
    __u64 ratio = rule->traffic_ratio_scaled;

    billed_delta = scaled_bytes(input_delta, ratio) + scaled_bytes(output_delta, ratio);
    if (rule->traffic_mode != 1) {
        billed_delta *= 2;
    }
    return billed_delta;
}

static __always_inline void load_input_counters(
    const struct pfwd_rule_val *rule,
    struct pfwd_counter **rule_counter,
    struct pfwd_user_counter **user_counter
) {
    __u32 rule_id = rule->rule_id;
    __u32 user_id = rule->user_id;

    *rule_counter = 0;
    *user_counter = 0;
    if (rule->rule_limit_bytes > 0 || rule->billing_enabled) {
        *rule_counter = bpf_map_lookup_elem(&pfwd_rule_counters, &rule_id);
    }
    if (rule->user_limit_enabled) {
        *user_counter = bpf_map_lookup_elem(&pfwd_user_counters, &user_id);
    }
}

static __always_inline int traffic_over_limit(
    const struct pfwd_rule_val *rule,
    __u64 billed_delta,
    struct pfwd_counter *rule_counter,
    struct pfwd_user_counter *user_counter
) {
    struct pfwd_reply_counter *reply_counter;
    __u64 current_rule;
    __u64 current_user;
    if (rule->rule_limit_bytes > 0) {
        __u32 rule_id = rule->rule_id;
        reply_counter = bpf_map_lookup_elem(&pfwd_rule_reply_counters, &rule_id);
        current_rule = rule_counter_billing_total(rule_counter, rule->rule_billing_used_base_bytes) + reply_counter_billing_total(reply_counter);
        if (current_rule + billed_delta > rule->rule_limit_bytes) {
            return 1;
        }
    }
    if (rule->user_limit_bytes > 0) {
        current_user = user_counter_billing_total(user_counter, rule->user_billing_used_base_bytes);
        if (current_user + billed_delta > rule->user_limit_bytes) {
            return 1;
        }
    }
    return 0;
}

static __always_inline void init_counter_plan(const struct pfwd_rule_val *rule, struct pfwd_counter_plan *plan) {
    plan->rule_counter = 0;
    plan->user_counter = 0;
    plan->billed = 0;
    plan->flags = rule ? rule->flags : 0;
}

static __always_inline int counter_plan_needs_policy(const struct pfwd_counter_plan *plan) {
    return plan->flags & PFWD_RULE_F_NEEDS_POLICY;
}

static __always_inline int counter_plan_needs_counter(const struct pfwd_counter_plan *plan) {
    return plan->flags & PFWD_RULE_F_NEEDS_COUNTER;
}

static __always_inline int counter_plan_needs_quota(const struct pfwd_counter_plan *plan) {
    return plan->flags & PFWD_RULE_F_NEEDS_QUOTA;
}

static __always_inline void load_input_counter_plan(
    const struct pfwd_rule_val *rule,
    __u64 input_delta,
    struct pfwd_counter_plan *plan
) {
    if (!(counter_plan_needs_counter(plan) || counter_plan_needs_quota(plan))) {
        return;
    }
    plan->billed = billed_delta_for_rule(rule, input_delta, 0);
    load_input_counters(rule, &plan->rule_counter, &plan->user_counter);
}

static __always_inline int counter_plan_over_limit(const struct pfwd_rule_val *rule, const struct pfwd_counter_plan *plan) {
    if (!counter_plan_needs_quota(plan)) {
        return 0;
    }
    return traffic_over_limit(rule, plan->billed, plan->rule_counter, plan->user_counter);
}

static __always_inline void count_input_with_counters(
    const struct pfwd_rule_val *rule,
    __u64 bytes,
    __u64 packets,
    __u64 billed,
    struct pfwd_counter *rule_counter,
    struct pfwd_user_counter *user_counter
) {
    if (rule_counter) {
        rule_counter->input_bytes += bytes;
        rule_counter->input_packets += packets;
        if (rule->billing_enabled) {
            rule_counter->billing_bytes += billed;
        }
    }
    if (rule->user_limit_enabled && user_counter) {
        if (rule->billing_enabled) {
            user_counter->billing_bytes += billed;
        }
    }
}

static __always_inline void count_input_with_plan(
    const struct pfwd_rule_val *rule,
    __u64 bytes,
    __u64 packets,
    const struct pfwd_counter_plan *plan
) {
    if (!counter_plan_needs_counter(plan)) {
        return;
    }
    count_input_with_counters(rule, bytes, packets, plan->billed, plan->rule_counter, plan->user_counter);
}

static __always_inline void count_output(struct pfwd_conn_val *conn, __u64 bytes, __u64 packets) {
    struct pfwd_reply_counter *reply_counter;
    struct pfwd_user_counter *user_counter;
    __u32 key = conn->rule_id;
    __u64 billed = 0;

    if (!conn->billing_enabled && !conn->user_limit_enabled) {
        conn->bytes += bytes;
        conn->packets += packets;
        return;
    }
    if (conn->billing_enabled) {
        billed = scaled_bytes(bytes, conn->traffic_ratio_scaled);
        if (conn->traffic_mode != 1) {
            billed *= 2;
        }
    }
    reply_counter = bpf_map_lookup_elem(&pfwd_rule_reply_counters, &key);
    if (reply_counter) {
        reply_counter->output_bytes += bytes;
        reply_counter->output_packets += packets;
        if (conn->billing_enabled) {
            reply_counter->billing_bytes += billed;
        }
    }
    if (conn->user_limit_enabled) {
        key = conn->user_id;
        user_counter = bpf_map_lookup_elem(&pfwd_user_counters, &key);
        if (user_counter && conn->billing_enabled) {
            user_counter->billing_bytes += billed;
        }
    }
}

static __always_inline void count_drop_with_counter(const struct pfwd_rule_val *rule, __u64 bytes, void *unused_rule_counter) {
    struct pfwd_drop_counter *counter;
    __u32 key = rule->rule_id;
    (void)unused_rule_counter;
    counter = bpf_map_lookup_elem(&pfwd_rule_drop_counters, &key);
    if (counter) {
        counter->dropped_bytes += bytes;
        counter->dropped_packets += 1;
    }
}

static __always_inline void count_drop(const struct pfwd_rule_val *rule, __u64 bytes) {
    count_drop_with_counter(rule, bytes, 0);
}

static __always_inline void count_drop_with_plan(const struct pfwd_rule_val *rule, __u64 bytes, const struct pfwd_counter_plan *plan) {
    count_drop_with_counter(rule, bytes, plan ? plan->rule_counter : 0);
}

static __always_inline __u32 pfwd_hash_mix(__u32 value) {
    value ^= value >> 16;
    value *= 0x7feb352dU;
    value ^= value >> 15;
    value *= 0x846ca68bU;
    value ^= value >> 16;
    return value;
}

static __always_inline __be16 pfwd_ephemeral_port(__u32 hash) {
    __u16 port = 32768 + (hash % 28232);
    return bpf_htons(port);
}

static __always_inline __u32 pfwd_hash_addr16(const __u8 addr[16]) {
    const __u32 *words = (const __u32 *)addr;
    __u32 hash = 0x811c9dc5U;
#pragma unroll
    for (int i = 0; i < 4; i++) {
        hash ^= words[i];
        hash *= 0x01000193U;
    }
    return hash;
}

static __always_inline __be16 allocate_source_port_v4(
    struct pfwd_reverse_key *reverse_key,
    __be16 preferred,
    __be32 client_addr,
    __be32 listen_addr,
    __be16 target_port
) {
    __u32 hash = (__u32)preferred ^ client_addr ^ listen_addr ^ ipv4_from16(reverse_key->target_addr) ^ (__u32)target_port;
    reverse_key->source_port = preferred;
    if (!bpf_map_lookup_elem(&pfwd_reverse, reverse_key)) {
        return preferred;
    }
#pragma unroll
    for (int i = 0; i < 16; i++) {
        hash = pfwd_hash_mix(hash + i + 1);
        reverse_key->source_port = pfwd_ephemeral_port(hash);
        if (!bpf_map_lookup_elem(&pfwd_reverse, reverse_key)) {
            return reverse_key->source_port;
        }
    }
    return 0;
}

static __always_inline __be16 allocate_source_port_v6(
    struct pfwd_reverse_key *reverse_key,
    __be16 preferred,
    const __u8 client_addr[16],
    const __u8 listen_addr[16],
    __be16 target_port
) {
    __u32 hash = (__u32)preferred ^ (__u32)target_port;
    hash ^= pfwd_hash_addr16(client_addr);
    hash ^= pfwd_hash_addr16(listen_addr);
    hash ^= pfwd_hash_addr16(reverse_key->target_addr);
    reverse_key->source_port = preferred;
    if (!bpf_map_lookup_elem(&pfwd_reverse, reverse_key)) {
        return preferred;
    }
#pragma unroll
    for (int i = 0; i < 16; i++) {
        hash = pfwd_hash_mix(hash + i + 1);
        reverse_key->source_port = pfwd_ephemeral_port(hash);
        if (!bpf_map_lookup_elem(&pfwd_reverse, reverse_key)) {
            return reverse_key->source_port;
        }
    }
    return 0;
}

static __always_inline int fib_redirect_v4(struct xdp_md *ctx, struct ethhdr *eth, struct ipv4hdr_min *ip4, __u8 protocol, __be16 sport, __be16 dport) {
    struct bpf_fib_lookup params = {};
    params.family = AF_INET;
    params.tos = ip4->tos;
    params.l4_protocol = protocol;
    params.sport = sport;
    params.dport = dport;
    params.tot_len = bpf_ntohs(ip4->tot_len);
    params.ipv4_src = ip4->saddr;
    params.ipv4_dst = ip4->daddr;
    params.ifindex = ctx->ingress_ifindex;
    if (bpf_fib_lookup(ctx, &params, sizeof(params), BPF_FIB_LOOKUP_DIRECT) != BPF_FIB_LKUP_RET_SUCCESS) {
        stat_inc(PFWD_STAT_DROPPED);
        return XDP_DROP;
    }
    pfwd_memcpy6(eth->h_source, params.smac);
    pfwd_memcpy6(eth->h_dest, params.dmac);
    return bpf_redirect(params.ifindex, 0);
}

static __always_inline int fib_redirect_v6(struct xdp_md *ctx, struct ethhdr *eth, struct ipv6hdr_min *ip6, __u8 protocol, __be16 sport, __be16 dport) {
    struct bpf_fib_lookup params = {};
    const __u32 *src = (const __u32 *)ip6->saddr;
    const __u32 *dst = (const __u32 *)ip6->daddr;
    params.family = AF_INET6;
    params.l4_protocol = protocol;
    params.sport = sport;
    params.dport = dport;
    params.tot_len = bpf_ntohs(ip6->payload_len) + sizeof(*ip6);
    params.ipv6_src[0] = src[0];
    params.ipv6_src[1] = src[1];
    params.ipv6_src[2] = src[2];
    params.ipv6_src[3] = src[3];
    params.ipv6_dst[0] = dst[0];
    params.ipv6_dst[1] = dst[1];
    params.ipv6_dst[2] = dst[2];
    params.ipv6_dst[3] = dst[3];
    params.ifindex = ctx->ingress_ifindex;
    if (bpf_fib_lookup(ctx, &params, sizeof(params), BPF_FIB_LOOKUP_DIRECT) != BPF_FIB_LKUP_RET_SUCCESS) {
        stat_inc(PFWD_STAT_DROPPED);
        return XDP_DROP;
    }
    pfwd_memcpy6(eth->h_source, params.smac);
    pfwd_memcpy6(eth->h_dest, params.dmac);
    return bpf_redirect(params.ifindex, 0);
}

static __always_inline int match_http(const __u8 *payload, __u32 len) {
    if (len >= 8 && payload[0] == 'O' && payload[1] == 'P' && payload[2] == 'T' && payload[3] == 'I' && payload[4] == 'O' && payload[5] == 'N' && payload[6] == 'S' && payload[7] == ' ') return 1;
    if (len >= 4 && payload[0] == 'G' && payload[1] == 'E' && payload[2] == 'T' && payload[3] == ' ') return 1;
    if (len >= 5 && payload[0] == 'P' && payload[1] == 'O' && payload[2] == 'S' && payload[3] == 'T' && payload[4] == ' ') return 1;
    if (len >= 5 && payload[0] == 'H' && payload[1] == 'E' && payload[2] == 'A' && payload[3] == 'D' && payload[4] == ' ') return 1;
    if (len >= 4 && payload[0] == 'P' && payload[1] == 'U' && payload[2] == 'T' && payload[3] == ' ') return 1;
    if (len >= 6 && payload[0] == 'P' && payload[1] == 'A' && payload[2] == 'T' && payload[3] == 'C' && payload[4] == 'H' && payload[5] == ' ') return 1;
    if (len >= 6 && payload[0] == 'T' && payload[1] == 'R' && payload[2] == 'A' && payload[3] == 'C' && payload[4] == 'E' && payload[5] == ' ') return 1;
    if (len >= 7 && payload[0] == 'D' && payload[1] == 'E' && payload[2] == 'L' && payload[3] == 'E' && payload[4] == 'T' && payload[5] == 'E' && payload[6] == ' ') return 1;
    if (len >= 8 && payload[0] == 'C' && payload[1] == 'O' && payload[2] == 'N' && payload[3] == 'N' && payload[4] == 'E' && payload[5] == 'C' && payload[6] == 'T' && payload[7] == ' ') return 1;
    if (len >= 8 && payload[0] == 'P' && payload[1] == 'R' && payload[2] == 'I' && payload[3] == ' ' && payload[4] == '*' && payload[5] == ' ' && payload[6] == 'H' && payload[7] == 'T') return 1;
    return 0;
}

static __always_inline int match_tls_client_hello(const __u8 *payload, __u32 len) {
    return len >= 6 && payload[0] == 0x16 && payload[1] == 0x03 && payload[2] <= 0x04 && payload[5] == 0x01;
}

static __always_inline int match_socks(const __u8 *payload, __u32 len) {
    if (len >= 3 && payload[0] == 0x05 && payload[1] >= 0x01 && payload[1] <= 0x10) return 1;
    if (len >= 8 && payload[0] == 0x04 && (payload[1] == 0x01 || payload[1] == 0x02)) return 1;
    return 0;
}

static __always_inline int inspect_guard_prefix(const struct pfwd_guard_prefix_val *prefix, const struct pfwd_rule_val *rule) {
    int http_possible = 0;
    int tls_possible = 0;
    int socks_possible = 0;
    __u16 flags = rule ? rule->flags : 0;
    int block_http = flags & PFWD_RULE_F_BLOCK_HTTP;
    int block_tls = flags & PFWD_RULE_F_BLOCK_TLS;
    int block_socks = flags & PFWD_RULE_F_BLOCK_SOCKS;

    if (prefix->seen_len >= 3) {
        if (block_http) {
            http_possible = match_http(prefix->prefix, prefix->seen_len);
        }
        if (block_socks) {
            socks_possible = match_socks(prefix->prefix, prefix->seen_len);
        }
    }
    if (prefix->seen_len >= 6 && block_tls) {
        tls_possible = match_tls_client_hello(prefix->prefix, prefix->seen_len);
    }
    if (prefix->seen_len >= 3 && (!block_tls || prefix->seen_len >= 6)) {
        if ((!block_http || !http_possible) &&
            (!block_socks || !socks_possible) &&
            (!block_tls || !tls_possible)) {
            return PFWD_INSPECT_ALLOW;
        }
    }
    if ((block_http && http_possible) ||
        (block_socks && socks_possible) ||
        (block_tls && tls_possible)) {
        stat_inc(PFWD_STAT_PROTOCOL_DROPPED);
        return PFWD_INSPECT_DROP;
    }
    if (prefix->seen_len < 8) {
        return PFWD_INSPECT_NEED_MORE;
    }
    return PFWD_INSPECT_ALLOW;
}

static __always_inline int flow_cached_verdict(struct pfwd_flow_key *key) {
    __u8 *value = bpf_map_lookup_elem(&pfwd_allowed_flows, key);
    if (!value) {
        return PFWD_CACHE_UNKNOWN;
    }
    return *value == PFWD_CACHE_DROP ? PFWD_CACHE_DROP : PFWD_CACHE_ALLOW;
}

static __always_inline void flow_store_verdict(struct pfwd_flow_key *key, __u8 verdict) {
    __u8 value = verdict;
    bpf_map_update_elem(&pfwd_allowed_flows, key, &value, BPF_ANY);
}

static __always_inline void flow_store_allow(struct pfwd_flow_key *key) {
    flow_store_verdict(key, PFWD_CACHE_ALLOW);
}

static __always_inline void flow_store_drop(struct pfwd_flow_key *key) {
    flow_store_verdict(key, PFWD_CACHE_DROP);
}

static __always_inline int host_egress_flow_cached_verdict(struct pfwd_flow_key *key) {
    __u8 *value = bpf_map_lookup_elem(&pfwd_host_egress_flows, key);
    if (!value) {
        return PFWD_CACHE_UNKNOWN;
    }
    return *value == PFWD_CACHE_DROP ? PFWD_CACHE_DROP : PFWD_CACHE_ALLOW;
}

static __always_inline void host_egress_flow_store_verdict(struct pfwd_flow_key *key, __u8 verdict) {
    __u8 value = verdict;
    bpf_map_update_elem(&pfwd_host_egress_flows, key, &value, BPF_ANY);
}

static __always_inline void host_egress_flow_store_allow(struct pfwd_flow_key *key) {
    host_egress_flow_store_verdict(key, PFWD_CACHE_ALLOW);
}

static __always_inline void host_egress_flow_store_drop(struct pfwd_flow_key *key) {
    host_egress_flow_store_verdict(key, PFWD_CACHE_DROP);
}

static __always_inline void count_host_egress_drop(void) {
    stat_inc(PFWD_STAT_DROPPED);
    stat_inc(PFWD_STAT_HOST_EGRESS_DROPPED);
}

static __always_inline void load_guard_payload_prefix(
    const __u8 *payload,
    void *data_end,
    struct pfwd_guard_prefix_val *prefix
) {
    if (!prefix) {
        return;
    }
    prefix->seen_len = 0;
    if ((void *)(payload + 1) > data_end) {
        return;
    }
    prefix->prefix[0] = payload[0];
    prefix->seen_len = 1;
    if ((void *)(payload + 2) > data_end) {
        return;
    }
    prefix->prefix[1] = payload[1];
    prefix->seen_len = 2;
    if ((void *)(payload + 3) > data_end) {
        return;
    }
    prefix->prefix[2] = payload[2];
    prefix->seen_len = 3;
    if ((void *)(payload + 4) > data_end) {
        return;
    }
    prefix->prefix[3] = payload[3];
    prefix->seen_len = 4;
    if ((void *)(payload + 5) > data_end) {
        return;
    }
    prefix->prefix[4] = payload[4];
    prefix->seen_len = 5;
    if ((void *)(payload + 6) > data_end) {
        return;
    }
    prefix->prefix[5] = payload[5];
    prefix->seen_len = 6;
    if ((void *)(payload + 7) > data_end) {
        return;
    }
    prefix->prefix[6] = payload[6];
    prefix->seen_len = 7;
    if ((void *)(payload + 8) > data_end) {
        return;
    }
    prefix->prefix[7] = payload[7];
    prefix->seen_len = 8;
}

static __always_inline int port_skipped(__be16 port) {
    __u32 key = bpf_ntohs(port);
    __u8 *value = bpf_map_lookup_elem(&pfwd_protocol_skip_ports, &key);
    return value && *value != 0;
}

static __always_inline int ingress_guard_bypassed(const struct pfwd_rule_val *rule, __be16 port) {
    return rule &&
           (rule->flags & PFWD_RULE_F_HAS_SKIP_PORTS) &&
           (rule->flags & (PFWD_RULE_F_NEEDS_ALLOW | PFWD_RULE_F_NEEDS_GUARD)) &&
           port_skipped(port);
}

static __always_inline struct pfwd_rule_val *lookup_forward_rule(
    __u8 family,
    __u8 protocol,
    __be16 listen_port,
    const __u8 listen_addr[16]
) {
    struct pfwd_rule_key exact_key = {
        .family = family,
        .protocol = protocol,
        .listen_port = listen_port,
    };
    struct pfwd_rule_key wildcard_key = {
        .family = family,
        .protocol = protocol,
        .listen_port = listen_port,
    };
    struct pfwd_rule_val *rule;

    pfwd_memcpy16(exact_key.listen_addr, listen_addr);
    rule = bpf_map_lookup_elem(&pfwd_rules, &exact_key);
    if (rule) {
        return rule;
    }
    return bpf_map_lookup_elem(&pfwd_rules, &wildcard_key);
}

static __always_inline struct pfwd_rule_val *lookup_forward_rule_v4(
    __u8 protocol,
    __be16 listen_port,
    __be32 listen_addr
) {
    struct pfwd_rule_key exact_key = {
        .family = 4,
        .protocol = protocol,
        .listen_port = listen_port,
    };
    struct pfwd_rule_key wildcard_key = {
        .family = 4,
        .protocol = protocol,
        .listen_port = listen_port,
    };
    struct pfwd_rule_val *rule;

    *(__be32 *)&exact_key.listen_addr[0] = listen_addr;
    rule = bpf_map_lookup_elem(&pfwd_rules, &exact_key);
    if (rule) {
        return rule;
    }
    return bpf_map_lookup_elem(&pfwd_rules, &wildcard_key);
}

static __always_inline int protocol_guard_active(const struct pfwd_rule_val *rule) {
    return rule && (rule->flags & PFWD_RULE_F_NEEDS_GUARD);
}

static __always_inline struct pfwd_settings *lookup_settings(void) {
    __u32 settings_key = 0;
    return bpf_map_lookup_elem(&pfwd_settings, &settings_key);
}

static __always_inline int append_guard_prefix(
    const struct pfwd_guard_prefix_val *loaded_prefix,
    struct pfwd_guard_prefix_val *state
) {
    __u32 offset;
    __u32 copy_len;
    __u64 current;
    __u64 incoming;
    __u64 merged;

    if (!loaded_prefix || !state) {
        return -1;
    }
    copy_len = loaded_prefix->seen_len;
    offset = state->seen_len;
    if (offset >= 8 || copy_len == 0) {
        return 0;
    }
    if (copy_len > 8 - offset) {
        copy_len = 8 - offset;
    }

    current = *(__u64 *)state->prefix;
    incoming = *(__u64 *)loaded_prefix->prefix;
    merged = current | (incoming << (offset * 8));
    switch (offset + copy_len) {
    case 1:
        merged &= 0x00000000000000ffULL;
        break;
    case 2:
        merged &= 0x000000000000ffffULL;
        break;
    case 3:
        merged &= 0x0000000000ffffffULL;
        break;
    case 4:
        merged &= 0x00000000ffffffffULL;
        break;
    case 5:
        merged &= 0x000000ffffffffffULL;
        break;
    case 6:
        merged &= 0x0000ffffffffffffULL;
        break;
    case 7:
        merged &= 0x00ffffffffffffffULL;
        break;
    default:
        break;
    }
    *(__u64 *)state->prefix = merged;
    state->seen_len = offset + copy_len;
    return 0;
}

static __always_inline int inspect_xdp_tcp_flow(
    void *payload_start,
    void *data_end,
    struct pfwd_rule_val *rule,
    __u64 packet_len,
    __u8 family,
    const __u8 saddr[16],
    const __u8 daddr[16],
    __be16 sport,
    __be16 dport
) {
    struct pfwd_flow_key flow = {};
    struct pfwd_guard_prefix_val next_prefix = {};
    struct pfwd_guard_prefix_val payload_prefix = {};
    struct pfwd_guard_prefix_val *stored_prefix;
    int verdict;

    if (!protocol_guard_active(rule)) {
        return XDP_PASS;
    }
    if (ingress_guard_bypassed(rule, dport)) {
        return XDP_PASS;
    }
    flow.family = family;
    flow.protocol = IPPROTO_TCP;
    flow.sport = sport;
    flow.dport = dport;
    pfwd_memcpy16(flow.saddr, saddr);
    pfwd_memcpy16(flow.daddr, daddr);
    verdict = flow_cached_verdict(&flow);
    if (verdict == PFWD_CACHE_ALLOW) {
        return XDP_PASS;
    }
    if (verdict == PFWD_CACHE_DROP) {
        count_drop(rule, packet_len);
        return XDP_DROP;
    }
    load_guard_payload_prefix((const __u8 *)payload_start, data_end, &payload_prefix);
    if (payload_prefix.seen_len == 0) {
        return XDP_PASS;
    }
    stored_prefix = bpf_map_lookup_elem(&pfwd_guard_prefixes, &flow);
    if (!stored_prefix && payload_prefix.seen_len >= 8) {
        verdict = inspect_guard_prefix(&payload_prefix, rule);
        if (verdict == PFWD_INSPECT_DROP) {
            flow_store_drop(&flow);
            count_drop(rule, packet_len);
            return XDP_DROP;
        }
        flow_store_allow(&flow);
        return XDP_PASS;
    }
    if (stored_prefix) {
        next_prefix = *stored_prefix;
    }
    if (append_guard_prefix(&payload_prefix, &next_prefix) < 0) {
        return XDP_PASS;
    }
    verdict = inspect_guard_prefix(&next_prefix, rule);
    if (verdict == PFWD_INSPECT_DROP) {
        flow_store_drop(&flow);
        count_drop(rule, packet_len);
        return XDP_DROP;
    }
    if (verdict == PFWD_INSPECT_NEED_MORE) {
        bpf_map_update_elem(&pfwd_guard_prefixes, &flow, &next_prefix, BPF_ANY);
        return XDP_PASS;
    }
    flow_store_allow(&flow);
    return XDP_PASS;
}

static __always_inline int inspect_xdp_tcp_flow_v4(
    void *payload_start,
    void *data_end,
    struct pfwd_rule_val *rule,
    __u64 packet_len,
    __be32 saddr,
    __be32 daddr,
    __be16 sport,
    __be16 dport
) {
    struct pfwd_flow_key flow = {};
    struct pfwd_guard_prefix_val next_prefix = {};
    struct pfwd_guard_prefix_val payload_prefix = {};
    struct pfwd_guard_prefix_val *stored_prefix;
    int verdict;

    if (!protocol_guard_active(rule)) {
        return XDP_PASS;
    }
    if (ingress_guard_bypassed(rule, dport)) {
        return XDP_PASS;
    }
    flow.family = 4;
    flow.protocol = IPPROTO_TCP;
    flow.sport = sport;
    flow.dport = dport;
    *(__be32 *)&flow.saddr[0] = saddr;
    *(__be32 *)&flow.daddr[0] = daddr;
    verdict = flow_cached_verdict(&flow);
    if (verdict == PFWD_CACHE_ALLOW) {
        return XDP_PASS;
    }
    if (verdict == PFWD_CACHE_DROP) {
        count_drop(rule, packet_len);
        return XDP_DROP;
    }
    load_guard_payload_prefix((const __u8 *)payload_start, data_end, &payload_prefix);
    if (payload_prefix.seen_len == 0) {
        return XDP_PASS;
    }
    stored_prefix = bpf_map_lookup_elem(&pfwd_guard_prefixes, &flow);
    if (!stored_prefix && payload_prefix.seen_len >= 8) {
        verdict = inspect_guard_prefix(&payload_prefix, rule);
        if (verdict == PFWD_INSPECT_DROP) {
            flow_store_drop(&flow);
            count_drop(rule, packet_len);
            return XDP_DROP;
        }
        flow_store_allow(&flow);
        return XDP_PASS;
    }
    if (stored_prefix) {
        next_prefix = *stored_prefix;
    }
    if (append_guard_prefix(&payload_prefix, &next_prefix) < 0) {
        return XDP_PASS;
    }
    verdict = inspect_guard_prefix(&next_prefix, rule);
    if (verdict == PFWD_INSPECT_DROP) {
        flow_store_drop(&flow);
        count_drop(rule, packet_len);
        return XDP_DROP;
    }
    if (verdict == PFWD_INSPECT_NEED_MORE) {
        bpf_map_update_elem(&pfwd_guard_prefixes, &flow, &next_prefix, BPF_ANY);
        return XDP_PASS;
    }
    flow_store_allow(&flow);
    return XDP_PASS;
}

static __always_inline void adjust_tcp_mss(struct tcphdr_min *tcp, void *data_end, __u16 value) {
    __u32 tcp_len = (__u32)(tcp->doff_res >> 4) * 4;
    __u32 opt_off = sizeof(*tcp);
    if (value == 0 || (tcp->flags & 0x02) == 0) {
        return;
    }
    if (tcp_len < sizeof(*tcp)) {
        return;
    }
#pragma unroll
    for (int i = 0; i < 6; i++) {
        __u8 *opt = (__u8 *)tcp + opt_off;
        if (opt_off + 1 > tcp_len || (void *)(opt + 1) > data_end) {
            return;
        }
        __u8 kind = opt[0];
        if (kind == 0) {
            return;
        }
        if (kind == 1) {
            opt_off += 1;
            continue;
        }
        if (opt_off + 2 > tcp_len || (void *)(opt + 2) > data_end) {
            return;
        }
        __u8 len = opt[1];
        if (len < 2 || opt_off + len > tcp_len) {
            return;
        }
        if (kind == 2 && len == 4) {
            __be16 *mss = (__be16 *)(opt + 2);
            if ((void *)(mss + 1) > data_end) {
                return;
            }
            __be16 old = *mss;
            __be16 new_value = bpf_htons(value);
            if (bpf_ntohs(old) > value) {
                *mss = new_value;
                tcp->check = csum_replace16(tcp->check, old, new_value);
            }
            return;
        }
        opt_off += len;
    }
}

static __always_inline int tc_redirect_external(const struct pfwd_settings *settings) {
    if (!settings || settings->external_ifindex == 0) {
        return TC_ACT_SHOT;
    }
    return bpf_redirect_neigh(settings->external_ifindex, 0, 0, 0);
}

static __always_inline struct bpf_sock *lookup_local_socket_v4(
    void *ctx,
    __u8 protocol,
    __be32 client_addr,
    __be32 target_addr,
    __be16 client_port,
    __be16 target_port
) {
    struct bpf_sock_tuple tuple = {};
    tuple.ipv4.saddr = client_addr;
    tuple.ipv4.daddr = target_addr;
    tuple.ipv4.sport = client_port;
    tuple.ipv4.dport = target_port;
    if (protocol == IPPROTO_TCP) {
        return bpf_sk_lookup_tcp(ctx, &tuple, sizeof(tuple.ipv4), BPF_F_CURRENT_NETNS, 0);
    }
    return bpf_sk_lookup_udp(ctx, &tuple, sizeof(tuple.ipv4), BPF_F_CURRENT_NETNS, 0);
}

static __always_inline struct bpf_sock *lookup_local_socket_v6(
    void *ctx,
    __u8 protocol,
    const __u8 client_addr[16],
    const __u8 target_addr[16],
    __be16 client_port,
    __be16 target_port
) {
    struct bpf_sock_tuple tuple = {};
    __builtin_memcpy(tuple.ipv6.saddr, client_addr, sizeof(tuple.ipv6.saddr));
    __builtin_memcpy(tuple.ipv6.daddr, target_addr, sizeof(tuple.ipv6.daddr));
    tuple.ipv6.sport = client_port;
    tuple.ipv6.dport = target_port;
    if (protocol == IPPROTO_TCP) {
        return bpf_sk_lookup_tcp(ctx, &tuple, sizeof(tuple.ipv6), BPF_F_CURRENT_NETNS, 0);
    }
    return bpf_sk_lookup_udp(ctx, &tuple, sizeof(tuple.ipv6), BPF_F_CURRENT_NETNS, 0);
}

static __always_inline int prepare_local_conn_v4(
    __be32 client_addr,
    __be32 listen_addr,
    __be16 client_port,
    __be16 listen_port,
    __u8 protocol,
    __u8 conn_state,
    const struct pfwd_rule_val *rule,
    struct pfwd_scratch *scratch,
    __u64 packet_len
) {
    struct pfwd_conn_key conn_key;
    struct pfwd_conn_val *existing_conn;
    __be32 source_addr = rule_snat_fixed(rule) ? ipv4_from16(rule->snat_addr) : listen_addr;
    __be16 source_port;

    if (!scratch) {
        stat_inc(PFWD_STAT_DROPPED);
        return -1;
    }
    fill_conn_key_v4(&conn_key, protocol, client_addr, listen_addr, client_port, listen_port, rule->target_port, rule->target_addr);
    existing_conn = bpf_map_lookup_elem(&pfwd_connections, &conn_key);
    if (existing_conn) {
        return 0;
    }
    __builtin_memset(&scratch->conn, 0, sizeof(scratch->conn));

    init_reverse_alloc_key_v4(&scratch->reverse_key, protocol, rule->target_port, source_addr, rule->target_addr);
    source_port = allocate_source_port_v4(&scratch->reverse_key, client_port, client_addr, listen_addr, rule->target_port);
    if (source_port == 0) {
        stat_inc(PFWD_STAT_DROPPED);
        count_drop(rule, packet_len);
        return -1;
    }

    scratch->conn.rule_id = rule->rule_id;
    scratch->conn.user_id = rule->user_id;
    set_ipv4_in16(scratch->conn.client_addr, client_addr);
    set_ipv4_in16(scratch->conn.listen_addr, listen_addr);
    set_ipv4_in16(scratch->conn.source_addr, source_addr);
    scratch->conn.client_port = client_port;
    scratch->conn.source_port = source_port;
    scratch->conn.listen_port = listen_port;
    scratch->conn.traffic_ratio_scaled = rule->traffic_ratio_scaled;
    scratch->conn.traffic_mode = rule->traffic_mode;
    scratch->conn.user_limit_enabled = rule->user_limit_enabled;
    scratch->conn.billing_enabled = rule->billing_enabled;
    if (protocol == IPPROTO_TCP) {
        record_new_tcp_state(&scratch->conn, conn_state);
    }
    bpf_map_update_elem(&pfwd_connections, &conn_key, &scratch->conn, BPF_ANY);

    scratch->reverse_key.source_port = source_port;
    bpf_map_update_elem(&pfwd_reverse, &scratch->reverse_key, &scratch->conn, BPF_ANY);
    return 0;
}

static __always_inline int prepare_local_conn_v6(
    const __u8 client_addr[16],
    const __u8 listen_addr[16],
    __be16 client_port,
    __be16 listen_port,
    __u8 protocol,
    __u8 conn_state,
    const struct pfwd_rule_val *rule,
    struct pfwd_scratch *scratch,
    __u64 packet_len
) {
    struct pfwd_conn_key conn_key;
    struct pfwd_conn_val *existing_conn;
    const __u8 *source_addr = rule_snat_fixed(rule) ? rule->snat_addr : listen_addr;
    __be16 source_port;

    if (!scratch) {
        stat_inc(PFWD_STAT_DROPPED);
        return -1;
    }
    fill_conn_key_v6(&conn_key, protocol, client_addr, listen_addr, client_port, listen_port, rule->target_port, rule->target_addr);
    existing_conn = bpf_map_lookup_elem(&pfwd_connections, &conn_key);
    if (existing_conn) {
        return 0;
    }
    __builtin_memset(&scratch->conn, 0, sizeof(scratch->conn));

    init_reverse_alloc_key_v6(&scratch->reverse_key, protocol, rule->target_port, source_addr, rule->target_addr);
    source_port = allocate_source_port_v6(&scratch->reverse_key, client_port, client_addr, listen_addr, rule->target_port);
    if (source_port == 0) {
        stat_inc(PFWD_STAT_DROPPED);
        count_drop(rule, packet_len);
        return -1;
    }

    scratch->conn.rule_id = rule->rule_id;
    scratch->conn.user_id = rule->user_id;
    pfwd_memcpy16(scratch->conn.client_addr, client_addr);
    pfwd_memcpy16(scratch->conn.listen_addr, listen_addr);
    pfwd_memcpy16(scratch->conn.source_addr, source_addr);
    scratch->conn.client_port = client_port;
    scratch->conn.source_port = source_port;
    scratch->conn.listen_port = listen_port;
    scratch->conn.traffic_ratio_scaled = rule->traffic_ratio_scaled;
    scratch->conn.traffic_mode = rule->traffic_mode;
    scratch->conn.user_limit_enabled = rule->user_limit_enabled;
    scratch->conn.billing_enabled = rule->billing_enabled;
    if (protocol == IPPROTO_TCP) {
        record_new_tcp_state(&scratch->conn, conn_state);
    }
    bpf_map_update_elem(&pfwd_connections, &conn_key, &scratch->conn, BPF_ANY);

    scratch->reverse_key.source_port = source_port;
    bpf_map_update_elem(&pfwd_reverse, &scratch->reverse_key, &scratch->conn, BPF_ANY);
    return 0;
}

static __always_inline int tc_local_forward_v4(
    void *ctx,
    void *data_end,
    struct ipv4hdr_min *ip4,
    __u32 ihl,
    __u8 protocol,
    __be16 sport,
    __be16 dport,
    struct pfwd_rule_val *rule,
    __u64 packet_len
) {
    struct bpf_sock *sk;
    __u8 conn_state = PFWD_CONN_STATE_NONE;
    struct pfwd_counter_plan counters = {};
    int guard_bypassed = ingress_guard_bypassed(rule, dport);

    init_counter_plan(rule, &counters);
    if (!guard_bypassed && rule_needs_allow(rule) && !whitelist_allowed_v4(ip4->saddr, rule)) {
        stat_inc(PFWD_STAT_WHITELIST_DROPPED);
        count_drop_with_plan(rule, packet_len, &counters);
        return TC_ACT_SHOT;
    }
    if (protocol == IPPROTO_TCP) {
        struct tcphdr_min *tcp = (void *)ip4 + ihl;
        __u32 tcp_len = (__u32)(tcp->doff_res >> 4) * 4;
        void *payload_start = (void *)tcp + tcp_len;
        if (tcp_len < sizeof(*tcp) || (void *)(tcp + 1) > data_end) {
            stat_inc(PFWD_STAT_PARSE_SKIPPED);
            return TC_ACT_OK;
        }
        if (!guard_bypassed && rule_needs_guard(rule)) {
            if (inspect_xdp_tcp_flow_v4(payload_start, data_end, rule, packet_len, ip4->saddr, ip4->daddr, sport, dport) == XDP_DROP) {
                return TC_ACT_SHOT;
            }
        }
        conn_state = tcp_syn_only(tcp) ? PFWD_CONN_STATE_TCP_SYN_PENDING : PFWD_CONN_STATE_TCP_ESTABLISHED;
    }
    if (counter_plan_needs_policy(&counters)) {
        load_input_counter_plan(rule, packet_len, &counters);
        if (counter_plan_over_limit(rule, &counters)) {
            stat_inc(PFWD_STAT_QUOTA_DROPPED);
            count_drop_with_plan(rule, packet_len, &counters);
            return TC_ACT_SHOT;
        }
    }
    sk = lookup_local_socket_v4(ctx, protocol, ip4->saddr, ipv4_from16(rule->target_addr), sport, rule->target_port);
    if (!sk) {
        stat_inc(PFWD_STAT_DROPPED);
        count_drop_with_plan(rule, packet_len, &counters);
        return TC_ACT_SHOT;
    }
    bpf_sk_release(sk);
    {
        __u32 scratch_key = 0;
        struct pfwd_scratch *scratch = bpf_map_lookup_elem(&pfwd_scratch, &scratch_key);
        if (prepare_local_conn_v4(ip4->saddr, ip4->daddr, sport, dport, protocol, conn_state, rule, scratch, packet_len) < 0) {
            return TC_ACT_SHOT;
        }
    }
    count_input_with_plan(rule, packet_len, 1, &counters);
    stat_inc(PFWD_STAT_FORWARDED);
    return TC_ACT_OK;
}

static __always_inline int tc_local_forward_v6(
    void *ctx,
    void *data_end,
    struct ipv6hdr_min *ip6,
    __u8 protocol,
    __be16 sport,
    __be16 dport,
    struct pfwd_rule_val *rule,
    __u64 packet_len
) {
    struct bpf_sock *sk;
    __u8 conn_state = PFWD_CONN_STATE_NONE;
    struct pfwd_counter_plan counters = {};
    int guard_bypassed = ingress_guard_bypassed(rule, dport);

    init_counter_plan(rule, &counters);
    if (!guard_bypassed && rule_needs_allow(rule) && !whitelist_allowed_v6(ip6->saddr, rule)) {
        stat_inc(PFWD_STAT_WHITELIST_DROPPED);
        count_drop_with_plan(rule, packet_len, &counters);
        return TC_ACT_SHOT;
    }
    if (protocol == IPPROTO_TCP) {
        struct tcphdr_min *tcp = (void *)(ip6 + 1);
        __u32 tcp_len = (__u32)(tcp->doff_res >> 4) * 4;
        void *payload_start = (void *)tcp + tcp_len;
        if (tcp_len < sizeof(*tcp) || (void *)(tcp + 1) > data_end) {
            stat_inc(PFWD_STAT_PARSE_SKIPPED);
            return TC_ACT_OK;
        }
        if (!guard_bypassed && rule_needs_guard(rule)) {
            if (inspect_xdp_tcp_flow(payload_start, data_end, rule, packet_len, 6, ip6->saddr, ip6->daddr, sport, dport) == XDP_DROP) {
                return TC_ACT_SHOT;
            }
        }
        conn_state = tcp_syn_only(tcp) ? PFWD_CONN_STATE_TCP_SYN_PENDING : PFWD_CONN_STATE_TCP_ESTABLISHED;
    }
    if (counter_plan_needs_policy(&counters)) {
        load_input_counter_plan(rule, packet_len, &counters);
        if (counter_plan_over_limit(rule, &counters)) {
            stat_inc(PFWD_STAT_QUOTA_DROPPED);
            count_drop_with_plan(rule, packet_len, &counters);
            return TC_ACT_SHOT;
        }
    }
    sk = lookup_local_socket_v6(ctx, protocol, ip6->saddr, rule->target_addr, sport, rule->target_port);
    if (!sk) {
        stat_inc(PFWD_STAT_DROPPED);
        count_drop_with_plan(rule, packet_len, &counters);
        return TC_ACT_SHOT;
    }
    bpf_sk_release(sk);
    {
        __u32 scratch_key = 0;
        struct pfwd_scratch *scratch = bpf_map_lookup_elem(&pfwd_scratch, &scratch_key);
        if (prepare_local_conn_v6(ip6->saddr, ip6->daddr, sport, dport, protocol, conn_state, rule, scratch, packet_len) < 0) {
            return TC_ACT_SHOT;
        }
    }
    count_input_with_plan(rule, packet_len, 1, &counters);
    stat_inc(PFWD_STAT_FORWARDED);
    return TC_ACT_OK;
}

static __always_inline int tc_ingress_allowed_v4(
    struct ipv4hdr_min *ip4,
    struct pfwd_rule_val *rule,
    __be16 dport,
    __u64 packet_len
) {
    if (!rule) {
        return 1;
    }
    if (ingress_guard_bypassed(rule, dport) || !rule_needs_allow(rule)) {
        return 1;
    }
    if (whitelist_allowed_v4(ip4->saddr, rule)) {
        return 1;
    }
    stat_inc(PFWD_STAT_WHITELIST_DROPPED);
    count_drop(rule, packet_len);
    return 0;
}

static __always_inline int tc_ingress_allowed_v6(
    struct ipv6hdr_min *ip6,
    struct pfwd_rule_val *rule,
    __be16 dport,
    __u64 packet_len
) {
    if (!rule) {
        return 1;
    }
    if (ingress_guard_bypassed(rule, dport) || !rule_needs_allow(rule)) {
        return 1;
    }
    if (whitelist_allowed_v6(ip6->saddr, rule)) {
        return 1;
    }
    stat_inc(PFWD_STAT_WHITELIST_DROPPED);
    count_drop(rule, packet_len);
    return 0;
}

static __always_inline int host_egress_allow_v4_tcp(
    struct ipv4hdr_min *ip4,
    const struct tcphdr_min *tcp,
    struct pfwd_settings *settings
) {
    struct pfwd_flow_key flow = {};
    int verdict;

    flow.family = 4;
    flow.protocol = IPPROTO_TCP;
    flow.sport = tcp->source;
    flow.dport = tcp->dest;
    *(__be32 *)&flow.saddr[0] = ip4->saddr;
    *(__be32 *)&flow.daddr[0] = ip4->daddr;
    verdict = host_egress_flow_cached_verdict(&flow);
    if (verdict == PFWD_CACHE_ALLOW) {
        return TC_ACT_OK;
    }
    if (verdict == PFWD_CACHE_DROP) {
        count_host_egress_drop();
        return TC_ACT_SHOT;
    }
    if (!settings) {
        settings = lookup_settings();
        if (!settings) {
            count_host_egress_drop();
            return TC_ACT_SHOT;
        }
    }
    if (egress_whitelist_allowed_v4(ip4->daddr, settings)) {
        host_egress_flow_store_allow(&flow);
        return TC_ACT_OK;
    }
    if (!tcp_syn_only(tcp)) {
        host_egress_flow_store_allow(&flow);
        return TC_ACT_OK;
    }
    host_egress_flow_store_drop(&flow);
    count_host_egress_drop();
    return TC_ACT_SHOT;
}

static __always_inline int host_egress_allow_v4_udp(
    struct ipv4hdr_min *ip4,
    const struct udphdr_min *udp,
    struct pfwd_settings *settings
) {
    struct pfwd_flow_key flow = {};
    int verdict;

    flow.family = 4;
    flow.protocol = IPPROTO_UDP;
    flow.sport = udp->source;
    flow.dport = udp->dest;
    *(__be32 *)&flow.saddr[0] = ip4->saddr;
    *(__be32 *)&flow.daddr[0] = ip4->daddr;
    verdict = host_egress_flow_cached_verdict(&flow);
    if (verdict == PFWD_CACHE_ALLOW) {
        return TC_ACT_OK;
    }
    if (verdict == PFWD_CACHE_DROP) {
        count_host_egress_drop();
        return TC_ACT_SHOT;
    }
    if (!settings) {
        settings = lookup_settings();
        if (!settings) {
            count_host_egress_drop();
            return TC_ACT_SHOT;
        }
    }
    if (egress_whitelist_allowed_v4(ip4->daddr, settings)) {
        host_egress_flow_store_allow(&flow);
        return TC_ACT_OK;
    }
    host_egress_flow_store_drop(&flow);
    count_host_egress_drop();
    return TC_ACT_SHOT;
}

static __always_inline int host_egress_allow_v6_tcp(
    struct ipv6hdr_min *ip6,
    const struct tcphdr_min *tcp,
    struct pfwd_settings *settings
) {
    struct pfwd_flow_key flow = {};
    int verdict;

    flow.family = 6;
    flow.protocol = IPPROTO_TCP;
    flow.sport = tcp->source;
    flow.dport = tcp->dest;
    pfwd_memcpy16(flow.saddr, ip6->saddr);
    pfwd_memcpy16(flow.daddr, ip6->daddr);
    verdict = host_egress_flow_cached_verdict(&flow);
    if (verdict == PFWD_CACHE_ALLOW) {
        return TC_ACT_OK;
    }
    if (verdict == PFWD_CACHE_DROP) {
        count_host_egress_drop();
        return TC_ACT_SHOT;
    }
    if (!settings) {
        settings = lookup_settings();
        if (!settings) {
            count_host_egress_drop();
            return TC_ACT_SHOT;
        }
    }
    if (egress_whitelist_allowed_v6(ip6->daddr, settings)) {
        host_egress_flow_store_allow(&flow);
        return TC_ACT_OK;
    }
    if (!tcp_syn_only(tcp)) {
        host_egress_flow_store_allow(&flow);
        return TC_ACT_OK;
    }
    host_egress_flow_store_drop(&flow);
    count_host_egress_drop();
    return TC_ACT_SHOT;
}

static __always_inline int host_egress_allow_v6_udp(
    struct ipv6hdr_min *ip6,
    const struct udphdr_min *udp,
    struct pfwd_settings *settings
) {
    struct pfwd_flow_key flow = {};
    int verdict;

    flow.family = 6;
    flow.protocol = IPPROTO_UDP;
    flow.sport = udp->source;
    flow.dport = udp->dest;
    pfwd_memcpy16(flow.saddr, ip6->saddr);
    pfwd_memcpy16(flow.daddr, ip6->daddr);
    verdict = host_egress_flow_cached_verdict(&flow);
    if (verdict == PFWD_CACHE_ALLOW) {
        return TC_ACT_OK;
    }
    if (verdict == PFWD_CACHE_DROP) {
        count_host_egress_drop();
        return TC_ACT_SHOT;
    }
    if (!settings) {
        settings = lookup_settings();
        if (!settings) {
            count_host_egress_drop();
            return TC_ACT_SHOT;
        }
    }
    if (egress_whitelist_allowed_v6(ip6->daddr, settings)) {
        host_egress_flow_store_allow(&flow);
        return TC_ACT_OK;
    }
    host_egress_flow_store_drop(&flow);
    count_host_egress_drop();
    return TC_ACT_SHOT;
}

SEC("tc")
int pfwd_host_egress(struct __sk_buff *skb) {
    void *data;
    void *data_end;
    struct ethhdr *eth;
    struct pfwd_settings *settings = 0;

    if (tc_pull_data_min(skb, ETH_HLEN + sizeof(struct ipv4hdr_min)) < 0) {
        stat_inc(PFWD_STAT_PARSE_SKIPPED);
        return TC_ACT_OK;
    }
    data = (void *)(long)skb->data;
    data_end = (void *)(long)skb->data_end;
    eth = data;
    if ((void *)(eth + 1) > data_end) {
        stat_inc(PFWD_STAT_PARSE_SKIPPED);
        return TC_ACT_OK;
    }
    if (bpf_ntohs(eth->h_proto) == ETH_P_IP) {
        struct ipv4hdr_min *ip4 = (void *)(eth + 1);
        __u32 ihl;
        __u8 protocol;
        __u32 l4_off;

        if ((void *)(ip4 + 1) > data_end) {
            stat_inc(PFWD_STAT_PARSE_SKIPPED);
            return TC_ACT_OK;
        }
        ihl = (__u32)(ip4->version_ihl & 0x0f) * 4;
        if (ihl < sizeof(*ip4)) {
            stat_inc(PFWD_STAT_PARSE_SKIPPED);
            return TC_ACT_OK;
        }
        protocol = ip4->protocol;
        l4_off = ETH_HLEN + ihl;
        if (protocol == IPPROTO_TCP) {
            struct tcphdr_min tcp = {};

            if (tc_load_tcp_min(skb, l4_off, &tcp) < 0) {
                stat_inc(PFWD_STAT_PARSE_SKIPPED);
                return TC_ACT_OK;
            }
            return host_egress_allow_v4_tcp(ip4, &tcp, settings);
        }
        if (protocol == IPPROTO_UDP) {
            struct udphdr_min udp = {};

            if (tc_load_udp_min(skb, l4_off, &udp) < 0) {
                stat_inc(PFWD_STAT_PARSE_SKIPPED);
                return TC_ACT_OK;
            }
            return host_egress_allow_v4_udp(ip4, &udp, settings);
        }
        settings = lookup_settings();
        if (!settings) {
            count_host_egress_drop();
            return TC_ACT_SHOT;
        }
        if (egress_whitelist_allowed_v4(ip4->daddr, settings)) {
            return TC_ACT_OK;
        }
        count_host_egress_drop();
        return TC_ACT_SHOT;
    }
    if (bpf_ntohs(eth->h_proto) == ETH_P_IPV6) {
        struct ipv6hdr_min *ip6 = (void *)(eth + 1);
        __u8 protocol;
        __u32 l4_off = ETH_HLEN + sizeof(struct ipv6hdr_min);

        if ((void *)(ip6 + 1) > data_end) {
            if (tc_pull_data_min(skb, ETH_HLEN + sizeof(struct ipv6hdr_min)) < 0) {
                stat_inc(PFWD_STAT_PARSE_SKIPPED);
                return TC_ACT_OK;
            }
            data = (void *)(long)skb->data;
            data_end = (void *)(long)skb->data_end;
            eth = data;
            if ((void *)(eth + 1) > data_end) {
                stat_inc(PFWD_STAT_PARSE_SKIPPED);
                return TC_ACT_OK;
            }
            ip6 = (void *)(eth + 1);
        }
        if ((void *)(ip6 + 1) > data_end) {
            stat_inc(PFWD_STAT_PARSE_SKIPPED);
            return TC_ACT_OK;
        }
        protocol = ip6->nexthdr;
        if (protocol == IPPROTO_TCP) {
            struct tcphdr_min tcp = {};

            if (tc_load_tcp_min(skb, l4_off, &tcp) < 0) {
                stat_inc(PFWD_STAT_PARSE_SKIPPED);
                return TC_ACT_OK;
            }
            return host_egress_allow_v6_tcp(ip6, &tcp, settings);
        }
        if (protocol == IPPROTO_UDP) {
            struct udphdr_min udp = {};

            if (tc_load_udp_min(skb, l4_off, &udp) < 0) {
                stat_inc(PFWD_STAT_PARSE_SKIPPED);
                return TC_ACT_OK;
            }
            return host_egress_allow_v6_udp(ip6, &udp, settings);
        }
        settings = lookup_settings();
        if (!settings) {
            count_host_egress_drop();
            return TC_ACT_SHOT;
        }
        if (egress_whitelist_allowed_v6(ip6->daddr, settings)) {
            return TC_ACT_OK;
        }
        count_host_egress_drop();
        return TC_ACT_SHOT;
    }
    return TC_ACT_OK;
}

SEC("xdp")
int pfwd_xdp(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    __u64 packet_len = (__u64)(data_end - data);

    if ((void *)(eth + 1) > data_end) {
        stat_inc(PFWD_STAT_PARSE_SKIPPED);
        return XDP_PASS;
    }
    if (bpf_ntohs(eth->h_proto) == ETH_P_IP) {
        struct ipv4hdr_min *ip4 = (void *)(eth + 1);
        __u32 ihl;
        __u8 protocol;
        __be16 sport = 0;
        __be16 dport = 0;
        struct pfwd_rule_val *rule;
        __u8 tcp_conn_state = PFWD_CONN_STATE_NONE;
        if ((void *)(ip4 + 1) > data_end) {
            stat_inc(PFWD_STAT_PARSE_SKIPPED);
            return XDP_PASS;
        }
        protocol = ip4->protocol;
        if (protocol != IPPROTO_TCP && protocol != IPPROTO_UDP) {
            stat_inc(PFWD_STAT_PASSED);
            return XDP_PASS;
        }
        ihl = (__u32)(ip4->version_ihl & 0x0f) * 4;
        if (ihl < sizeof(*ip4)) {
            stat_inc(PFWD_STAT_PARSE_SKIPPED);
            return XDP_PASS;
        }
        if (protocol == IPPROTO_TCP) {
            struct tcphdr_min *tcp = (void *)ip4 + ihl;
            if ((void *)(tcp + 1) > data_end) {
                stat_inc(PFWD_STAT_PARSE_SKIPPED);
                return XDP_PASS;
            }
            sport = tcp->source;
            dport = tcp->dest;
        } else {
            struct udphdr_min *udp = (void *)ip4 + ihl;
            if ((void *)(udp + 1) > data_end) {
                stat_inc(PFWD_STAT_PARSE_SKIPPED);
                return XDP_PASS;
            }
            sport = udp->source;
            dport = udp->dest;
        }

        rule = lookup_forward_rule_v4(protocol, dport, ip4->daddr);
        if (rule) {
            if (rule_xdp_disabled(rule)) {
                stat_inc(PFWD_STAT_PASSED);
                return XDP_PASS;
            }
            if (rule_target_is_loopback(4, rule)) {
                return XDP_PASS;
            }
            struct pfwd_conn_val *existing_conn = 0;
            struct pfwd_counter_plan counters = {};
            __be32 old_saddr = ip4->saddr;
            __be32 old_daddr = ip4->daddr;
            __be16 old_sport = sport;
            __be16 old_dport = dport;
            __be32 new_saddr;
            __be32 new_daddr = ipv4_from16(rule->target_addr);
            __be16 new_sport = sport;
            __be16 new_dport = rule->target_port;
            struct pfwd_conn_key conn_key;
            int guard_bypassed = ingress_guard_bypassed(rule, dport);
            init_counter_plan(rule, &counters);
            if (!guard_bypassed && rule_needs_allow(rule) && !whitelist_allowed_v4(ip4->saddr, rule)) {
                stat_inc(PFWD_STAT_WHITELIST_DROPPED);
                count_drop_with_plan(rule, packet_len, &counters);
                return XDP_DROP;
            }
            if (protocol == IPPROTO_TCP) {
                struct tcphdr_min *tcp = (void *)ip4 + ihl;
                __u32 tcp_len = (__u32)(tcp->doff_res >> 4) * 4;
                void *payload_start = (void *)tcp + tcp_len;
                if (tcp_len < sizeof(*tcp)) {
                    stat_inc(PFWD_STAT_PARSE_SKIPPED);
                    return XDP_PASS;
                }
                if (!guard_bypassed && rule_needs_guard(rule)) {
                    if (inspect_xdp_tcp_flow_v4(payload_start, data_end, rule, packet_len, ip4->saddr, ip4->daddr, sport, dport) == XDP_DROP) {
                        return XDP_DROP;
                    }
                }
                tcp_conn_state = tcp_syn_only(tcp) ? PFWD_CONN_STATE_TCP_SYN_PENDING : PFWD_CONN_STATE_TCP_ESTABLISHED;
            }
            if (counter_plan_needs_policy(&counters)) {
                load_input_counter_plan(rule, packet_len, &counters);
                if (counter_plan_over_limit(rule, &counters)) {
                    stat_inc(PFWD_STAT_QUOTA_DROPPED);
                    count_drop_with_plan(rule, packet_len, &counters);
                    return XDP_DROP;
                }
            }
            fill_conn_key_v4(&conn_key, protocol, ip4->saddr, ip4->daddr, sport, dport, rule->target_port, rule->target_addr);
            existing_conn = bpf_map_lookup_elem(&pfwd_connections, &conn_key);
            if (existing_conn) {
                new_sport = existing_conn->source_port;
                new_saddr = ipv4_from16(existing_conn->source_addr);
                if (protocol == IPPROTO_TCP && tcp_conn_state == PFWD_CONN_STATE_TCP_ESTABLISHED) {
                    mark_tcp_established(existing_conn);
                }
            } else {
                __u32 scratch_key = 0;
                struct pfwd_scratch *scratch = bpf_map_lookup_elem(&pfwd_scratch, &scratch_key);
                if (!scratch) {
                    stat_inc(PFWD_STAT_DROPPED);
                    return XDP_DROP;
                }
                __builtin_memset(&scratch->conn, 0, sizeof(scratch->conn));
                new_saddr = rule_snat_fixed(rule) ? ipv4_from16(rule->snat_addr) : old_daddr;
                init_reverse_alloc_key_v4(&scratch->reverse_key, protocol, new_dport, new_saddr, rule->target_addr);
                new_sport = allocate_source_port_v4(&scratch->reverse_key, sport, old_saddr, old_daddr, new_dport);
                if (new_sport == 0) {
                    stat_inc(PFWD_STAT_DROPPED);
                    count_drop_with_plan(rule, packet_len, &counters);
                    return XDP_DROP;
                }
                scratch->conn.rule_id = rule->rule_id;
                scratch->conn.user_id = rule->user_id;
                set_ipv4_in16(scratch->conn.client_addr, old_saddr);
                set_ipv4_in16(scratch->conn.listen_addr, old_daddr);
                set_ipv4_in16(scratch->conn.source_addr, new_saddr);
                scratch->conn.client_port = old_sport;
                scratch->conn.source_port = new_sport;
                scratch->conn.listen_port = old_dport;
                scratch->conn.traffic_ratio_scaled = rule->traffic_ratio_scaled;
                scratch->conn.traffic_mode = rule->traffic_mode;
                scratch->conn.user_limit_enabled = rule->user_limit_enabled;
                scratch->conn.billing_enabled = rule->billing_enabled;
                if (protocol == IPPROTO_TCP) {
                    record_new_tcp_state(&scratch->conn, tcp_conn_state);
                }
                bpf_map_update_elem(&pfwd_connections, &conn_key, &scratch->conn, BPF_ANY);
                scratch->reverse_key.source_port = new_sport;
                bpf_map_update_elem(&pfwd_reverse, &scratch->reverse_key, &scratch->conn, BPF_ANY);
            }
            rewrite_l4_forward_v4(
                ip4, ihl, protocol,
                old_saddr, old_daddr,
                old_sport, old_dport,
                new_saddr, new_daddr,
                new_sport, new_dport,
                data_end, rule
            );
            {
                int action = fib_redirect_v4(ctx, eth, ip4, protocol, new_sport, new_dport);
                if (action == XDP_DROP) {
                    count_drop_with_plan(rule, packet_len, &counters);
                    return action;
                }
                count_input_with_plan(rule, packet_len, 1, &counters);
                stat_inc(PFWD_STAT_FORWARDED);
                return action;
            }
        }

        {
            struct pfwd_reverse_key reverse_key;
            struct pfwd_conn_val *conn;
            __be32 old_saddr = ip4->saddr;
            __be32 old_daddr = ip4->daddr;
            fill_reverse_lookup_key_v4(&reverse_key, protocol, ip4->daddr, ip4->saddr, dport, sport);
            conn = bpf_map_lookup_elem(&pfwd_reverse, &reverse_key);
            if (conn) {
                if (protocol == IPPROTO_TCP) {
                    mark_tcp_established(conn);
                }
                __be16 new_sport = conn->listen_port;
                __be16 new_dport = conn->source_port;
                __be32 new_saddr = ipv4_from16(conn->listen_addr);
                __be32 new_daddr = ipv4_from16(conn->client_addr);
                rewrite_l4_reply_v4(
                    ip4, ihl, protocol,
                    old_saddr, old_daddr,
                    new_saddr, new_daddr,
                    sport, dport,
                    new_sport, new_dport
                );
                {
                    int action = fib_redirect_v4(ctx, eth, ip4, protocol, new_sport, new_dport);
                    if (action == XDP_DROP) {
                        return action;
                    }
                    count_output(conn, packet_len, 1);
                    stat_inc(PFWD_STAT_FORWARDED);
                    return action;
                }
            }
        }
        stat_inc(PFWD_STAT_PASSED);
        return XDP_PASS;
    }

    if (bpf_ntohs(eth->h_proto) == ETH_P_IPV6) {
        struct ipv6hdr_min *ip6 = (void *)(eth + 1);
        __u8 protocol;
        __be16 sport = 0;
        __be16 dport = 0;
        struct pfwd_rule_val *rule;
        __u8 tcp_conn_state = PFWD_CONN_STATE_NONE;
        if ((void *)(ip6 + 1) > data_end) {
            stat_inc(PFWD_STAT_PARSE_SKIPPED);
            return XDP_PASS;
        }
        protocol = ip6->nexthdr;
        if (protocol != IPPROTO_TCP && protocol != IPPROTO_UDP) {
            stat_inc(PFWD_STAT_PASSED);
            return XDP_PASS;
        }
        if (protocol == IPPROTO_TCP) {
            struct tcphdr_min *tcp = (void *)(ip6 + 1);
            if ((void *)(tcp + 1) > data_end) {
                stat_inc(PFWD_STAT_PARSE_SKIPPED);
                return XDP_PASS;
            }
            sport = tcp->source;
            dport = tcp->dest;
        } else {
            struct udphdr_min *udp = (void *)(ip6 + 1);
            if ((void *)(udp + 1) > data_end) {
                stat_inc(PFWD_STAT_PARSE_SKIPPED);
                return XDP_PASS;
            }
            sport = udp->source;
            dport = udp->dest;
        }
        rule = lookup_forward_rule(6, protocol, dport, ip6->daddr);
        if (rule) {
            if (rule_xdp_disabled(rule)) {
                stat_inc(PFWD_STAT_PASSED);
                return XDP_PASS;
            }
            if (rule_target_is_loopback(6, rule)) {
                return XDP_PASS;
            }
            struct pfwd_conn_val *existing_conn = 0;
            struct pfwd_counter_plan counters = {};
            const __u8 *new_saddr;
            __be16 new_sport = sport;
            struct pfwd_conn_key conn_key;
            int guard_bypassed = ingress_guard_bypassed(rule, dport);
            init_counter_plan(rule, &counters);
            if (!guard_bypassed && rule_needs_allow(rule) && !whitelist_allowed_v6(ip6->saddr, rule)) {
                stat_inc(PFWD_STAT_WHITELIST_DROPPED);
                count_drop_with_plan(rule, packet_len, &counters);
                return XDP_DROP;
            }
            if (protocol == IPPROTO_TCP) {
                struct tcphdr_min *tcp = (void *)(ip6 + 1);
                __u32 tcp_len = (__u32)(tcp->doff_res >> 4) * 4;
                void *payload_start = (void *)tcp + tcp_len;
                if (tcp_len < sizeof(*tcp)) {
                    stat_inc(PFWD_STAT_PARSE_SKIPPED);
                    return XDP_PASS;
                }
                if (!guard_bypassed && rule_needs_guard(rule)) {
                    if (inspect_xdp_tcp_flow(payload_start, data_end, rule, packet_len, 6, ip6->saddr, ip6->daddr, sport, dport) == XDP_DROP) {
                        return XDP_DROP;
                    }
                }
                tcp_conn_state = tcp_syn_only(tcp) ? PFWD_CONN_STATE_TCP_SYN_PENDING : PFWD_CONN_STATE_TCP_ESTABLISHED;
            }
            if (counter_plan_needs_policy(&counters)) {
                load_input_counter_plan(rule, packet_len, &counters);
                if (counter_plan_over_limit(rule, &counters)) {
                    stat_inc(PFWD_STAT_QUOTA_DROPPED);
                    count_drop_with_plan(rule, packet_len, &counters);
                    return XDP_DROP;
                }
            }
            fill_conn_key_v6(&conn_key, protocol, ip6->saddr, ip6->daddr, sport, dport, rule->target_port, rule->target_addr);
            existing_conn = bpf_map_lookup_elem(&pfwd_connections, &conn_key);
            if (existing_conn) {
                new_sport = existing_conn->source_port;
                new_saddr = existing_conn->source_addr;
                if (protocol == IPPROTO_TCP && tcp_conn_state == PFWD_CONN_STATE_TCP_ESTABLISHED) {
                    mark_tcp_established(existing_conn);
                }
            } else {
                __u32 scratch_key = 0;
                struct pfwd_scratch *scratch = bpf_map_lookup_elem(&pfwd_scratch, &scratch_key);
                const __u8 *source_addr;
                if (!scratch) {
                    stat_inc(PFWD_STAT_DROPPED);
                    return XDP_DROP;
                }
                __builtin_memset(&scratch->conn, 0, sizeof(scratch->conn));
                source_addr = rule_snat_fixed(rule) ? rule->snat_addr : ip6->daddr;
                init_reverse_alloc_key_v6(&scratch->reverse_key, protocol, rule->target_port, source_addr, rule->target_addr);
                new_sport = allocate_source_port_v6(&scratch->reverse_key, sport, ip6->saddr, ip6->daddr, rule->target_port);
                if (new_sport == 0) {
                    stat_inc(PFWD_STAT_DROPPED);
                    count_drop_with_plan(rule, packet_len, &counters);
                    return XDP_DROP;
                }
                scratch->conn.rule_id = rule->rule_id;
                scratch->conn.user_id = rule->user_id;
                pfwd_memcpy16(scratch->conn.client_addr, ip6->saddr);
                pfwd_memcpy16(scratch->conn.listen_addr, ip6->daddr);
                pfwd_memcpy16(scratch->conn.source_addr, source_addr);
                scratch->conn.client_port = sport;
                scratch->conn.source_port = new_sport;
                scratch->conn.listen_port = dport;
                scratch->conn.traffic_ratio_scaled = rule->traffic_ratio_scaled;
                scratch->conn.traffic_mode = rule->traffic_mode;
                scratch->conn.user_limit_enabled = rule->user_limit_enabled;
                scratch->conn.billing_enabled = rule->billing_enabled;
                if (protocol == IPPROTO_TCP) {
                    record_new_tcp_state(&scratch->conn, tcp_conn_state);
                }
                bpf_map_update_elem(&pfwd_connections, &conn_key, &scratch->conn, BPF_ANY);
                scratch->reverse_key.source_port = new_sport;
                bpf_map_update_elem(&pfwd_reverse, &scratch->reverse_key, &scratch->conn, BPF_ANY);
                new_saddr = source_addr;
            }
            rewrite_l4_forward_v6(
                ip6, protocol,
                ip6->saddr, ip6->daddr,
                sport, dport,
                new_saddr, rule->target_addr,
                new_sport, rule->target_port,
                data_end, rule
            );
            {
                int action = fib_redirect_v6(ctx, eth, ip6, protocol, new_sport, rule->target_port);
                if (action == XDP_DROP) {
                    count_drop_with_plan(rule, packet_len, &counters);
                    return action;
                }
                count_input_with_plan(rule, packet_len, 1, &counters);
                stat_inc(PFWD_STAT_FORWARDED);
                return action;
            }
        }
        {
            struct pfwd_reverse_key reverse_key;
            struct pfwd_conn_val *conn;
            fill_reverse_lookup_key_v6(&reverse_key, protocol, ip6->daddr, ip6->saddr, dport, sport);
            conn = bpf_map_lookup_elem(&pfwd_reverse, &reverse_key);
            if (conn) {
                if (protocol == IPPROTO_TCP) {
                    mark_tcp_established(conn);
                }
                __be16 new_sport = conn->listen_port;
                __be16 new_dport = conn->source_port;
                rewrite_l4_reply_v6(
                    ip6, protocol,
                    ip6->saddr, ip6->daddr,
                    conn->listen_addr, conn->client_addr,
                    sport, dport,
                    new_sport, new_dport
                );
                {
                    int action = fib_redirect_v6(ctx, eth, ip6, protocol, new_sport, new_dport);
                    if (action == XDP_DROP) {
                        return action;
                    }
                    count_output(conn, packet_len, 1);
                    stat_inc(PFWD_STAT_FORWARDED);
                    return action;
                }
            }
        }
        stat_inc(PFWD_STAT_PASSED);
        return XDP_PASS;
    }

    stat_inc(PFWD_STAT_PASSED);
    return XDP_PASS;
}

SEC("tc")
int pfwd_ingress(struct __sk_buff *skb) {
    void *data;
    void *data_end;
    struct ethhdr *eth;
    __u64 packet_len = skb->len;

    if (tc_pull_data_min(skb, ETH_HLEN + sizeof(struct ipv4hdr_min)) < 0) {
        stat_inc(PFWD_STAT_PARSE_SKIPPED);
        return TC_ACT_OK;
    }
    data = (void *)(long)skb->data;
    data_end = (void *)(long)skb->data_end;
    eth = data;
    if ((void *)(eth + 1) > data_end) {
        stat_inc(PFWD_STAT_PARSE_SKIPPED);
        return TC_ACT_OK;
    }
    if (bpf_ntohs(eth->h_proto) == ETH_P_IP) {
        struct ipv4hdr_min *ip4 = (void *)(eth + 1);
        __u32 ihl;
        __u8 protocol;
        __be16 sport = 0;
        __be16 dport = 0;
        struct pfwd_rule_val *rule;

        if ((void *)(ip4 + 1) > data_end) {
            stat_inc(PFWD_STAT_PARSE_SKIPPED);
            return TC_ACT_OK;
        }
        protocol = ip4->protocol;
        if (protocol != IPPROTO_TCP && protocol != IPPROTO_UDP) {
            return TC_ACT_OK;
        }
        ihl = (__u32)(ip4->version_ihl & 0x0f) * 4;
        if (ihl < sizeof(*ip4)) {
            stat_inc(PFWD_STAT_PARSE_SKIPPED);
            return TC_ACT_OK;
        }
        if (protocol == IPPROTO_TCP) {
            struct tcphdr_min tcp_hdr = {};
            __u32 l4_off = ETH_HLEN + ihl;
            int needs_pull = 0;

            if (tc_load_tcp_min(skb, l4_off, &tcp_hdr) < 0) {
                stat_inc(PFWD_STAT_PARSE_SKIPPED);
                return TC_ACT_OK;
            }
            sport = tcp_hdr.source;
            dport = tcp_hdr.dest;
            rule = lookup_forward_rule_v4(protocol, dport, ip4->daddr);
            if (rule && !rule_xdp_disabled(rule)) {
                if (rule_target_is_loopback(4, rule)) {
                    needs_pull = 1;
                } else {
                    if (!tc_ingress_allowed_v4(ip4, rule, dport, packet_len)) {
                        return TC_ACT_SHOT;
                    }
                    if (rule_needs_guard(rule)) {
                        needs_pull = 1;
                    }
                }
            }
            if (!needs_pull) {
                return TC_ACT_OK;
            }
            if (tc_pull_data_min(skb, l4_off + sizeof(struct tcphdr_min)) < 0) {
                stat_inc(PFWD_STAT_PARSE_SKIPPED);
                return TC_ACT_OK;
            }
            data = (void *)(long)skb->data;
            data_end = (void *)(long)skb->data_end;
            eth = data;
            if ((void *)(eth + 1) > data_end) {
                stat_inc(PFWD_STAT_PARSE_SKIPPED);
                return TC_ACT_OK;
            }
            ip4 = (void *)(eth + 1);
            if ((void *)(ip4 + 1) > data_end || (void *)ip4 + ihl > data_end) {
                stat_inc(PFWD_STAT_PARSE_SKIPPED);
                return TC_ACT_OK;
            }
            {
                struct tcphdr_min *tcp = (void *)ip4 + ihl;
                if ((void *)(tcp + 1) > data_end) {
                    stat_inc(PFWD_STAT_PARSE_SKIPPED);
                    return TC_ACT_OK;
                }
            }
            if (rule_target_is_loopback(4, rule)) {
                return tc_local_forward_v4(skb, data_end, ip4, ihl, protocol, sport, dport, rule, packet_len);
            }
            if (!rule_needs_guard(rule)) {
                return TC_ACT_OK;
            }
            {
                struct tcphdr_min *tcp = (void *)ip4 + ihl;
            __u32 tcp_len;
            void *payload_start;
            if ((void *)(tcp + 1) > data_end) {
                stat_inc(PFWD_STAT_PARSE_SKIPPED);
                return TC_ACT_OK;
            }
            tcp_len = (__u32)(tcp->doff_res >> 4) * 4;
            payload_start = (void *)tcp + tcp_len;
            if (tcp_len < sizeof(*tcp)) {
                stat_inc(PFWD_STAT_PARSE_SKIPPED);
                return TC_ACT_OK;
            }
            if (inspect_xdp_tcp_flow_v4(payload_start, data_end, rule, packet_len, ip4->saddr, ip4->daddr, sport, dport) == XDP_DROP) {
                return TC_ACT_SHOT;
            }
            return TC_ACT_OK;
            }
        }
        {
            struct udphdr_min udp_hdr = {};
            __u32 l4_off = ETH_HLEN + ihl;

            if (tc_load_udp_min(skb, l4_off, &udp_hdr) < 0) {
                stat_inc(PFWD_STAT_PARSE_SKIPPED);
                return TC_ACT_OK;
            }
            sport = udp_hdr.source;
            dport = udp_hdr.dest;
            rule = lookup_forward_rule_v4(protocol, dport, ip4->daddr);
            if (rule && !rule_xdp_disabled(rule) && rule_target_is_loopback(4, rule)) {
                return tc_local_forward_v4(skb, data_end, ip4, ihl, protocol, sport, dport, rule, packet_len);
            }
            if (rule && !rule_xdp_disabled(rule) &&
                !tc_ingress_allowed_v4(ip4, rule, dport, packet_len)) {
                return TC_ACT_SHOT;
            }
            return TC_ACT_OK;
        }
    }
    if (bpf_ntohs(eth->h_proto) == ETH_P_IPV6) {
        struct ipv6hdr_min *ip6 = (void *)(eth + 1);
        __u8 protocol;
        __be16 sport = 0;
        __be16 dport = 0;
        struct pfwd_rule_val *rule;

        if ((void *)(ip6 + 1) > data_end) {
            if (tc_pull_data_min(skb, ETH_HLEN + sizeof(struct ipv6hdr_min)) < 0) {
                stat_inc(PFWD_STAT_PARSE_SKIPPED);
                return TC_ACT_OK;
            }
            data = (void *)(long)skb->data;
            data_end = (void *)(long)skb->data_end;
            eth = data;
            if ((void *)(eth + 1) > data_end) {
                stat_inc(PFWD_STAT_PARSE_SKIPPED);
                return TC_ACT_OK;
            }
            ip6 = (void *)(eth + 1);
        }
        if ((void *)(ip6 + 1) > data_end) {
            stat_inc(PFWD_STAT_PARSE_SKIPPED);
            return TC_ACT_OK;
        }
        protocol = ip6->nexthdr;
        if (protocol != IPPROTO_TCP && protocol != IPPROTO_UDP) {
            return TC_ACT_OK;
        }
        if (protocol == IPPROTO_TCP) {
            struct tcphdr_min tcp_hdr = {};
            int needs_pull = 0;

            if (tc_load_tcp_min(skb, ETH_HLEN + sizeof(struct ipv6hdr_min), &tcp_hdr) < 0) {
                stat_inc(PFWD_STAT_PARSE_SKIPPED);
                return TC_ACT_OK;
            }
            sport = tcp_hdr.source;
            dport = tcp_hdr.dest;
            rule = lookup_forward_rule(6, protocol, dport, ip6->daddr);
            if (rule && !rule_xdp_disabled(rule)) {
                if (rule_target_is_loopback(6, rule)) {
                    needs_pull = 1;
                } else {
                    if (!tc_ingress_allowed_v6(ip6, rule, dport, packet_len)) {
                        return TC_ACT_SHOT;
                    }
                    if (rule_needs_guard(rule)) {
                        needs_pull = 1;
                    }
                }
            }
            if (!needs_pull) {
                return TC_ACT_OK;
            }
            if (tc_pull_data_min(skb, ETH_HLEN + sizeof(struct ipv6hdr_min) + sizeof(struct tcphdr_min)) < 0) {
                stat_inc(PFWD_STAT_PARSE_SKIPPED);
                return TC_ACT_OK;
            }
            data = (void *)(long)skb->data;
            data_end = (void *)(long)skb->data_end;
            eth = data;
            if ((void *)(eth + 1) > data_end) {
                stat_inc(PFWD_STAT_PARSE_SKIPPED);
                return TC_ACT_OK;
            }
            ip6 = (void *)(eth + 1);
            if ((void *)(ip6 + 1) > data_end) {
                stat_inc(PFWD_STAT_PARSE_SKIPPED);
                return TC_ACT_OK;
            }
            {
                struct tcphdr_min *tcp = (void *)(ip6 + 1);
                if ((void *)(tcp + 1) > data_end) {
                    stat_inc(PFWD_STAT_PARSE_SKIPPED);
                    return TC_ACT_OK;
                }
            }
            if (rule_target_is_loopback(6, rule)) {
                return tc_local_forward_v6(skb, data_end, ip6, protocol, sport, dport, rule, packet_len);
            }
            if (!rule_needs_guard(rule)) {
                return TC_ACT_OK;
            }
            {
                struct tcphdr_min *tcp = (void *)(ip6 + 1);
            __u32 tcp_len;
            void *payload_start;
            if ((void *)(tcp + 1) > data_end) {
                stat_inc(PFWD_STAT_PARSE_SKIPPED);
                return TC_ACT_OK;
            }
            tcp_len = (__u32)(tcp->doff_res >> 4) * 4;
            payload_start = (void *)tcp + tcp_len;
            if (tcp_len < sizeof(*tcp)) {
                stat_inc(PFWD_STAT_PARSE_SKIPPED);
                return TC_ACT_OK;
            }
            if (inspect_xdp_tcp_flow(payload_start, data_end, rule, packet_len, 6, ip6->saddr, ip6->daddr, sport, dport) == XDP_DROP) {
                return TC_ACT_SHOT;
            }
            return TC_ACT_OK;
            }
        }
        {
            struct udphdr_min udp_hdr = {};

            if (tc_load_udp_min(skb, ETH_HLEN + sizeof(struct ipv6hdr_min), &udp_hdr) < 0) {
                stat_inc(PFWD_STAT_PARSE_SKIPPED);
                return TC_ACT_OK;
            }
            sport = udp_hdr.source;
            dport = udp_hdr.dest;
            rule = lookup_forward_rule(6, protocol, dport, ip6->daddr);
            if (rule && !rule_xdp_disabled(rule) && rule_target_is_loopback(6, rule)) {
                return tc_local_forward_v6(skb, data_end, ip6, protocol, sport, dport, rule, packet_len);
            }
            if (rule && !rule_xdp_disabled(rule) &&
                !tc_ingress_allowed_v6(ip6, rule, dport, packet_len)) {
                return TC_ACT_SHOT;
            }
            return TC_ACT_OK;
        }
    }
    return TC_ACT_OK;
}

SEC("tc")
int pfwd_loopback_egress(struct __sk_buff *skb) {
    void *data;
    void *data_end;
    struct ethhdr *eth;
    struct pfwd_settings *settings = 0;
    __u64 packet_len = skb->len;

    if (tc_pull_data_min(skb, ETH_HLEN + sizeof(struct ipv4hdr_min)) < 0) {
        stat_inc(PFWD_STAT_PARSE_SKIPPED);
        return TC_ACT_OK;
    }
    data = (void *)(long)skb->data;
    data_end = (void *)(long)skb->data_end;
    eth = data;
    if ((void *)(eth + 1) > data_end) {
        stat_inc(PFWD_STAT_PARSE_SKIPPED);
        return TC_ACT_OK;
    }
    if (bpf_ntohs(eth->h_proto) == ETH_P_IP) {
        struct ipv4hdr_min *ip4 = (void *)(eth + 1);
        __u32 ihl;
        __u8 protocol;
        __be16 sport = 0;
        __be16 dport = 0;
        struct pfwd_reverse_key reverse_key;
        struct pfwd_conn_val *conn;
        __u32 l4_off;

        if ((void *)(ip4 + 1) > data_end) {
            stat_inc(PFWD_STAT_PARSE_SKIPPED);
            return TC_ACT_OK;
        }
        protocol = ip4->protocol;
        if (protocol != IPPROTO_TCP && protocol != IPPROTO_UDP) {
            return TC_ACT_OK;
        }
        ihl = (__u32)(ip4->version_ihl & 0x0f) * 4;
        if (ihl < sizeof(*ip4)) {
            stat_inc(PFWD_STAT_PARSE_SKIPPED);
            return TC_ACT_OK;
        }
        l4_off = ETH_HLEN + ihl;
        if (protocol == IPPROTO_TCP) {
            struct tcphdr_min tcp_hdr = {};

            if (tc_load_tcp_min(skb, l4_off, &tcp_hdr) < 0) {
                stat_inc(PFWD_STAT_PARSE_SKIPPED);
                return TC_ACT_OK;
            }
            sport = tcp_hdr.source;
            dport = tcp_hdr.dest;
        } else {
            struct udphdr_min udp_hdr = {};

            if (tc_load_udp_min(skb, l4_off, &udp_hdr) < 0) {
                stat_inc(PFWD_STAT_PARSE_SKIPPED);
                return TC_ACT_OK;
            }
            sport = udp_hdr.source;
            dport = udp_hdr.dest;
        }
        fill_reverse_lookup_key_v4(&reverse_key, protocol, ip4->daddr, ip4->saddr, dport, sport);
        conn = bpf_map_lookup_elem(&pfwd_reverse, &reverse_key);
        if (!conn) {
            return TC_ACT_OK;
        }
        if (tc_pull_data_min(skb, l4_off + (protocol == IPPROTO_TCP ? sizeof(struct tcphdr_min) : sizeof(struct udphdr_min))) < 0) {
            stat_inc(PFWD_STAT_PARSE_SKIPPED);
            return TC_ACT_OK;
        }
        data = (void *)(long)skb->data;
        data_end = (void *)(long)skb->data_end;
        eth = data;
        if ((void *)(eth + 1) > data_end) {
            stat_inc(PFWD_STAT_PARSE_SKIPPED);
            return TC_ACT_OK;
        }
        ip4 = (void *)(eth + 1);
        if ((void *)(ip4 + 1) > data_end || (void *)ip4 + ihl > data_end) {
            stat_inc(PFWD_STAT_PARSE_SKIPPED);
            return TC_ACT_OK;
        }
        if (!settings) {
            settings = lookup_settings();
            if (!settings) {
                return TC_ACT_OK;
            }
        }
        if (protocol == IPPROTO_TCP) {
            mark_tcp_established(conn);
        }
        {
            __be16 new_sport = conn->listen_port;
            __be16 new_dport = conn->source_port;
            __be32 new_saddr = ipv4_from16(conn->listen_addr);
            __be32 new_daddr = ipv4_from16(conn->client_addr);
            rewrite_l4_reply_v4(
                ip4, ihl, protocol,
                ip4->saddr, ip4->daddr,
                new_saddr, new_daddr,
                sport, dport,
                new_sport, new_dport
            );
            {
                int action = tc_redirect_external(settings);
                if (action != TC_ACT_REDIRECT) {
                    return TC_ACT_SHOT;
                }
                count_output(conn, packet_len, 1);
                stat_inc(PFWD_STAT_FORWARDED);
                return action;
            }
        }
    }
    if (bpf_ntohs(eth->h_proto) == ETH_P_IPV6) {
        struct ipv6hdr_min *ip6 = (void *)(eth + 1);
        __u8 protocol;
        __be16 sport = 0;
        __be16 dport = 0;
        struct pfwd_reverse_key reverse_key;
        struct pfwd_conn_val *conn;

        if ((void *)(ip6 + 1) > data_end) {
            if (tc_pull_data_min(skb, ETH_HLEN + sizeof(struct ipv6hdr_min)) < 0) {
                stat_inc(PFWD_STAT_PARSE_SKIPPED);
                return TC_ACT_OK;
            }
            data = (void *)(long)skb->data;
            data_end = (void *)(long)skb->data_end;
            eth = data;
            if ((void *)(eth + 1) > data_end) {
                stat_inc(PFWD_STAT_PARSE_SKIPPED);
                return TC_ACT_OK;
            }
            ip6 = (void *)(eth + 1);
        }
        if ((void *)(ip6 + 1) > data_end) {
            stat_inc(PFWD_STAT_PARSE_SKIPPED);
            return TC_ACT_OK;
        }
        protocol = ip6->nexthdr;
        if (protocol != IPPROTO_TCP && protocol != IPPROTO_UDP) {
            return TC_ACT_OK;
        }
        if (protocol == IPPROTO_TCP) {
            struct tcphdr_min tcp_hdr = {};

            if (tc_load_tcp_min(skb, ETH_HLEN + sizeof(struct ipv6hdr_min), &tcp_hdr) < 0) {
                stat_inc(PFWD_STAT_PARSE_SKIPPED);
                return TC_ACT_OK;
            }
            sport = tcp_hdr.source;
            dport = tcp_hdr.dest;
        } else {
            struct udphdr_min udp_hdr = {};

            if (tc_load_udp_min(skb, ETH_HLEN + sizeof(struct ipv6hdr_min), &udp_hdr) < 0) {
                stat_inc(PFWD_STAT_PARSE_SKIPPED);
                return TC_ACT_OK;
            }
            sport = udp_hdr.source;
            dport = udp_hdr.dest;
        }
        fill_reverse_lookup_key_v6(&reverse_key, protocol, ip6->daddr, ip6->saddr, dport, sport);
        conn = bpf_map_lookup_elem(&pfwd_reverse, &reverse_key);
        if (!conn) {
            return TC_ACT_OK;
        }
        if (tc_pull_data_min(skb, ETH_HLEN + sizeof(struct ipv6hdr_min) + (protocol == IPPROTO_TCP ? sizeof(struct tcphdr_min) : sizeof(struct udphdr_min))) < 0) {
            stat_inc(PFWD_STAT_PARSE_SKIPPED);
            return TC_ACT_OK;
        }
        data = (void *)(long)skb->data;
        data_end = (void *)(long)skb->data_end;
        eth = data;
        if ((void *)(eth + 1) > data_end) {
            stat_inc(PFWD_STAT_PARSE_SKIPPED);
            return TC_ACT_OK;
        }
        ip6 = (void *)(eth + 1);
        if ((void *)(ip6 + 1) > data_end) {
            stat_inc(PFWD_STAT_PARSE_SKIPPED);
            return TC_ACT_OK;
        }
        if (!settings) {
            settings = lookup_settings();
            if (!settings) {
                return TC_ACT_OK;
            }
        }
        if (protocol == IPPROTO_TCP) {
            mark_tcp_established(conn);
        }
        {
            __be16 new_sport = conn->listen_port;
            __be16 new_dport = conn->source_port;
            rewrite_l4_reply_v6(
                ip6, protocol,
                ip6->saddr, ip6->daddr,
                conn->listen_addr, conn->client_addr,
                sport, dport,
                new_sport, new_dport
            );
            {
                int action = tc_redirect_external(settings);
                if (action != TC_ACT_REDIRECT) {
                    return TC_ACT_SHOT;
                }
                count_output(conn, packet_len, 1);
                stat_inc(PFWD_STAT_FORWARDED);
                return action;
            }
        }
    }
    return TC_ACT_OK;
}

SEC("sk_lookup")
int pfwd_sk_lookup(struct bpf_sk_lookup *ctx) {
    struct pfwd_rule_val *rule;
    struct bpf_sock *sk;
    __u8 listen_addr[16];
    int err;

    if (ctx->protocol != IPPROTO_TCP && ctx->protocol != IPPROTO_UDP) {
        return SK_PASS;
    }
    if (ctx->family == AF_INET) {
        rule = lookup_forward_rule_v4((__u8)ctx->protocol, bpf_htons((__u16)ctx->local_port), ctx->local_ip4);
        if (!rule || !rule_target_is_loopback(4, rule)) {
            return SK_PASS;
        }
        sk = lookup_local_socket_v4(ctx, (__u8)ctx->protocol, ctx->remote_ip4, ipv4_from16(rule->target_addr), ctx->remote_port, rule->target_port);
    } else if (ctx->family == AF_INET6) {
        pfwd_memcpy16(listen_addr, (const __u8 *)ctx->local_ip6);
        rule = lookup_forward_rule(6, (__u8)ctx->protocol, bpf_htons((__u16)ctx->local_port), listen_addr);
        if (!rule || !rule_target_is_loopback(6, rule)) {
            return SK_PASS;
        }
        sk = lookup_local_socket_v6(ctx, (__u8)ctx->protocol, (const __u8 *)ctx->remote_ip6, rule->target_addr, ctx->remote_port, rule->target_port);
    } else {
        return SK_PASS;
    }

    if (!sk) {
        stat_inc(PFWD_STAT_DROPPED);
        return SK_DROP;
    }
    err = bpf_sk_assign(ctx, sk, BPF_SK_LOOKUP_F_REPLACE);
    bpf_sk_release(sk);
    if (err) {
        stat_inc(PFWD_STAT_DROPPED);
        return SK_DROP;
    }
    return SK_PASS;
}
