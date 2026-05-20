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
    PFWD_STAT_MAX = 9,
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
    __u8 pad[2];
    __u32 external_ifindex;
    __u32 loopback_ifindex;
};

struct pfwd_port_key {
    __be16 port;
    __u8 pad[4];
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
    __u16 client_port;
    __u8 source_addr[16];
    __u8 target_addr[16];
    __u8 client_addr[16];
};

struct pfwd_counter {
    __u64 input_bytes;
    __u64 output_bytes;
    __u64 input_packets;
    __u64 output_packets;
    __u64 dropped_bytes;
    __u64 dropped_packets;
    __u64 billing_bytes;
};

struct pfwd_whitelist_key_v4 {
    __u32 prefixlen;
    __u32 addr;
};

struct pfwd_whitelist_key_v6 {
    __u32 prefixlen;
    __u8 addr[16];
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
    struct pfwd_conn_key conn_key;
    struct pfwd_conn_val conn;
    struct pfwd_reverse_key reverse_key;
    __u8 addr_a[16];
    __u8 addr_b[16];
    __u8 addr_c[16];
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
    __uint(max_entries, PFWD_MAX_USERS);
    __type(key, __u32);
    __type(value, struct pfwd_counter);
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
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct pfwd_flow_key);
    __type(value, __u8);
} pfwd_allowed_flows SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct pfwd_flow_key);
    __type(value, struct pfwd_guard_prefix_val);
} pfwd_guard_prefixes SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, struct pfwd_port_key);
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

static __always_inline void copy_ipv4_to16(__u8 dst[16], __be32 addr) {
    const __u8 *src = (const __u8 *)&addr;
    int i;
#pragma unroll
    for (i = 0; i < 16; i++) {
        dst[i] = 0;
    }
#pragma unroll
    for (i = 0; i < 4; i++) {
        dst[i] = src[i];
    }
}

static __always_inline __be32 ipv4_from16(const __u8 addr[16]) {
    const __be32 *value = (const __be32 *)addr;
    return *value;
}

static __always_inline __u16 csum_replace_addr16(__u16 csum, const __u8 old_addr[16], const __u8 new_addr[16]) {
    const __u32 *old32 = (const __u32 *)old_addr;
    const __u32 *new32 = (const __u32 *)new_addr;
#pragma unroll
    for (int i = 0; i < 4; i++) {
        csum = csum_replace32(csum, old32[i], new32[i]);
    }
    return csum;
}

static __always_inline void zero_addr16(__u8 addr[16]) {
    int i;
#pragma unroll
    for (i = 0; i < 16; i++) {
        addr[i] = 0;
    }
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

static __always_inline int whitelist_allowed_v4(__be32 addr) {
    int verdict = whitelist_cache_hit_v4(addr);

    if (verdict != PFWD_CACHE_UNKNOWN) {
        return verdict == PFWD_CACHE_ALLOW;
    }
    verdict = whitelist_match_v4(addr) ? PFWD_CACHE_ALLOW : PFWD_CACHE_DROP;
    whitelist_cache_store_v4(addr, verdict);
    return verdict == PFWD_CACHE_ALLOW;
}

static __always_inline int whitelist_allowed_v6(const __u8 addr[16]) {
    int verdict = whitelist_cache_hit_v6(addr);

    if (verdict != PFWD_CACHE_UNKNOWN) {
        return verdict == PFWD_CACHE_ALLOW;
    }
    verdict = whitelist_match_v6(addr) ? PFWD_CACHE_ALLOW : PFWD_CACHE_DROP;
    whitelist_cache_store_v6(addr, verdict);
    return verdict == PFWD_CACHE_ALLOW;
}

static __always_inline __u64 counter_billing_total(struct pfwd_counter *counter, __u64 base) {
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

static __always_inline int traffic_over_limit(const struct pfwd_rule_val *rule, __u64 input_delta, __u64 output_delta) {
    struct pfwd_counter *rule_counter;
    struct pfwd_counter *user_counter;
    __u64 billed_delta;
    __u64 current_rule;
    __u64 current_user;
    __u32 rule_id = rule->rule_id;
    __u32 user_id = rule->user_id;
    __u64 ratio = rule->traffic_ratio_scaled;
    billed_delta = scaled_bytes(input_delta, ratio) + scaled_bytes(output_delta, ratio);
    if (rule->traffic_mode != 1) {
        billed_delta *= 2;
    }
    if (rule->rule_limit_bytes > 0) {
        rule_counter = bpf_map_lookup_elem(&pfwd_rule_counters, &rule_id);
        current_rule = counter_billing_total(rule_counter, rule->rule_billing_used_base_bytes);
        if (current_rule + billed_delta > rule->rule_limit_bytes) {
            return 1;
        }
    }
    if (rule->user_limit_bytes > 0) {
        user_counter = bpf_map_lookup_elem(&pfwd_user_counters, &user_id);
        current_user = counter_billing_total(user_counter, rule->user_billing_used_base_bytes);
        if (current_user + billed_delta > rule->user_limit_bytes) {
            return 1;
        }
    }
    return 0;
}

static __always_inline void count_input(const struct pfwd_rule_val *rule, __u64 bytes, __u64 packets) {
    struct pfwd_counter *counter;
    __u32 key = rule->rule_id;
    __u64 billed = 0;

    if (rule->billing_enabled) {
        billed = scaled_bytes(bytes, rule->traffic_ratio_scaled);
        if (rule->traffic_mode != 1) {
            billed *= 2;
        }
    }
    counter = bpf_map_lookup_elem(&pfwd_rule_counters, &key);
    if (counter) {
        counter->input_bytes += bytes;
        counter->input_packets += packets;
        if (rule->billing_enabled) {
            counter->billing_bytes += billed;
        }
    }
    key = rule->user_id;
    if (rule->user_limit_enabled) {
        counter = bpf_map_lookup_elem(&pfwd_user_counters, &key);
        if (counter) {
            counter->input_bytes += bytes;
            counter->input_packets += packets;
            if (rule->billing_enabled) {
                counter->billing_bytes += billed;
            }
        }
    }
}

static __always_inline void count_output(const struct pfwd_conn_val *conn, __u64 bytes, __u64 packets) {
    struct pfwd_counter *counter;
    __u32 key = conn->rule_id;
    __u64 billed = 0;

    if (conn->billing_enabled) {
        billed = scaled_bytes(bytes, conn->traffic_ratio_scaled);
        if (conn->traffic_mode != 1) {
            billed *= 2;
        }
    }
    counter = bpf_map_lookup_elem(&pfwd_rule_counters, &key);
    if (counter) {
        counter->output_bytes += bytes;
        counter->output_packets += packets;
        if (conn->billing_enabled) {
            counter->billing_bytes += billed;
        }
    }
    key = conn->user_id;
    if (conn->user_limit_enabled) {
        counter = bpf_map_lookup_elem(&pfwd_user_counters, &key);
        if (counter) {
            counter->output_bytes += bytes;
            counter->output_packets += packets;
            if (conn->billing_enabled) {
                counter->billing_bytes += billed;
            }
        }
    }
}

static __always_inline void count_drop(const struct pfwd_rule_val *rule, __u64 bytes) {
    struct pfwd_counter *counter;
    __u32 key = rule->rule_id;
    counter = bpf_map_lookup_elem(&pfwd_rule_counters, &key);
    if (counter) {
        counter->dropped_bytes += bytes;
        counter->dropped_packets += 1;
    }
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

static __always_inline int inspect_payload_bytes_xdp(const __u8 *payload, __u32 len, const struct pfwd_settings *settings) {
    if (settings->block_http && match_http(payload, len)) {
        stat_inc(PFWD_STAT_PROTOCOL_DROPPED);
        return PFWD_INSPECT_DROP;
    }
    if (settings->block_tls && match_tls_client_hello(payload, len)) {
        stat_inc(PFWD_STAT_PROTOCOL_DROPPED);
        return PFWD_INSPECT_DROP;
    }
    if (settings->block_socks && match_socks(payload, len)) {
        stat_inc(PFWD_STAT_PROTOCOL_DROPPED);
        return PFWD_INSPECT_DROP;
    }
    return PFWD_INSPECT_ALLOW;
}

static __always_inline int inspect_guard_prefix(const struct pfwd_guard_prefix_val *prefix, const struct pfwd_settings *settings) {
    int http_possible = 0;
    int tls_possible = 0;
    int socks_possible = 0;

    if (prefix->seen_len >= 3) {
        if (settings->block_http) {
            http_possible = match_http(prefix->prefix, prefix->seen_len);
        }
        if (settings->block_socks) {
            socks_possible = match_socks(prefix->prefix, prefix->seen_len);
        }
    }
    if (prefix->seen_len >= 6 && settings->block_tls) {
        tls_possible = match_tls_client_hello(prefix->prefix, prefix->seen_len);
    }
    if (prefix->seen_len >= 3 && (!settings->block_tls || prefix->seen_len >= 6)) {
        if ((!settings->block_http || !http_possible) &&
            (!settings->block_socks || !socks_possible) &&
            (!settings->block_tls || !tls_possible)) {
            return PFWD_INSPECT_ALLOW;
        }
    }
    int verdict = inspect_payload_bytes_xdp(prefix->prefix, prefix->seen_len, settings);
    if (verdict == PFWD_INSPECT_DROP) {
        return verdict;
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

static __always_inline int inspect_payload_xdp(void *payload_start, void *data_end, __u32 len, const struct pfwd_settings *settings) {
    __u8 *p = payload_start;
    __u8 payload[8] = {};
    __u32 read_len = len >= 8 ? 8 : len;

    if (read_len < 3) {
        return PFWD_INSPECT_NEED_MORE;
    }
    if (read_len > 0) {
        if ((void *)(p + 1) > data_end) {
            stat_inc(PFWD_STAT_PARSE_SKIPPED);
            return PFWD_INSPECT_NEED_MORE;
        }
        payload[0] = p[0];
    }
    if (read_len > 1) {
        if ((void *)(p + 2) > data_end) {
            stat_inc(PFWD_STAT_PARSE_SKIPPED);
            return PFWD_INSPECT_NEED_MORE;
        }
        payload[1] = p[1];
    }
    if (read_len > 2) {
        if ((void *)(p + 3) > data_end) {
            stat_inc(PFWD_STAT_PARSE_SKIPPED);
            return PFWD_INSPECT_NEED_MORE;
        }
        payload[2] = p[2];
    }
    if (read_len > 3) {
        if ((void *)(p + 4) > data_end) {
            stat_inc(PFWD_STAT_PARSE_SKIPPED);
            return PFWD_INSPECT_NEED_MORE;
        }
        payload[3] = p[3];
    }
    if (read_len > 4) {
        if ((void *)(p + 5) > data_end) {
            stat_inc(PFWD_STAT_PARSE_SKIPPED);
            return PFWD_INSPECT_NEED_MORE;
        }
        payload[4] = p[4];
    }
    if (read_len > 5) {
        if ((void *)(p + 6) > data_end) {
            stat_inc(PFWD_STAT_PARSE_SKIPPED);
            return PFWD_INSPECT_NEED_MORE;
        }
        payload[5] = p[5];
    }
    if (read_len > 6) {
        if ((void *)(p + 7) > data_end) {
            stat_inc(PFWD_STAT_PARSE_SKIPPED);
            return PFWD_INSPECT_NEED_MORE;
        }
        payload[6] = p[6];
    }
    if (read_len > 7) {
        if ((void *)(p + 8) > data_end) {
            stat_inc(PFWD_STAT_PARSE_SKIPPED);
            return PFWD_INSPECT_NEED_MORE;
        }
        payload[7] = p[7];
    }
    return inspect_payload_bytes_xdp(payload, read_len, settings);
}

static __always_inline __u32 tcp_payload_prefix_len(const __u8 *payload, void *data_end) {
    __u32 len = 0;

    if ((void *)(payload + 1) > data_end) {
        return 0;
    }
    len = 1;
    if ((void *)(payload + 2) > data_end) {
        return len;
    }
    len = 2;
    if ((void *)(payload + 3) > data_end) {
        return len;
    }
    len = 3;
    if ((void *)(payload + 4) > data_end) {
        return len;
    }
    len = 4;
    if ((void *)(payload + 5) > data_end) {
        return len;
    }
    len = 5;
    if ((void *)(payload + 6) > data_end) {
        return len;
    }
    len = 6;
    if ((void *)(payload + 7) > data_end) {
        return len;
    }
    len = 7;
    if ((void *)(payload + 8) > data_end) {
        return len;
    }
    return 8;
}

static __always_inline int port_skipped(__be16 port) {
    struct pfwd_port_key key = {
        .port = port,
    };
    __u8 *value = bpf_map_lookup_elem(&pfwd_protocol_skip_ports, &key);
    return value != 0;
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

static __always_inline int protocol_guard_active(const struct pfwd_settings *settings) {
    return settings && settings->guard_enabled && (settings->block_http || settings->block_tls || settings->block_socks);
}

static __always_inline int rule_xdp_disabled(const struct pfwd_rule_val *rule) {
    return rule && (rule->flags & PFWD_RULE_F_XDP_DISABLED);
}

static __always_inline int append_guard_prefix(
    const __u8 *payload,
    void *data_end,
    __u32 payload_len,
    struct pfwd_guard_prefix_val *state
) {
    __u32 offset;
    __u32 copy_len = payload_len;

    if (!state) {
        return -1;
    }
    offset = state->seen_len;
    if (offset >= 8 || copy_len == 0) {
        return 0;
    }
    if (copy_len > 8 - offset) {
        copy_len = 8 - offset;
    }
    if (offset == 0) {
        if (copy_len > 0) {
            if ((void *)(payload + 1) > data_end) { stat_inc(PFWD_STAT_PARSE_SKIPPED); return -1; }
            state->prefix[0] = payload[0];
        }
        if (copy_len > 1) {
            if ((void *)(payload + 2) > data_end) { stat_inc(PFWD_STAT_PARSE_SKIPPED); return -1; }
            state->prefix[1] = payload[1];
        }
        if (copy_len > 2) {
            if ((void *)(payload + 3) > data_end) { stat_inc(PFWD_STAT_PARSE_SKIPPED); return -1; }
            state->prefix[2] = payload[2];
        }
        if (copy_len > 3) {
            if ((void *)(payload + 4) > data_end) { stat_inc(PFWD_STAT_PARSE_SKIPPED); return -1; }
            state->prefix[3] = payload[3];
        }
        if (copy_len > 4) {
            if ((void *)(payload + 5) > data_end) { stat_inc(PFWD_STAT_PARSE_SKIPPED); return -1; }
            state->prefix[4] = payload[4];
        }
        if (copy_len > 5) {
            if ((void *)(payload + 6) > data_end) { stat_inc(PFWD_STAT_PARSE_SKIPPED); return -1; }
            state->prefix[5] = payload[5];
        }
        if (copy_len > 6) {
            if ((void *)(payload + 7) > data_end) { stat_inc(PFWD_STAT_PARSE_SKIPPED); return -1; }
            state->prefix[6] = payload[6];
        }
        if (copy_len > 7) {
            if ((void *)(payload + 8) > data_end) { stat_inc(PFWD_STAT_PARSE_SKIPPED); return -1; }
            state->prefix[7] = payload[7];
        }
    } else if (offset == 1) {
        if (copy_len > 0) {
            if ((void *)(payload + 1) > data_end) { stat_inc(PFWD_STAT_PARSE_SKIPPED); return -1; }
            state->prefix[1] = payload[0];
        }
        if (copy_len > 1) {
            if ((void *)(payload + 2) > data_end) { stat_inc(PFWD_STAT_PARSE_SKIPPED); return -1; }
            state->prefix[2] = payload[1];
        }
        if (copy_len > 2) {
            if ((void *)(payload + 3) > data_end) { stat_inc(PFWD_STAT_PARSE_SKIPPED); return -1; }
            state->prefix[3] = payload[2];
        }
        if (copy_len > 3) {
            if ((void *)(payload + 4) > data_end) { stat_inc(PFWD_STAT_PARSE_SKIPPED); return -1; }
            state->prefix[4] = payload[3];
        }
        if (copy_len > 4) {
            if ((void *)(payload + 5) > data_end) { stat_inc(PFWD_STAT_PARSE_SKIPPED); return -1; }
            state->prefix[5] = payload[4];
        }
        if (copy_len > 5) {
            if ((void *)(payload + 6) > data_end) { stat_inc(PFWD_STAT_PARSE_SKIPPED); return -1; }
            state->prefix[6] = payload[5];
        }
        if (copy_len > 6) {
            if ((void *)(payload + 7) > data_end) { stat_inc(PFWD_STAT_PARSE_SKIPPED); return -1; }
            state->prefix[7] = payload[6];
        }
    } else if (offset == 2) {
        if (copy_len > 0) {
            if ((void *)(payload + 1) > data_end) { stat_inc(PFWD_STAT_PARSE_SKIPPED); return -1; }
            state->prefix[2] = payload[0];
        }
        if (copy_len > 1) {
            if ((void *)(payload + 2) > data_end) { stat_inc(PFWD_STAT_PARSE_SKIPPED); return -1; }
            state->prefix[3] = payload[1];
        }
        if (copy_len > 2) {
            if ((void *)(payload + 3) > data_end) { stat_inc(PFWD_STAT_PARSE_SKIPPED); return -1; }
            state->prefix[4] = payload[2];
        }
        if (copy_len > 3) {
            if ((void *)(payload + 4) > data_end) { stat_inc(PFWD_STAT_PARSE_SKIPPED); return -1; }
            state->prefix[5] = payload[3];
        }
        if (copy_len > 4) {
            if ((void *)(payload + 5) > data_end) { stat_inc(PFWD_STAT_PARSE_SKIPPED); return -1; }
            state->prefix[6] = payload[4];
        }
        if (copy_len > 5) {
            if ((void *)(payload + 6) > data_end) { stat_inc(PFWD_STAT_PARSE_SKIPPED); return -1; }
            state->prefix[7] = payload[5];
        }
    } else if (offset == 3) {
        if (copy_len > 0) {
            if ((void *)(payload + 1) > data_end) { stat_inc(PFWD_STAT_PARSE_SKIPPED); return -1; }
            state->prefix[3] = payload[0];
        }
        if (copy_len > 1) {
            if ((void *)(payload + 2) > data_end) { stat_inc(PFWD_STAT_PARSE_SKIPPED); return -1; }
            state->prefix[4] = payload[1];
        }
        if (copy_len > 2) {
            if ((void *)(payload + 3) > data_end) { stat_inc(PFWD_STAT_PARSE_SKIPPED); return -1; }
            state->prefix[5] = payload[2];
        }
        if (copy_len > 3) {
            if ((void *)(payload + 4) > data_end) { stat_inc(PFWD_STAT_PARSE_SKIPPED); return -1; }
            state->prefix[6] = payload[3];
        }
        if (copy_len > 4) {
            if ((void *)(payload + 5) > data_end) { stat_inc(PFWD_STAT_PARSE_SKIPPED); return -1; }
            state->prefix[7] = payload[4];
        }
    } else if (offset == 4) {
        if (copy_len > 0) {
            if ((void *)(payload + 1) > data_end) { stat_inc(PFWD_STAT_PARSE_SKIPPED); return -1; }
            state->prefix[4] = payload[0];
        }
        if (copy_len > 1) {
            if ((void *)(payload + 2) > data_end) { stat_inc(PFWD_STAT_PARSE_SKIPPED); return -1; }
            state->prefix[5] = payload[1];
        }
        if (copy_len > 2) {
            if ((void *)(payload + 3) > data_end) { stat_inc(PFWD_STAT_PARSE_SKIPPED); return -1; }
            state->prefix[6] = payload[2];
        }
        if (copy_len > 3) {
            if ((void *)(payload + 4) > data_end) { stat_inc(PFWD_STAT_PARSE_SKIPPED); return -1; }
            state->prefix[7] = payload[3];
        }
    } else if (offset == 5) {
        if (copy_len > 0) {
            if ((void *)(payload + 1) > data_end) { stat_inc(PFWD_STAT_PARSE_SKIPPED); return -1; }
            state->prefix[5] = payload[0];
        }
        if (copy_len > 1) {
            if ((void *)(payload + 2) > data_end) { stat_inc(PFWD_STAT_PARSE_SKIPPED); return -1; }
            state->prefix[6] = payload[1];
        }
        if (copy_len > 2) {
            if ((void *)(payload + 3) > data_end) { stat_inc(PFWD_STAT_PARSE_SKIPPED); return -1; }
            state->prefix[7] = payload[2];
        }
    } else if (offset == 6) {
        if (copy_len > 0) {
            if ((void *)(payload + 1) > data_end) { stat_inc(PFWD_STAT_PARSE_SKIPPED); return -1; }
            state->prefix[6] = payload[0];
        }
        if (copy_len > 1) {
            if ((void *)(payload + 2) > data_end) { stat_inc(PFWD_STAT_PARSE_SKIPPED); return -1; }
            state->prefix[7] = payload[1];
        }
    } else if (offset == 7) {
        if (copy_len > 0) {
            if ((void *)(payload + 1) > data_end) { stat_inc(PFWD_STAT_PARSE_SKIPPED); return -1; }
            state->prefix[7] = payload[0];
        }
    }
    state->seen_len = offset + copy_len;
    return 0;
}

static __always_inline int inspect_xdp_tcp_flow(
    void *payload_start,
    void *data_end,
    const struct pfwd_settings *settings,
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
    struct pfwd_guard_prefix_val *stored_prefix;
    __u32 payload_len;
    int verdict;

    if (!protocol_guard_active(settings)) {
        return XDP_PASS;
    }
    if (settings->has_skip_ports && port_skipped(dport)) {
        return XDP_PASS;
    }
    payload_len = tcp_payload_prefix_len((const __u8 *)payload_start, data_end);
    if (payload_len == 0) {
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
    stored_prefix = bpf_map_lookup_elem(&pfwd_guard_prefixes, &flow);
    if (!stored_prefix && payload_len >= 8) {
        verdict = inspect_payload_xdp(payload_start, data_end, payload_len, settings);
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
    if (append_guard_prefix(payload_start, data_end, payload_len, &next_prefix) < 0) {
        return XDP_PASS;
    }
    verdict = inspect_guard_prefix(&next_prefix, settings);
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
    struct pfwd_conn_val *existing_conn;
    __be32 source_addr = rule->snat_mode == PFWD_SNAT_FIXED ? ipv4_from16(rule->snat_addr) : listen_addr;
    __be16 source_port;

    if (!scratch) {
        stat_inc(PFWD_STAT_DROPPED);
        return -1;
    }
    __builtin_memset(scratch, 0, sizeof(*scratch));
    scratch->conn_key.family = 4;
    scratch->conn_key.protocol = protocol;
    scratch->conn_key.client_port = client_port;
    scratch->conn_key.listen_port = listen_port;
    scratch->conn_key.target_port = rule->target_port;
    copy_ipv4_to16(scratch->conn_key.client_addr, client_addr);
    copy_ipv4_to16(scratch->conn_key.listen_addr, listen_addr);
    pfwd_memcpy16(scratch->conn_key.target_addr, rule->target_addr);
    existing_conn = bpf_map_lookup_elem(&pfwd_connections, &scratch->conn_key);
    if (existing_conn) {
        return 0;
    }

    scratch->reverse_key.family = 4;
    scratch->reverse_key.protocol = protocol;
    scratch->reverse_key.target_port = rule->target_port;
    pfwd_memcpy16(scratch->reverse_key.target_addr, rule->target_addr);
    source_port = allocate_source_port_v4(&scratch->reverse_key, client_port, client_addr, listen_addr, rule->target_port);
    if (source_port == 0) {
        stat_inc(PFWD_STAT_DROPPED);
        count_drop(rule, packet_len);
        return -1;
    }

    scratch->conn.rule_id = rule->rule_id;
    scratch->conn.user_id = rule->user_id;
    copy_ipv4_to16(scratch->conn.client_addr, client_addr);
    copy_ipv4_to16(scratch->conn.listen_addr, listen_addr);
    copy_ipv4_to16(scratch->conn.source_addr, source_addr);
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
    scratch->conn.packets = 1;
    scratch->conn.bytes = packet_len;
    bpf_map_update_elem(&pfwd_connections, &scratch->conn_key, &scratch->conn, BPF_ANY);

    scratch->reverse_key.source_port = source_port;
    copy_ipv4_to16(scratch->reverse_key.source_addr, source_addr);
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
    struct pfwd_conn_val *existing_conn;
    __be16 source_port;

    if (!scratch) {
        stat_inc(PFWD_STAT_DROPPED);
        return -1;
    }
    __builtin_memset(scratch, 0, sizeof(*scratch));
    scratch->conn_key.family = 6;
    scratch->conn_key.protocol = protocol;
    scratch->conn_key.client_port = client_port;
    scratch->conn_key.listen_port = listen_port;
    scratch->conn_key.target_port = rule->target_port;
    pfwd_memcpy16(scratch->conn_key.client_addr, client_addr);
    pfwd_memcpy16(scratch->conn_key.listen_addr, listen_addr);
    pfwd_memcpy16(scratch->conn_key.target_addr, rule->target_addr);
    existing_conn = bpf_map_lookup_elem(&pfwd_connections, &scratch->conn_key);
    if (existing_conn) {
        return 0;
    }

    scratch->reverse_key.family = 6;
    scratch->reverse_key.protocol = protocol;
    scratch->reverse_key.target_port = rule->target_port;
    pfwd_memcpy16(scratch->reverse_key.target_addr, rule->target_addr);
    pfwd_memcpy16(scratch->addr_a, client_addr);
    pfwd_memcpy16(scratch->addr_b, listen_addr);
    if (rule->snat_mode == PFWD_SNAT_FIXED) {
        pfwd_memcpy16(scratch->addr_c, rule->snat_addr);
    } else {
        pfwd_memcpy16(scratch->addr_c, listen_addr);
    }
    source_port = allocate_source_port_v6(&scratch->reverse_key, client_port, scratch->addr_a, scratch->addr_b, rule->target_port);
    if (source_port == 0) {
        stat_inc(PFWD_STAT_DROPPED);
        count_drop(rule, packet_len);
        return -1;
    }

    scratch->conn.rule_id = rule->rule_id;
    scratch->conn.user_id = rule->user_id;
    pfwd_memcpy16(scratch->conn.client_addr, client_addr);
    pfwd_memcpy16(scratch->conn.listen_addr, listen_addr);
    pfwd_memcpy16(scratch->conn.source_addr, scratch->addr_c);
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
    scratch->conn.packets = 1;
    scratch->conn.bytes = packet_len;
    bpf_map_update_elem(&pfwd_connections, &scratch->conn_key, &scratch->conn, BPF_ANY);

    scratch->reverse_key.source_port = source_port;
    pfwd_memcpy16(scratch->reverse_key.source_addr, scratch->addr_c);
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
    const struct pfwd_settings *settings,
    struct pfwd_rule_val *rule,
    __u64 packet_len
) {
    __u32 scratch_key = 0;
    struct pfwd_scratch *scratch = bpf_map_lookup_elem(&pfwd_scratch, &scratch_key);
    struct bpf_sock *sk;
    __u8 conn_state = PFWD_CONN_STATE_NONE;

    if (settings && settings->whitelist_enabled && !whitelist_allowed_v4(ip4->saddr)) {
        stat_inc(PFWD_STAT_WHITELIST_DROPPED);
        count_drop(rule, packet_len);
        return TC_ACT_SHOT;
    }
    if (protocol == IPPROTO_TCP) {
        struct tcphdr_min *tcp = (void *)ip4 + ihl;
        __u32 tcp_len = (__u32)(tcp->doff_res >> 4) * 4;
        void *payload_start = (void *)tcp + tcp_len;
        __u8 src16[16];
        __u8 dst16[16];
        if (tcp_len < sizeof(*tcp) || (void *)(tcp + 1) > data_end) {
            stat_inc(PFWD_STAT_PARSE_SKIPPED);
            return TC_ACT_OK;
        }
        copy_ipv4_to16(src16, ip4->saddr);
        copy_ipv4_to16(dst16, ip4->daddr);
        if (inspect_xdp_tcp_flow(payload_start, data_end, settings, rule, packet_len, 4, src16, dst16, sport, dport) == XDP_DROP) {
            return TC_ACT_SHOT;
        }
        conn_state = tcp_syn_only(tcp) ? PFWD_CONN_STATE_TCP_SYN_PENDING : PFWD_CONN_STATE_TCP_ESTABLISHED;
    }
    if ((rule->rule_limit_bytes > 0 || rule->user_limit_bytes > 0) && traffic_over_limit(rule, packet_len, 0)) {
        stat_inc(PFWD_STAT_QUOTA_DROPPED);
        count_drop(rule, packet_len);
        return TC_ACT_SHOT;
    }
    sk = lookup_local_socket_v4(ctx, protocol, ip4->saddr, ipv4_from16(rule->target_addr), sport, rule->target_port);
    if (!sk) {
        stat_inc(PFWD_STAT_DROPPED);
        count_drop(rule, packet_len);
        return TC_ACT_SHOT;
    }
    bpf_sk_release(sk);
    if (prepare_local_conn_v4(ip4->saddr, ip4->daddr, sport, dport, protocol, conn_state, rule, scratch, packet_len) < 0) {
        return TC_ACT_SHOT;
    }
    count_input(rule, packet_len, 1);
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
    const struct pfwd_settings *settings,
    struct pfwd_rule_val *rule,
    __u64 packet_len
) {
    __u32 scratch_key = 0;
    struct pfwd_scratch *scratch = bpf_map_lookup_elem(&pfwd_scratch, &scratch_key);
    struct bpf_sock *sk;
    __u8 conn_state = PFWD_CONN_STATE_NONE;

    if (settings && settings->whitelist_enabled && !whitelist_allowed_v6(ip6->saddr)) {
        stat_inc(PFWD_STAT_WHITELIST_DROPPED);
        count_drop(rule, packet_len);
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
        if (inspect_xdp_tcp_flow(payload_start, data_end, settings, rule, packet_len, 6, ip6->saddr, ip6->daddr, sport, dport) == XDP_DROP) {
            return TC_ACT_SHOT;
        }
        conn_state = tcp_syn_only(tcp) ? PFWD_CONN_STATE_TCP_SYN_PENDING : PFWD_CONN_STATE_TCP_ESTABLISHED;
    }
    if ((rule->rule_limit_bytes > 0 || rule->user_limit_bytes > 0) && traffic_over_limit(rule, packet_len, 0)) {
        stat_inc(PFWD_STAT_QUOTA_DROPPED);
        count_drop(rule, packet_len);
        return TC_ACT_SHOT;
    }
    sk = lookup_local_socket_v6(ctx, protocol, ip6->saddr, rule->target_addr, sport, rule->target_port);
    if (!sk) {
        stat_inc(PFWD_STAT_DROPPED);
        count_drop(rule, packet_len);
        return TC_ACT_SHOT;
    }
    bpf_sk_release(sk);
    if (prepare_local_conn_v6(ip6->saddr, ip6->daddr, sport, dport, protocol, conn_state, rule, scratch, packet_len) < 0) {
        return TC_ACT_SHOT;
    }
    count_input(rule, packet_len, 1);
    stat_inc(PFWD_STAT_FORWARDED);
    return TC_ACT_OK;
}

SEC("xdp")
int pfwd_xdp(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    __u64 packet_len = (__u64)(data_end - data);
    __u32 settings_key = 0;
    struct pfwd_settings *settings;

    if ((void *)(eth + 1) > data_end) {
        stat_inc(PFWD_STAT_PARSE_SKIPPED);
        return XDP_PASS;
    }
    settings = bpf_map_lookup_elem(&pfwd_settings, &settings_key);

    if (bpf_ntohs(eth->h_proto) == ETH_P_IP) {
        struct ipv4hdr_min *ip4 = (void *)(eth + 1);
        __u32 ihl;
        __u8 protocol;
        __be16 sport = 0;
        __be16 dport = 0;
        __u8 listen_addr[16];
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

        copy_ipv4_to16(listen_addr, ip4->daddr);
        rule = lookup_forward_rule(4, protocol, dport, listen_addr);
        if (rule) {
            if (rule_xdp_disabled(rule)) {
                stat_inc(PFWD_STAT_PASSED);
                return XDP_PASS;
            }
            if (rule_target_is_loopback(4, rule)) {
                return XDP_PASS;
            }
            __u32 scratch_key = 0;
            struct pfwd_scratch *scratch = bpf_map_lookup_elem(&pfwd_scratch, &scratch_key);
            struct pfwd_conn_val *existing_conn = 0;
            __be32 old_saddr = ip4->saddr;
            __be32 old_daddr = ip4->daddr;
            __be16 old_sport = sport;
            __be16 old_dport = dport;
            __be32 new_saddr = rule->snat_mode == PFWD_SNAT_FIXED ? ipv4_from16(rule->snat_addr) : old_daddr;
            __be32 new_daddr = ipv4_from16(rule->target_addr);
            __be16 new_sport = sport;
            __be16 new_dport = rule->target_port;
            if (settings && settings->whitelist_enabled && !whitelist_allowed_v4(ip4->saddr)) {
                stat_inc(PFWD_STAT_WHITELIST_DROPPED);
                count_drop(rule, packet_len);
                return XDP_DROP;
            }
            if (protocol == IPPROTO_TCP) {
                struct tcphdr_min *tcp = (void *)ip4 + ihl;
                __u32 tcp_len = (__u32)(tcp->doff_res >> 4) * 4;
                void *payload_start = (void *)tcp + tcp_len;
                __u8 src16[16];
                __u8 dst16[16];
                if (tcp_len < sizeof(*tcp)) {
                    stat_inc(PFWD_STAT_PARSE_SKIPPED);
                    return XDP_PASS;
                }
                copy_ipv4_to16(src16, ip4->saddr);
                copy_ipv4_to16(dst16, ip4->daddr);
                if (inspect_xdp_tcp_flow(payload_start, data_end, settings, rule, packet_len, 4, src16, dst16, sport, dport) == XDP_DROP) {
                    return XDP_DROP;
                }
                tcp_conn_state = tcp_syn_only(tcp) ? PFWD_CONN_STATE_TCP_SYN_PENDING : PFWD_CONN_STATE_TCP_ESTABLISHED;
            }
            if ((rule->rule_limit_bytes > 0 || rule->user_limit_bytes > 0) && traffic_over_limit(rule, packet_len, 0)) {
                stat_inc(PFWD_STAT_QUOTA_DROPPED);
                count_drop(rule, packet_len);
                return XDP_DROP;
            }
            if (!scratch) {
                stat_inc(PFWD_STAT_DROPPED);
                return XDP_DROP;
            }
            __builtin_memset(scratch, 0, sizeof(*scratch));
            scratch->conn_key.family = 4;
            scratch->conn_key.protocol = protocol;
            scratch->conn_key.client_port = sport;
            scratch->conn_key.listen_port = dport;
            scratch->conn_key.target_port = rule->target_port;
            copy_ipv4_to16(scratch->conn_key.client_addr, ip4->saddr);
            copy_ipv4_to16(scratch->conn_key.listen_addr, ip4->daddr);
            pfwd_memcpy16(scratch->conn_key.target_addr, rule->target_addr);
            scratch->reverse_key.family = 4;
            scratch->reverse_key.protocol = protocol;
            scratch->reverse_key.target_port = new_dport;
            copy_ipv4_to16(scratch->reverse_key.source_addr, new_saddr);
            pfwd_memcpy16(scratch->reverse_key.target_addr, rule->target_addr);
            existing_conn = bpf_map_lookup_elem(&pfwd_connections, &scratch->conn_key);
            if (existing_conn) {
                new_sport = existing_conn->source_port;
                new_saddr = ipv4_from16(existing_conn->source_addr);
                if (protocol == IPPROTO_TCP && tcp_conn_state == PFWD_CONN_STATE_TCP_ESTABLISHED) {
                    mark_tcp_established(existing_conn);
                }
            } else {
                new_sport = allocate_source_port_v4(&scratch->reverse_key, sport, old_saddr, old_daddr, new_dport);
                if (new_sport == 0) {
                    stat_inc(PFWD_STAT_DROPPED);
                    count_drop(rule, packet_len);
                    return XDP_DROP;
                }
            }
            if (!existing_conn) {
                scratch->conn.rule_id = rule->rule_id;
                scratch->conn.user_id = rule->user_id;
                copy_ipv4_to16(scratch->conn.client_addr, old_saddr);
                copy_ipv4_to16(scratch->conn.listen_addr, old_daddr);
                copy_ipv4_to16(scratch->conn.source_addr, new_saddr);
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
                scratch->conn.packets = 1;
                scratch->conn.bytes = packet_len;
                bpf_map_update_elem(&pfwd_connections, &scratch->conn_key, &scratch->conn, BPF_ANY);
                scratch->reverse_key.source_port = new_sport;
                copy_ipv4_to16(scratch->reverse_key.source_addr, new_saddr);
                bpf_map_update_elem(&pfwd_reverse, &scratch->reverse_key, &scratch->conn, BPF_ANY);
            }
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
                if (rule->mss_mode != PFWD_MSS_NONE) {
                    adjust_tcp_mss(tcp, data_end, rule->mss_value);
                }
            } else {
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
            {
                int action = fib_redirect_v4(ctx, eth, ip4, protocol, new_sport, new_dport);
                if (action == XDP_DROP) {
                    count_drop(rule, packet_len);
                    return action;
                }
                count_input(rule, packet_len, 1);
                stat_inc(PFWD_STAT_FORWARDED);
                return action;
            }
        }

        {
            struct pfwd_reverse_key reverse_key = {};
            struct pfwd_conn_val *conn;
            __be32 old_saddr = ip4->saddr;
            __be32 old_daddr = ip4->daddr;
            reverse_key.family = 4;
            reverse_key.protocol = protocol;
            reverse_key.source_port = dport;
            reverse_key.target_port = sport;
            reverse_key.client_port = 0;
            copy_ipv4_to16(reverse_key.source_addr, ip4->daddr);
            copy_ipv4_to16(reverse_key.target_addr, ip4->saddr);
            copy_ipv4_to16(reverse_key.client_addr, 0);
            conn = bpf_map_lookup_elem(&pfwd_reverse, &reverse_key);
            if (conn) {
                if (protocol == IPPROTO_TCP) {
                    mark_tcp_established(conn);
                }
                __be16 new_sport = conn->listen_port;
                __be16 new_dport = conn->source_port;
                __be32 new_saddr = ipv4_from16(conn->listen_addr);
                __be32 new_daddr = ipv4_from16(conn->client_addr);
                ip4->saddr = new_saddr;
                ip4->daddr = new_daddr;
                ip4->check = csum_replace32(ip4->check, old_saddr, new_saddr);
                ip4->check = csum_replace32(ip4->check, old_daddr, new_daddr);
                if (protocol == IPPROTO_TCP) {
                    struct tcphdr_min *tcp = (void *)ip4 + ihl;
                    __be16 old_src_port = tcp->source;
                    __be16 old_dst_port = tcp->dest;
                    tcp->source = new_sport;
                    tcp->dest = new_dport;
                    tcp->check = csum_replace32(tcp->check, old_saddr, new_saddr);
                    tcp->check = csum_replace32(tcp->check, old_daddr, new_daddr);
                    tcp->check = csum_replace16(tcp->check, old_src_port, new_sport);
                    tcp->check = csum_replace16(tcp->check, old_dst_port, new_dport);
                } else {
                    struct udphdr_min *udp = (void *)ip4 + ihl;
                    __be16 old_src_port = udp->source;
                    __be16 old_dst_port = udp->dest;
                    udp->source = new_sport;
                    udp->dest = new_dport;
                    if (udp->check) {
                        udp->check = csum_replace32(udp->check, old_saddr, new_saddr);
                        udp->check = csum_replace32(udp->check, old_daddr, new_daddr);
                        udp->check = csum_replace16(udp->check, old_src_port, new_sport);
                        udp->check = csum_replace16(udp->check, old_dst_port, new_dport);
                    }
                }
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
            __u32 scratch_key = 0;
            struct pfwd_scratch *scratch = bpf_map_lookup_elem(&pfwd_scratch, &scratch_key);
            struct pfwd_conn_val *existing_conn = 0;
            __be16 new_sport = sport;
            if (settings && settings->whitelist_enabled && !whitelist_allowed_v6(ip6->saddr)) {
                stat_inc(PFWD_STAT_WHITELIST_DROPPED);
                count_drop(rule, packet_len);
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
                if (inspect_xdp_tcp_flow(payload_start, data_end, settings, rule, packet_len, 6, ip6->saddr, ip6->daddr, sport, dport) == XDP_DROP) {
                    return XDP_DROP;
                }
                tcp_conn_state = tcp_syn_only(tcp) ? PFWD_CONN_STATE_TCP_SYN_PENDING : PFWD_CONN_STATE_TCP_ESTABLISHED;
            }
            if ((rule->rule_limit_bytes > 0 || rule->user_limit_bytes > 0) && traffic_over_limit(rule, packet_len, 0)) {
                stat_inc(PFWD_STAT_QUOTA_DROPPED);
                count_drop(rule, packet_len);
                return XDP_DROP;
            }
            if (!scratch) {
                stat_inc(PFWD_STAT_DROPPED);
                return XDP_DROP;
            }
            __builtin_memset(scratch, 0, sizeof(*scratch));
            scratch->conn_key.family = 6;
            scratch->conn_key.protocol = protocol;
            scratch->conn_key.client_port = sport;
            scratch->conn_key.listen_port = dport;
            scratch->conn_key.target_port = rule->target_port;
            pfwd_memcpy16(scratch->conn_key.client_addr, ip6->saddr);
            pfwd_memcpy16(scratch->conn_key.listen_addr, ip6->daddr);
            pfwd_memcpy16(scratch->conn_key.target_addr, rule->target_addr);
            pfwd_memcpy16(scratch->addr_a, ip6->saddr);
            pfwd_memcpy16(scratch->addr_b, ip6->daddr);
            if (rule->snat_mode == PFWD_SNAT_FIXED) {
                pfwd_memcpy16(scratch->addr_c, rule->snat_addr);
            } else {
                pfwd_memcpy16(scratch->addr_c, ip6->daddr);
            }
            scratch->reverse_key.family = 6;
            scratch->reverse_key.protocol = protocol;
            scratch->reverse_key.target_port = rule->target_port;
            pfwd_memcpy16(scratch->reverse_key.source_addr, scratch->addr_c);
            pfwd_memcpy16(scratch->reverse_key.target_addr, rule->target_addr);
            existing_conn = bpf_map_lookup_elem(&pfwd_connections, &scratch->conn_key);
            if (existing_conn) {
                new_sport = existing_conn->source_port;
                pfwd_memcpy16(scratch->addr_c, existing_conn->source_addr);
                if (protocol == IPPROTO_TCP && tcp_conn_state == PFWD_CONN_STATE_TCP_ESTABLISHED) {
                    mark_tcp_established(existing_conn);
                }
            } else {
                new_sport = allocate_source_port_v6(&scratch->reverse_key, sport, scratch->addr_a, scratch->addr_b, rule->target_port);
                if (new_sport == 0) {
                    stat_inc(PFWD_STAT_DROPPED);
                    count_drop(rule, packet_len);
                    return XDP_DROP;
                }
            }
            if (!existing_conn) {
                scratch->conn.rule_id = rule->rule_id;
                scratch->conn.user_id = rule->user_id;
                pfwd_memcpy16(scratch->conn.client_addr, scratch->addr_a);
                pfwd_memcpy16(scratch->conn.listen_addr, scratch->addr_b);
                pfwd_memcpy16(scratch->conn.source_addr, scratch->addr_c);
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
                bpf_map_update_elem(&pfwd_connections, &scratch->conn_key, &scratch->conn, BPF_ANY);
                scratch->reverse_key.source_port = new_sport;
                pfwd_memcpy16(scratch->reverse_key.source_addr, scratch->addr_c);
                bpf_map_update_elem(&pfwd_reverse, &scratch->reverse_key, &scratch->conn, BPF_ANY);
            }
            pfwd_memcpy16(ip6->saddr, scratch->addr_c);
            pfwd_memcpy16(ip6->daddr, rule->target_addr);
            if (protocol == IPPROTO_TCP) {
                struct tcphdr_min *tcp = (void *)(ip6 + 1);
                __be16 old_sport = tcp->source;
                __be16 old_dport = tcp->dest;
                tcp->source = new_sport;
                tcp->dest = rule->target_port;
                tcp->check = csum_replace_addr16(tcp->check, scratch->addr_a, ip6->saddr);
                tcp->check = csum_replace_addr16(tcp->check, scratch->addr_b, rule->target_addr);
                tcp->check = csum_replace16(tcp->check, old_sport, new_sport);
                tcp->check = csum_replace16(tcp->check, old_dport, rule->target_port);
                if (rule->mss_mode != PFWD_MSS_NONE) {
                    adjust_tcp_mss(tcp, data_end, rule->mss_value);
                }
            } else {
                struct udphdr_min *udp = (void *)(ip6 + 1);
                __be16 old_sport = udp->source;
                __be16 old_dport = udp->dest;
                udp->source = new_sport;
                udp->dest = rule->target_port;
                if (udp->check) {
                    udp->check = csum_replace_addr16(udp->check, scratch->addr_a, ip6->saddr);
                    udp->check = csum_replace_addr16(udp->check, scratch->addr_b, rule->target_addr);
                    udp->check = csum_replace16(udp->check, old_sport, new_sport);
                    udp->check = csum_replace16(udp->check, old_dport, rule->target_port);
                }
            }
            {
                int action = fib_redirect_v6(ctx, eth, ip6, protocol, new_sport, rule->target_port);
                if (action == XDP_DROP) {
                    count_drop(rule, packet_len);
                    return action;
                }
                count_input(rule, packet_len, 1);
                stat_inc(PFWD_STAT_FORWARDED);
                return action;
            }
        }
        {
            struct pfwd_reverse_key reverse_key = {};
            struct pfwd_conn_val *conn;
            reverse_key.family = 6;
            reverse_key.protocol = protocol;
            reverse_key.source_port = dport;
            reverse_key.target_port = sport;
            reverse_key.client_port = 0;
            pfwd_memcpy16(reverse_key.source_addr, ip6->daddr);
            pfwd_memcpy16(reverse_key.target_addr, ip6->saddr);
            zero_addr16(reverse_key.client_addr);
            conn = bpf_map_lookup_elem(&pfwd_reverse, &reverse_key);
            if (conn) {
                if (protocol == IPPROTO_TCP) {
                    mark_tcp_established(conn);
                }
                __u8 old_saddr[16];
                __u8 old_daddr[16];
                __be16 new_sport = conn->listen_port;
                __be16 new_dport = conn->source_port;
                pfwd_memcpy16(old_saddr, ip6->saddr);
                pfwd_memcpy16(old_daddr, ip6->daddr);
                pfwd_memcpy16(ip6->saddr, conn->listen_addr);
                pfwd_memcpy16(ip6->daddr, conn->client_addr);
                if (protocol == IPPROTO_TCP) {
                    struct tcphdr_min *tcp = (void *)(ip6 + 1);
                    __be16 old_sport = tcp->source;
                    __be16 old_dport = tcp->dest;
                    tcp->source = new_sport;
                    tcp->dest = new_dport;
                    tcp->check = csum_replace_addr16(tcp->check, old_saddr, ip6->saddr);
                    tcp->check = csum_replace_addr16(tcp->check, old_daddr, ip6->daddr);
                    tcp->check = csum_replace16(tcp->check, old_sport, new_sport);
                    tcp->check = csum_replace16(tcp->check, old_dport, new_dport);
                } else {
                    struct udphdr_min *udp = (void *)(ip6 + 1);
                    __be16 old_sport = udp->source;
                    __be16 old_dport = udp->dest;
                    udp->source = new_sport;
                    udp->dest = new_dport;
                    if (udp->check) {
                        udp->check = csum_replace_addr16(udp->check, old_saddr, ip6->saddr);
                        udp->check = csum_replace_addr16(udp->check, old_daddr, ip6->daddr);
                        udp->check = csum_replace16(udp->check, old_sport, new_sport);
                        udp->check = csum_replace16(udp->check, old_dport, new_dport);
                    }
                }
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
    __u32 settings_key = 0;
    struct pfwd_settings *settings = bpf_map_lookup_elem(&pfwd_settings, &settings_key);
    __u64 packet_len = skb->len;

    if (bpf_skb_pull_data(skb, skb->len) < 0) {
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
        __u8 listen_addr[16];
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
            struct tcphdr_min *tcp = (void *)ip4 + ihl;
            __u32 tcp_len;
            void *payload_start;
            __u8 src16[16];
            __u8 dst16[16];
            if ((void *)(tcp + 1) > data_end) {
                stat_inc(PFWD_STAT_PARSE_SKIPPED);
                return TC_ACT_OK;
            }
            sport = tcp->source;
            dport = tcp->dest;
            copy_ipv4_to16(listen_addr, ip4->daddr);
            rule = lookup_forward_rule(4, protocol, dport, listen_addr);
            if (rule && !rule_xdp_disabled(rule) && rule_target_is_loopback(4, rule)) {
                return tc_local_forward_v4(skb, data_end, ip4, ihl, protocol, sport, dport, settings, rule, packet_len);
            }
            if (!rule || !protocol_guard_active(settings) || (settings->has_skip_ports && port_skipped(dport))) {
                return TC_ACT_OK;
            }
            tcp_len = (__u32)(tcp->doff_res >> 4) * 4;
            payload_start = (void *)tcp + tcp_len;
            if (tcp_len < sizeof(*tcp)) {
                stat_inc(PFWD_STAT_PARSE_SKIPPED);
                return TC_ACT_OK;
            }
            copy_ipv4_to16(src16, ip4->saddr);
            copy_ipv4_to16(dst16, ip4->daddr);
            if (inspect_xdp_tcp_flow(payload_start, data_end, settings, rule, packet_len, 4, src16, dst16, sport, dport) == XDP_DROP) {
                return TC_ACT_SHOT;
            }
            return TC_ACT_OK;
        }
        {
            struct udphdr_min *udp = (void *)ip4 + ihl;
            if ((void *)(udp + 1) > data_end) {
                stat_inc(PFWD_STAT_PARSE_SKIPPED);
                return TC_ACT_OK;
            }
            sport = udp->source;
            dport = udp->dest;
            copy_ipv4_to16(listen_addr, ip4->daddr);
            rule = lookup_forward_rule(4, protocol, dport, listen_addr);
            if (rule && !rule_xdp_disabled(rule) && rule_target_is_loopback(4, rule)) {
                return tc_local_forward_v4(skb, data_end, ip4, ihl, protocol, sport, dport, settings, rule, packet_len);
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
            stat_inc(PFWD_STAT_PARSE_SKIPPED);
            return TC_ACT_OK;
        }
        protocol = ip6->nexthdr;
        if (protocol != IPPROTO_TCP && protocol != IPPROTO_UDP) {
            return TC_ACT_OK;
        }
        if (protocol == IPPROTO_TCP) {
            struct tcphdr_min *tcp = (void *)(ip6 + 1);
            __u32 tcp_len;
            void *payload_start;
            if ((void *)(tcp + 1) > data_end) {
                stat_inc(PFWD_STAT_PARSE_SKIPPED);
                return TC_ACT_OK;
            }
            sport = tcp->source;
            dport = tcp->dest;
            rule = lookup_forward_rule(6, protocol, dport, ip6->daddr);
            if (rule && !rule_xdp_disabled(rule) && rule_target_is_loopback(6, rule)) {
                return tc_local_forward_v6(skb, data_end, ip6, protocol, sport, dport, settings, rule, packet_len);
            }
            if (!rule || !protocol_guard_active(settings) || (settings->has_skip_ports && port_skipped(dport))) {
                return TC_ACT_OK;
            }
            tcp_len = (__u32)(tcp->doff_res >> 4) * 4;
            payload_start = (void *)tcp + tcp_len;
            if (tcp_len < sizeof(*tcp)) {
                stat_inc(PFWD_STAT_PARSE_SKIPPED);
                return TC_ACT_OK;
            }
            if (inspect_xdp_tcp_flow(payload_start, data_end, settings, rule, packet_len, 6, ip6->saddr, ip6->daddr, sport, dport) == XDP_DROP) {
                return TC_ACT_SHOT;
            }
            return TC_ACT_OK;
        }
        {
            struct udphdr_min *udp = (void *)(ip6 + 1);
            if ((void *)(udp + 1) > data_end) {
                stat_inc(PFWD_STAT_PARSE_SKIPPED);
                return TC_ACT_OK;
            }
            sport = udp->source;
            dport = udp->dest;
            rule = lookup_forward_rule(6, protocol, dport, ip6->daddr);
            if (rule && !rule_xdp_disabled(rule) && rule_target_is_loopback(6, rule)) {
                return tc_local_forward_v6(skb, data_end, ip6, protocol, sport, dport, settings, rule, packet_len);
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
    __u32 settings_key = 0;
    struct pfwd_settings *settings = bpf_map_lookup_elem(&pfwd_settings, &settings_key);
    __u64 packet_len = skb->len;

    if (!settings) {
        return TC_ACT_OK;
    }
    if (bpf_skb_pull_data(skb, skb->len) < 0) {
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
        struct pfwd_reverse_key reverse_key = {};
        struct pfwd_conn_val *conn;
        __be32 old_saddr;
        __be32 old_daddr;

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
            struct tcphdr_min *tcp = (void *)ip4 + ihl;
            if ((void *)(tcp + 1) > data_end) {
                stat_inc(PFWD_STAT_PARSE_SKIPPED);
                return TC_ACT_OK;
            }
            sport = tcp->source;
            dport = tcp->dest;
        } else {
            struct udphdr_min *udp = (void *)ip4 + ihl;
            if ((void *)(udp + 1) > data_end) {
                stat_inc(PFWD_STAT_PARSE_SKIPPED);
                return TC_ACT_OK;
            }
            sport = udp->source;
            dport = udp->dest;
        }
        old_saddr = ip4->saddr;
        old_daddr = ip4->daddr;
        reverse_key.family = 4;
        reverse_key.protocol = protocol;
        reverse_key.source_port = dport;
        reverse_key.target_port = sport;
        reverse_key.client_port = 0;
        copy_ipv4_to16(reverse_key.source_addr, ip4->daddr);
        copy_ipv4_to16(reverse_key.target_addr, ip4->saddr);
        zero_addr16(reverse_key.client_addr);
        conn = bpf_map_lookup_elem(&pfwd_reverse, &reverse_key);
        if (!conn) {
            return TC_ACT_OK;
        }
        if (protocol == IPPROTO_TCP) {
            mark_tcp_established(conn);
        }
        {
            __be16 new_sport = conn->listen_port;
            __be16 new_dport = conn->source_port;
            __be32 new_saddr = ipv4_from16(conn->listen_addr);
            __be32 new_daddr = ipv4_from16(conn->client_addr);
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
                tcp->check = csum_replace16(tcp->check, sport, new_sport);
                tcp->check = csum_replace16(tcp->check, dport, new_dport);
            } else {
                struct udphdr_min *udp = (void *)ip4 + ihl;
                udp->source = new_sport;
                udp->dest = new_dport;
                if (udp->check) {
                    udp->check = csum_replace32(udp->check, old_saddr, new_saddr);
                    udp->check = csum_replace32(udp->check, old_daddr, new_daddr);
                    udp->check = csum_replace16(udp->check, sport, new_sport);
                    udp->check = csum_replace16(udp->check, dport, new_dport);
                }
            }
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
        struct pfwd_reverse_key reverse_key = {};
        struct pfwd_conn_val *conn;
        __u8 old_saddr[16];
        __u8 old_daddr[16];

        if ((void *)(ip6 + 1) > data_end) {
            stat_inc(PFWD_STAT_PARSE_SKIPPED);
            return TC_ACT_OK;
        }
        protocol = ip6->nexthdr;
        if (protocol != IPPROTO_TCP && protocol != IPPROTO_UDP) {
            return TC_ACT_OK;
        }
        if (protocol == IPPROTO_TCP) {
            struct tcphdr_min *tcp = (void *)(ip6 + 1);
            if ((void *)(tcp + 1) > data_end) {
                stat_inc(PFWD_STAT_PARSE_SKIPPED);
                return TC_ACT_OK;
            }
            sport = tcp->source;
            dport = tcp->dest;
        } else {
            struct udphdr_min *udp = (void *)(ip6 + 1);
            if ((void *)(udp + 1) > data_end) {
                stat_inc(PFWD_STAT_PARSE_SKIPPED);
                return TC_ACT_OK;
            }
            sport = udp->source;
            dport = udp->dest;
        }
        reverse_key.family = 6;
        reverse_key.protocol = protocol;
        reverse_key.source_port = dport;
        reverse_key.target_port = sport;
        reverse_key.client_port = 0;
        pfwd_memcpy16(reverse_key.source_addr, ip6->daddr);
        pfwd_memcpy16(reverse_key.target_addr, ip6->saddr);
        zero_addr16(reverse_key.client_addr);
        conn = bpf_map_lookup_elem(&pfwd_reverse, &reverse_key);
        if (!conn) {
            return TC_ACT_OK;
        }
        if (protocol == IPPROTO_TCP) {
            mark_tcp_established(conn);
        }
        pfwd_memcpy16(old_saddr, ip6->saddr);
        pfwd_memcpy16(old_daddr, ip6->daddr);
        pfwd_memcpy16(ip6->saddr, conn->listen_addr);
        pfwd_memcpy16(ip6->daddr, conn->client_addr);
        {
            __be16 new_sport = conn->listen_port;
            __be16 new_dport = conn->source_port;
            if (protocol == IPPROTO_TCP) {
                struct tcphdr_min *tcp = (void *)(ip6 + 1);
                tcp->source = new_sport;
                tcp->dest = new_dport;
                tcp->check = csum_replace_addr16(tcp->check, old_saddr, ip6->saddr);
                tcp->check = csum_replace_addr16(tcp->check, old_daddr, ip6->daddr);
                tcp->check = csum_replace16(tcp->check, sport, new_sport);
                tcp->check = csum_replace16(tcp->check, dport, new_dport);
            } else {
                struct udphdr_min *udp = (void *)(ip6 + 1);
                udp->source = new_sport;
                udp->dest = new_dport;
                if (udp->check) {
                    udp->check = csum_replace_addr16(udp->check, old_saddr, ip6->saddr);
                    udp->check = csum_replace_addr16(udp->check, old_daddr, ip6->daddr);
                    udp->check = csum_replace16(udp->check, sport, new_sport);
                    udp->check = csum_replace16(udp->check, dport, new_dport);
                }
            }
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
        copy_ipv4_to16(listen_addr, ctx->local_ip4);
        rule = lookup_forward_rule(4, (__u8)ctx->protocol, bpf_htons((__u16)ctx->local_port), listen_addr);
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
