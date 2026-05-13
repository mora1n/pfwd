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
    PFWD_STAT_MAX = 7,
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

struct pfwd_settings {
    __u8 whitelist_enabled;
    __u8 block_http;
    __u8 block_tls;
    __u8 block_socks;
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
    __u8 pad[7];
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
    __u8 pad8[7];
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
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, PFWD_MAX_RULES);
    __type(key, __u32);
    __type(value, struct pfwd_counter);
} pfwd_rule_counters SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, PFWD_MAX_USERS);
    __type(key, __u32);
    __type(value, struct pfwd_counter);
} pfwd_user_counters SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
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
    __type(key, struct pfwd_flow_key);
    __type(value, __u8);
} pfwd_allowed_flows SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct pfwd_scratch);
} pfwd_scratch SEC(".maps");

static __always_inline void stat_inc(__u32 index) {
    __u64 *value = bpf_map_lookup_elem(&pfwd_stats, &index);
    if (value) {
        __sync_fetch_and_add(value, 1);
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

static __always_inline int whitelist_match_v4(__be32 addr) {
    struct pfwd_whitelist_key_v4 key = {
        .prefixlen = 32,
        .addr = addr,
    };
    __u8 *value = bpf_map_lookup_elem(&pfwd_whitelist_v4, &key);
    return value != 0;
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

static __always_inline int traffic_over_limit(const struct pfwd_rule_val *rule, __u64 input_delta, __u64 output_delta) {
    struct pfwd_counter *rule_counter;
    struct pfwd_counter *user_counter;
    __u64 billed_delta;
    __u64 current_rule;
    __u64 current_user;
    __u32 rule_id = rule->rule_id;
    __u32 user_id = rule->user_id;
    __u64 ratio = rule->traffic_ratio_scaled;
    if (ratio == 0) {
        ratio = PFWD_RATIO_SCALE;
    }
    billed_delta = ((input_delta * ratio) / PFWD_RATIO_SCALE) + ((output_delta * ratio) / PFWD_RATIO_SCALE);
    if (rule->traffic_mode != 1) {
        billed_delta *= 2;
    }
    rule_counter = bpf_map_lookup_elem(&pfwd_rule_counters, &rule_id);
    current_rule = rule->rule_billing_used_base_bytes;
    if (rule_counter) {
        current_rule += rule_counter->billing_bytes;
    }
    user_counter = bpf_map_lookup_elem(&pfwd_user_counters, &user_id);
    current_user = rule->user_billing_used_base_bytes;
    if (user_counter) {
        current_user += user_counter->billing_bytes;
    }
    if (rule->rule_limit_bytes > 0 && current_rule + billed_delta > rule->rule_limit_bytes) {
        return 1;
    }
    if (rule->user_limit_bytes > 0 && current_user + billed_delta > rule->user_limit_bytes) {
        return 1;
    }
    return 0;
}

static __always_inline void count_input(const struct pfwd_rule_val *rule, __u64 bytes, __u64 packets) {
    struct pfwd_counter *counter;
    __u32 key = rule->rule_id;
    __u64 ratio = rule->traffic_ratio_scaled;
    __u64 billed;
    if (ratio == 0) {
        ratio = PFWD_RATIO_SCALE;
    }
    billed = (bytes * ratio) / PFWD_RATIO_SCALE;
    if (rule->traffic_mode != 1) {
        billed *= 2;
    }
    counter = bpf_map_lookup_elem(&pfwd_rule_counters, &key);
    if (counter) {
        __sync_fetch_and_add(&counter->input_bytes, bytes);
        __sync_fetch_and_add(&counter->input_packets, packets);
        __sync_fetch_and_add(&counter->billing_bytes, billed);
    }
    key = rule->user_id;
    counter = bpf_map_lookup_elem(&pfwd_user_counters, &key);
    if (counter) {
        __sync_fetch_and_add(&counter->input_bytes, bytes);
        __sync_fetch_and_add(&counter->input_packets, packets);
        __sync_fetch_and_add(&counter->billing_bytes, billed);
    }
}

static __always_inline void count_output(const struct pfwd_conn_val *conn, __u64 bytes, __u64 packets) {
    struct pfwd_counter *counter;
    __u32 key = conn->rule_id;
    __u64 ratio = conn->traffic_ratio_scaled;
    __u64 billed;
    if (ratio == 0) {
        ratio = PFWD_RATIO_SCALE;
    }
    billed = (bytes * ratio) / PFWD_RATIO_SCALE;
    if (conn->traffic_mode != 1) {
        billed *= 2;
    }
    counter = bpf_map_lookup_elem(&pfwd_rule_counters, &key);
    if (counter) {
        __sync_fetch_and_add(&counter->output_bytes, bytes);
        __sync_fetch_and_add(&counter->output_packets, packets);
        __sync_fetch_and_add(&counter->billing_bytes, billed);
    }
    key = conn->user_id;
    counter = bpf_map_lookup_elem(&pfwd_user_counters, &key);
    if (counter) {
        __sync_fetch_and_add(&counter->output_bytes, bytes);
        __sync_fetch_and_add(&counter->output_packets, packets);
        __sync_fetch_and_add(&counter->billing_bytes, billed);
    }
}

static __always_inline void count_drop(const struct pfwd_rule_val *rule, __u64 bytes) {
    struct pfwd_counter *counter;
    __u32 key = rule->rule_id;
    counter = bpf_map_lookup_elem(&pfwd_rule_counters, &key);
    if (counter) {
        __sync_fetch_and_add(&counter->dropped_bytes, bytes);
        __sync_fetch_and_add(&counter->dropped_packets, 1);
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
    if (len >= 4 && payload[0] == 'G' && payload[1] == 'E' && payload[2] == 'T' && payload[3] == ' ') return 1;
    if (len >= 5 && payload[0] == 'P' && payload[1] == 'O' && payload[2] == 'S' && payload[3] == 'T' && payload[4] == ' ') return 1;
    if (len >= 5 && payload[0] == 'H' && payload[1] == 'E' && payload[2] == 'A' && payload[3] == 'D' && payload[4] == ' ') return 1;
    if (len >= 4 && payload[0] == 'P' && payload[1] == 'U' && payload[2] == 'T' && payload[3] == ' ') return 1;
    if (len >= 7 && payload[0] == 'D' && payload[1] == 'E' && payload[2] == 'L' && payload[3] == 'E' && payload[4] == 'T' && payload[5] == 'E' && payload[6] == ' ') return 1;
    if (len >= 8 && payload[0] == 'C' && payload[1] == 'O' && payload[2] == 'N' && payload[3] == 'N' && payload[4] == 'E' && payload[5] == 'C' && payload[6] == 'T' && payload[7] == ' ') return 1;
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

static __always_inline int flow_allowed(struct pfwd_flow_key *key) {
    __u8 *value = bpf_map_lookup_elem(&pfwd_allowed_flows, key);
    return value != 0;
}

static __always_inline void flow_store(struct pfwd_flow_key *key) {
    __u8 value = 1;
    bpf_map_update_elem(&pfwd_allowed_flows, key, &value, BPF_ANY);
}

static __always_inline int inspect_payload(struct __sk_buff *skb, __u32 offset, __u32 len, const struct pfwd_settings *settings) {
    __u8 payload[8];
    __u32 read_len = len >= 8 ? 8 : len;
    if (read_len < 3) {
        return TC_ACT_OK;
    }
    if (bpf_skb_load_bytes(skb, offset, payload, read_len) < 0) {
        stat_inc(PFWD_STAT_PARSE_SKIPPED);
        return TC_ACT_OK;
    }
    if (settings->block_http && match_http(payload, read_len)) {
        stat_inc(PFWD_STAT_PROTOCOL_DROPPED);
        return TC_ACT_SHOT;
    }
    if (settings->block_tls && match_tls_client_hello(payload, read_len)) {
        stat_inc(PFWD_STAT_PROTOCOL_DROPPED);
        return TC_ACT_SHOT;
    }
    if (settings->block_socks && match_socks(payload, read_len)) {
        stat_inc(PFWD_STAT_PROTOCOL_DROPPED);
        return TC_ACT_SHOT;
    }
    return TC_ACT_OK;
}

static __always_inline void adjust_tcp_mss(struct tcphdr_min *tcp, void *data_end, __u16 value) {
    __u8 *ptr = (__u8 *)(tcp + 1);
    __u8 *end = (__u8 *)tcp + ((__u32)(tcp->doff_res >> 4) * 4);
    if (value == 0 || (tcp->flags & 0x02) == 0) {
        return;
    }
    if ((void *)end > data_end) {
        return;
    }
#pragma unroll
    for (int i = 0; i < 6; i++) {
        if (ptr + 4 > end) {
            return;
        }
        __u8 kind = ptr[0];
        if (kind == 0) {
            return;
        }
        if (kind == 1) {
            ptr++;
            continue;
        }
        __u8 len = ptr[1];
        if (len < 2 || ptr + len > end) {
            return;
        }
        if (kind == 2 && len == 4) {
            __be16 *mss = (__be16 *)(ptr + 2);
            __be16 old = *mss;
            __be16 new_value = bpf_htons(value);
            if (bpf_ntohs(old) > value) {
                *mss = new_value;
                tcp->check = csum_replace16(tcp->check, old, new_value);
            }
            return;
        }
        ptr += len;
    }
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
        struct pfwd_rule_key rule_key = {};
        struct pfwd_rule_val *rule;
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

        rule_key.family = 4;
        rule_key.protocol = protocol;
        rule_key.listen_port = dport;
        copy_ipv4_to16(rule_key.listen_addr, ip4->daddr);
        rule = bpf_map_lookup_elem(&pfwd_rules, &rule_key);
        if (!rule) {
            zero_addr16(rule_key.listen_addr);
            rule = bpf_map_lookup_elem(&pfwd_rules, &rule_key);
        }
        if (rule) {
            __u32 scratch_key = 0;
            struct pfwd_scratch *scratch = bpf_map_lookup_elem(&pfwd_scratch, &scratch_key);
            struct pfwd_conn_val *existing_conn;
            __be32 old_saddr = ip4->saddr;
            __be32 old_daddr = ip4->daddr;
            __be16 old_sport = sport;
            __be16 old_dport = dport;
            __be32 new_saddr = rule->snat_mode == PFWD_SNAT_FIXED ? ipv4_from16(rule->snat_addr) : old_daddr;
            __be32 new_daddr = ipv4_from16(rule->target_addr);
            __be16 new_sport = sport;
            __be16 new_dport = rule->target_port;
            if (settings && settings->whitelist_enabled && !whitelist_match_v4(ip4->saddr)) {
                stat_inc(PFWD_STAT_WHITELIST_DROPPED);
                count_drop(rule, packet_len);
                return XDP_DROP;
            }
            if (traffic_over_limit(rule, packet_len, 0)) {
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
            } else {
                new_sport = allocate_source_port_v4(&scratch->reverse_key, sport, old_saddr, old_daddr, new_dport);
                if (new_sport == 0) {
                    stat_inc(PFWD_STAT_DROPPED);
                    count_drop(rule, packet_len);
                    return XDP_DROP;
                }
            }
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
            scratch->conn.packets = 1;
            scratch->conn.bytes = packet_len;
            bpf_map_update_elem(&pfwd_connections, &scratch->conn_key, &scratch->conn, BPF_ANY);
            scratch->reverse_key.source_port = new_sport;
            copy_ipv4_to16(scratch->reverse_key.source_addr, new_saddr);
            bpf_map_update_elem(&pfwd_reverse, &scratch->reverse_key, &scratch->conn, BPF_ANY);
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
            count_input(rule, packet_len, 1);
            stat_inc(PFWD_STAT_FORWARDED);
            return fib_redirect_v4(ctx, eth, ip4, protocol, new_sport, new_dport);
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
                count_output(conn, packet_len, 1);
                stat_inc(PFWD_STAT_FORWARDED);
                return fib_redirect_v4(ctx, eth, ip4, protocol, new_sport, new_dport);
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
        struct pfwd_rule_key rule_key = {};
        struct pfwd_rule_val *rule;
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
        rule_key.family = 6;
        rule_key.protocol = protocol;
        rule_key.listen_port = dport;
        pfwd_memcpy16(rule_key.listen_addr, ip6->daddr);
        rule = bpf_map_lookup_elem(&pfwd_rules, &rule_key);
        if (!rule) {
            zero_addr16(rule_key.listen_addr);
            rule = bpf_map_lookup_elem(&pfwd_rules, &rule_key);
        }
        if (rule) {
            __u32 scratch_key = 0;
            struct pfwd_scratch *scratch = bpf_map_lookup_elem(&pfwd_scratch, &scratch_key);
            struct pfwd_conn_val *existing_conn;
            __be16 new_sport = sport;
            if (settings && settings->whitelist_enabled && !whitelist_match_v6(ip6->saddr)) {
                stat_inc(PFWD_STAT_WHITELIST_DROPPED);
                count_drop(rule, packet_len);
                return XDP_DROP;
            }
            if (traffic_over_limit(rule, packet_len, 0)) {
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
            } else {
                new_sport = allocate_source_port_v6(&scratch->reverse_key, sport, scratch->addr_a, scratch->addr_b, rule->target_port);
                if (new_sport == 0) {
                    stat_inc(PFWD_STAT_DROPPED);
                    count_drop(rule, packet_len);
                    return XDP_DROP;
                }
            }
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
            bpf_map_update_elem(&pfwd_connections, &scratch->conn_key, &scratch->conn, BPF_ANY);
            scratch->reverse_key.source_port = new_sport;
            pfwd_memcpy16(scratch->reverse_key.source_addr, scratch->addr_c);
            bpf_map_update_elem(&pfwd_reverse, &scratch->reverse_key, &scratch->conn, BPF_ANY);
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
            count_input(rule, packet_len, 1);
            stat_inc(PFWD_STAT_FORWARDED);
            return fib_redirect_v6(ctx, eth, ip6, protocol, new_sport, rule->target_port);
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
                count_output(conn, packet_len, 1);
                stat_inc(PFWD_STAT_FORWARDED);
                return fib_redirect_v6(ctx, eth, ip6, protocol, new_sport, new_dport);
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
    struct ethhdr eth;
    __u32 settings_key = 0;
    struct pfwd_settings *settings = bpf_map_lookup_elem(&pfwd_settings, &settings_key);
    struct pfwd_flow_key flow = {};
    __u32 l4_offset = 0;
    __u32 payload_offset = 0;
    __u32 payload_len = 0;
    struct tcphdr_min tcp;

    if (!settings || (!settings->block_http && !settings->block_tls && !settings->block_socks)) {
        return TC_ACT_OK;
    }
    if (bpf_skb_load_bytes(skb, 0, &eth, sizeof(eth)) < 0) {
        stat_inc(PFWD_STAT_PARSE_SKIPPED);
        return TC_ACT_OK;
    }
    if (bpf_ntohs(eth.h_proto) == ETH_P_IP) {
        struct ipv4hdr_min ip4;
        __u32 ihl;
        if (bpf_skb_load_bytes(skb, ETH_HLEN, &ip4, sizeof(ip4)) < 0) {
            stat_inc(PFWD_STAT_PARSE_SKIPPED);
            return TC_ACT_OK;
        }
        if (ip4.protocol != IPPROTO_TCP) {
            return TC_ACT_OK;
        }
        ihl = (__u32)(ip4.version_ihl & 0x0f) * 4;
        if (ihl < sizeof(ip4)) {
            stat_inc(PFWD_STAT_PARSE_SKIPPED);
            return TC_ACT_OK;
        }
        flow.family = 4;
        flow.protocol = IPPROTO_TCP;
        copy_ipv4_to16(flow.saddr, ip4.saddr);
        copy_ipv4_to16(flow.daddr, ip4.daddr);
        l4_offset = ETH_HLEN + ihl;
    } else if (bpf_ntohs(eth.h_proto) == ETH_P_IPV6) {
        struct ipv6hdr_min ip6;
        if (bpf_skb_load_bytes(skb, ETH_HLEN, &ip6, sizeof(ip6)) < 0) {
            stat_inc(PFWD_STAT_PARSE_SKIPPED);
            return TC_ACT_OK;
        }
        if (ip6.nexthdr != IPPROTO_TCP) {
            return TC_ACT_OK;
        }
        flow.family = 6;
        flow.protocol = IPPROTO_TCP;
        pfwd_memcpy16(flow.saddr, ip6.saddr);
        pfwd_memcpy16(flow.daddr, ip6.daddr);
        l4_offset = ETH_HLEN + sizeof(ip6);
    } else {
        return TC_ACT_OK;
    }
    if (bpf_skb_load_bytes(skb, l4_offset, &tcp, sizeof(tcp)) < 0) {
        stat_inc(PFWD_STAT_PARSE_SKIPPED);
        return TC_ACT_OK;
    }
    flow.sport = tcp.source;
    flow.dport = tcp.dest;
    if (flow_allowed(&flow)) {
        return TC_ACT_OK;
    }
    payload_offset = l4_offset + ((__u32)(tcp.doff_res >> 4) * 4);
    if (payload_offset <= l4_offset || payload_offset >= skb->len) {
        return TC_ACT_OK;
    }
    payload_len = skb->len - payload_offset;
    if (inspect_payload(skb, payload_offset, payload_len, settings) == TC_ACT_SHOT) {
        return TC_ACT_SHOT;
    }
    if (payload_len > 0) {
        flow_store(&flow);
    }
    return TC_ACT_OK;
}
