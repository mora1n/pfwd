//go:build ignore

#include "xdp_bpf.h"

char __license[] SEC("license") = "Dual MIT/GPL";

enum pfwd_stat_index {
    PFWD_STAT_PASSED = 0,
    PFWD_STAT_DROPPED = 1,
    PFWD_STAT_FORWARDED = 2,
    PFWD_STAT_QUOTA_DROPPED = 3,
    PFWD_STAT_PARSE_SKIPPED = 4,
    PFWD_STAT_TCP_PREWARMED = 5,
    PFWD_STAT_TCP_ESTABLISHED = 6,
    PFWD_STAT_MAX = 7,
};

enum pfwd_rule_flags {
    PFWD_RULE_F_XDP_DISABLED = 1U << 0,
    PFWD_RULE_F_NEEDS_COUNTER = 1U << 1,
    PFWD_RULE_F_NEEDS_QUOTA = 1U << 2,
    PFWD_RULE_F_SNAT_FIXED = 1U << 3,
    PFWD_RULE_F_MSS_ENABLED = 1U << 4,
};

enum pfwd_conn_state {
    PFWD_CONN_STATE_NONE = 0,
    PFWD_CONN_STATE_TCP_SYN_PENDING = 1,
    PFWD_CONN_STATE_TCP_ESTABLISHED = 2,
};

struct pfwd_settings {
    __u32 external_ifindex;
    __u32 pad[3];
};

struct pfwd_rule_key {
    __u8 family;
    __u8 protocol;
    __u16 listen_port;
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
    __u8 pad_rule[4];
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
    __u64 last_seen_ns;
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

static __always_inline int rule_xdp_disabled(const struct pfwd_rule_val *rule) {
    return rule && (rule->flags & PFWD_RULE_F_XDP_DISABLED);
}

static __always_inline int rule_snat_fixed(const struct pfwd_rule_val *rule) {
    return rule && (rule->flags & PFWD_RULE_F_SNAT_FIXED);
}

static __always_inline int rule_mss_enabled(const struct pfwd_rule_val *rule) {
    return rule && (rule->flags & PFWD_RULE_F_MSS_ENABLED);
}

static __always_inline void set_ipv4_in16(__u8 dst[16], __be32 addr) {
    *(__be32 *)&dst[0] = addr;
    *(__u32 *)&dst[4] = 0;
    *(__u32 *)&dst[8] = 0;
    *(__u32 *)&dst[12] = 0;
}

static __always_inline __be32 ipv4_from16(const __u8 addr[16]) {
    return *(const __be32 *)addr;
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

static __always_inline int tcp_syn_only(const struct tcphdr_min *tcp) {
    __u8 flags;

    if (!tcp) {
        return 0;
    }
    flags = tcp->flags;
    return (flags & 0x02) && !(flags & 0x15);
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

static __always_inline __u16 csum_replace_addr16(__u16 csum, const __u8 old_addr[16], const __u8 new_addr[16]) {
    const __u32 *old32 = (const __u32 *)old_addr;
    const __u32 *new32 = (const __u32 *)new_addr;
#pragma unroll
    for (int i = 0; i < 4; i++) {
        csum = csum_replace32(csum, old32[i], new32[i]);
    }
    return csum;
}

static __always_inline void adjust_tcp_mss(struct tcphdr_min *tcp, void *data_end, __u16 value) {
    __u8 *opt = (void *)(tcp + 1);
    __u32 tcp_len = ((__u32)(tcp->doff_res >> 4)) * 4;
    __u32 opt_len;

    if (value == 0 || tcp_len <= sizeof(*tcp)) {
        return;
    }
    opt_len = tcp_len - sizeof(*tcp);
#pragma unroll
    for (int i = 0; i < 40; i++) {
        __u8 kind;
        __u8 len;
        __u16 old;
        __be16 new_value;
        if ((__u32)i >= opt_len || opt + 1 > (__u8 *)data_end) {
            break;
        }
        kind = *opt;
        if (kind == 0) {
            break;
        }
        if (kind == 1) {
            opt++;
            continue;
        }
        if (opt + 2 > (__u8 *)data_end) {
            break;
        }
        len = *(opt + 1);
        if (len < 2 || (__u32)i + len > opt_len) {
            break;
        }
        if (kind == 2 && len == 4 && opt + 4 <= (__u8 *)data_end) {
            old = *(__u16 *)(opt + 2);
            new_value = bpf_htons(value);
            if (old != new_value) {
                *(__u16 *)(opt + 2) = new_value;
                tcp->check = csum_replace16(tcp->check, old, new_value);
            }
            break;
        }
        opt += len;
    }
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
    } else {
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
    } else {
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

static __always_inline __u64 reply_counter_billing_total(struct pfwd_reply_counter *counter) {
    if (!counter) {
        return 0;
    }
    return counter->billing_bytes;
}

static __always_inline void init_counter_plan(const struct pfwd_rule_val *rule, struct pfwd_counter_plan *plan) {
    plan->rule_counter = 0;
    plan->user_counter = 0;
    plan->billed = 0;
    plan->flags = rule ? rule->flags : 0;
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
    __u32 rule_id;
    __u32 user_id;

    if (!(counter_plan_needs_counter(plan) || counter_plan_needs_quota(plan))) {
        return;
    }
    rule_id = rule->rule_id;
    user_id = rule->user_id;
    plan->billed = billed_delta_for_rule(rule, input_delta, 0);
    if (rule->rule_limit_bytes > 0 || rule->billing_enabled) {
        plan->rule_counter = bpf_map_lookup_elem(&pfwd_rule_counters, &rule_id);
    }
    if (rule->user_limit_enabled) {
        plan->user_counter = bpf_map_lookup_elem(&pfwd_user_counters, &user_id);
    }
}

static __always_inline int counter_plan_over_limit(const struct pfwd_rule_val *rule, const struct pfwd_counter_plan *plan) {
    struct pfwd_reply_counter *reply_counter;
    __u64 current_rule;
    __u64 current_user;

    if (!counter_plan_needs_quota(plan)) {
        return 0;
    }
    if (rule->rule_limit_bytes > 0) {
        __u32 rule_id = rule->rule_id;
        reply_counter = bpf_map_lookup_elem(&pfwd_rule_reply_counters, &rule_id);
        current_rule = rule->rule_billing_used_base_bytes;
        if (plan->rule_counter) {
            current_rule += plan->rule_counter->billing_bytes;
        }
        current_rule += reply_counter_billing_total(reply_counter);
        if (current_rule + plan->billed > rule->rule_limit_bytes) {
            return 1;
        }
    }
    if (rule->user_limit_bytes > 0) {
        current_user = rule->user_billing_used_base_bytes;
        if (plan->user_counter) {
            current_user += plan->user_counter->billing_bytes;
        }
        if (current_user + plan->billed > rule->user_limit_bytes) {
            return 1;
        }
    }
    return 0;
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
    if (plan->rule_counter) {
        plan->rule_counter->input_bytes += bytes;
        plan->rule_counter->input_packets += packets;
        if (rule->billing_enabled) {
            plan->rule_counter->billing_bytes += plan->billed;
        }
    }
    if (rule->user_limit_enabled && plan->user_counter && rule->billing_enabled) {
        plan->user_counter->billing_bytes += plan->billed;
    }
}

static __always_inline void count_output(struct pfwd_conn_val *conn, __u64 bytes, __u64 packets) {
    struct pfwd_reply_counter *reply_counter;
    struct pfwd_user_counter *user_counter;
    __u32 key = conn->rule_id;
    __u64 billed = 0;

    conn->last_seen_ns = bpf_ktime_get_ns();
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

static __always_inline void count_drop(const struct pfwd_rule_val *rule, __u64 bytes) {
    struct pfwd_drop_counter *counter;
    __u32 key = rule->rule_id;

    counter = bpf_map_lookup_elem(&pfwd_rule_drop_counters, &key);
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

static __always_inline struct pfwd_rule_val *lookup_forward_rule(__u8 family, __u8 protocol, __be16 dport) {
    struct pfwd_rule_key key = {
        .family = family,
        .protocol = protocol,
        .listen_port = dport,
    };
    return bpf_map_lookup_elem(&pfwd_rules, &key);
}

static __always_inline struct pfwd_rule_val *lookup_forward_rule_v4(__u8 protocol, __be16 dport) {
    return lookup_forward_rule(4, protocol, dport);
}

static __always_inline void record_new_tcp_state(struct pfwd_conn_val *conn, __u8 state) {
    if (!conn) {
        return;
    }
    conn->state = state;
    conn->last_seen_ns = bpf_ktime_get_ns();
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
    conn->last_seen_ns = bpf_ktime_get_ns();
}

static __always_inline int forward_v4(
    struct xdp_md *ctx,
    struct ethhdr *eth,
    struct ipv4hdr_min *ip4,
    __u32 ihl,
    __u8 protocol,
    __be16 sport,
    __be16 dport,
    struct pfwd_rule_val *rule,
    __u64 packet_len,
    void *data_end
) {
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
    __u8 tcp_conn_state = PFWD_CONN_STATE_NONE;

    if (rule_xdp_disabled(rule) || rule_target_is_loopback(4, rule)) {
        stat_inc(PFWD_STAT_PASSED);
        return XDP_PASS;
    }
    if (protocol == IPPROTO_TCP) {
        struct tcphdr_min *tcp = (void *)ip4 + ihl;
        __u32 tcp_len;
        if ((void *)(tcp + 1) > data_end) {
            stat_inc(PFWD_STAT_PARSE_SKIPPED);
            return XDP_PASS;
        }
        tcp_len = (__u32)(tcp->doff_res >> 4) * 4;
        if (tcp_len < sizeof(*tcp) || (void *)tcp + tcp_len > data_end) {
            stat_inc(PFWD_STAT_PARSE_SKIPPED);
            return XDP_PASS;
        }
        tcp_conn_state = tcp_syn_only(tcp) ? PFWD_CONN_STATE_TCP_SYN_PENDING : PFWD_CONN_STATE_TCP_ESTABLISHED;
    }
    init_counter_plan(rule, &counters);
    if (counter_plan_needs_counter(&counters) || counter_plan_needs_quota(&counters)) {
        load_input_counter_plan(rule, packet_len, &counters);
        if (counter_plan_over_limit(rule, &counters)) {
            stat_inc(PFWD_STAT_QUOTA_DROPPED);
            count_drop(rule, packet_len);
            return XDP_DROP;
        }
    }
    fill_conn_key_v4(&conn_key, protocol, old_saddr, old_daddr, sport, dport, rule->target_port, rule->target_addr);
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
            count_drop(rule, packet_len);
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
            count_drop(rule, packet_len);
            return action;
        }
        count_input_with_plan(rule, packet_len, 1, &counters);
        stat_inc(PFWD_STAT_FORWARDED);
        return action;
    }
}

static __always_inline int reply_v4(
    struct xdp_md *ctx,
    struct ethhdr *eth,
    struct ipv4hdr_min *ip4,
    __u32 ihl,
    __u8 protocol,
    __be16 sport,
    __be16 dport,
    __u64 packet_len
) {
    struct pfwd_reverse_key reverse_key;
    struct pfwd_conn_val *conn;
    __be32 old_saddr = ip4->saddr;
    __be32 old_daddr = ip4->daddr;

    fill_reverse_lookup_key_v4(&reverse_key, protocol, ip4->daddr, ip4->saddr, dport, sport);
    conn = bpf_map_lookup_elem(&pfwd_reverse, &reverse_key);
    if (!conn) {
        return XDP_PASS;
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

static __always_inline int forward_v6(
    struct xdp_md *ctx,
    struct ethhdr *eth,
    struct ipv6hdr_min *ip6,
    __u8 protocol,
    __be16 sport,
    __be16 dport,
    struct pfwd_rule_val *rule,
    __u64 packet_len,
    void *data_end
) {
    struct pfwd_conn_val *existing_conn = 0;
    struct pfwd_counter_plan counters = {};
    const __u8 *new_saddr;
    __be16 new_sport = sport;
    struct pfwd_conn_key conn_key;
    __u8 tcp_conn_state = PFWD_CONN_STATE_NONE;

    if (rule_xdp_disabled(rule) || rule_target_is_loopback(6, rule)) {
        stat_inc(PFWD_STAT_PASSED);
        return XDP_PASS;
    }
    if (protocol == IPPROTO_TCP) {
        struct tcphdr_min *tcp = (void *)(ip6 + 1);
        __u32 tcp_len;
        if ((void *)(tcp + 1) > data_end) {
            stat_inc(PFWD_STAT_PARSE_SKIPPED);
            return XDP_PASS;
        }
        tcp_len = (__u32)(tcp->doff_res >> 4) * 4;
        if (tcp_len < sizeof(*tcp) || (void *)tcp + tcp_len > data_end) {
            stat_inc(PFWD_STAT_PARSE_SKIPPED);
            return XDP_PASS;
        }
        tcp_conn_state = tcp_syn_only(tcp) ? PFWD_CONN_STATE_TCP_SYN_PENDING : PFWD_CONN_STATE_TCP_ESTABLISHED;
    }
    init_counter_plan(rule, &counters);
    if (counter_plan_needs_counter(&counters) || counter_plan_needs_quota(&counters)) {
        load_input_counter_plan(rule, packet_len, &counters);
        if (counter_plan_over_limit(rule, &counters)) {
            stat_inc(PFWD_STAT_QUOTA_DROPPED);
            count_drop(rule, packet_len);
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
        if (!scratch) {
            stat_inc(PFWD_STAT_DROPPED);
            return XDP_DROP;
        }
        __builtin_memset(&scratch->conn, 0, sizeof(scratch->conn));
        new_saddr = rule_snat_fixed(rule) ? rule->snat_addr : ip6->daddr;
        init_reverse_alloc_key_v6(&scratch->reverse_key, protocol, rule->target_port, new_saddr, rule->target_addr);
        new_sport = allocate_source_port_v6(&scratch->reverse_key, sport, ip6->saddr, ip6->daddr, rule->target_port);
        if (new_sport == 0) {
            stat_inc(PFWD_STAT_DROPPED);
            count_drop(rule, packet_len);
            return XDP_DROP;
        }
        scratch->conn.rule_id = rule->rule_id;
        scratch->conn.user_id = rule->user_id;
        pfwd_memcpy16(scratch->conn.client_addr, ip6->saddr);
        pfwd_memcpy16(scratch->conn.listen_addr, ip6->daddr);
        pfwd_memcpy16(scratch->conn.source_addr, new_saddr);
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
            count_drop(rule, packet_len);
            return action;
        }
        count_input_with_plan(rule, packet_len, 1, &counters);
        stat_inc(PFWD_STAT_FORWARDED);
        return action;
    }
}

static __always_inline int reply_v6(
    struct xdp_md *ctx,
    struct ethhdr *eth,
    struct ipv6hdr_min *ip6,
    __u8 protocol,
    __be16 sport,
    __be16 dport,
    __u64 packet_len
) {
    struct pfwd_reverse_key reverse_key;
    struct pfwd_conn_val *conn;
    __u8 old_saddr[16];
    __u8 old_daddr[16];

    fill_reverse_lookup_key_v6(&reverse_key, protocol, ip6->daddr, ip6->saddr, dport, sport);
    conn = bpf_map_lookup_elem(&pfwd_reverse, &reverse_key);
    if (!conn) {
        return XDP_PASS;
    }
    if (protocol == IPPROTO_TCP) {
        mark_tcp_established(conn);
    }
    pfwd_memcpy16(old_saddr, ip6->saddr);
    pfwd_memcpy16(old_daddr, ip6->daddr);
    rewrite_l4_reply_v6(
        ip6, protocol,
        old_saddr, old_daddr,
        conn->listen_addr, conn->client_addr,
        sport, dport,
        conn->listen_port, conn->source_port
    );
    {
        int action = fib_redirect_v6(ctx, eth, ip6, protocol, conn->listen_port, conn->source_port);
        if (action == XDP_DROP) {
            return action;
        }
        count_output(conn, packet_len, 1);
        stat_inc(PFWD_STAT_FORWARDED);
        return action;
    }
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
        int reply_action;

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
        if (ihl < sizeof(*ip4) || (void *)ip4 + ihl > data_end) {
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
        rule = lookup_forward_rule_v4(protocol, dport);
        if (rule) {
            return forward_v4(ctx, eth, ip4, ihl, protocol, sport, dport, rule, packet_len, data_end);
        }
        reply_action = reply_v4(ctx, eth, ip4, ihl, protocol, sport, dport, packet_len);
        if (reply_action != XDP_PASS) {
            return reply_action;
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
        int reply_action;

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
        rule = lookup_forward_rule(6, protocol, dport);
        if (rule) {
            return forward_v6(ctx, eth, ip6, protocol, sport, dport, rule, packet_len, data_end);
        }
        reply_action = reply_v6(ctx, eth, ip6, protocol, sport, dport, packet_len);
        if (reply_action != XDP_PASS) {
            return reply_action;
        }
        stat_inc(PFWD_STAT_PASSED);
        return XDP_PASS;
    }

    stat_inc(PFWD_STAT_PASSED);
    return XDP_PASS;
}
