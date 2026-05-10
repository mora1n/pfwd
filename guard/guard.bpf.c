#include "guard_bpf.h"

char __license[] SEC("license") = "Dual MIT/GPL";

enum stat_index {
    STAT_TOTAL = 0,
    STAT_WHITELIST_HIT = 1,
    STAT_HTTP_DROP = 2,
    STAT_TLS_DROP = 3,
    STAT_SOCKS_DROP = 4,
    STAT_PARSE_SKIP = 5,
    STAT_MAX = 6,
};

struct guard_settings {
    __u8 whitelist_enabled;
    __u8 block_http;
    __u8 block_tls;
    __u8 block_socks;
};

struct whitelist_key_v4 {
    __u32 prefixlen;
    __u32 addr;
};

struct whitelist_key_v6 {
    __u32 prefixlen;
    __u8 addr[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct guard_settings);
} guard_settings SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 65536);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct whitelist_key_v4);
    __type(value, __u8);
} guard_whitelist_v4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 65536);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct whitelist_key_v6);
    __type(value, __u8);
} guard_whitelist_v6 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u8);
} guard_allow_tcp_ports SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, STAT_MAX);
    __type(key, __u32);
    __type(value, __u64);
} guard_stats SEC(".maps");

static __always_inline void stat_inc(__u32 index) {
    __u64 *value;

    value = bpf_map_lookup_elem(&guard_stats, &index);
    if (value) {
        __sync_fetch_and_add(value, 1);
    }
}

static __always_inline int whitelist_match_v4(__be32 addr) {
    struct whitelist_key_v4 key = {
        .prefixlen = 32,
        .addr = addr,
    };
    __u8 *value;

    value = bpf_map_lookup_elem(&guard_whitelist_v4, &key);
    return value != 0;
}

static __always_inline int whitelist_match_v6(const __u8 addr[16]) {
    struct whitelist_key_v6 key = {
        .prefixlen = 128,
    };
    __u8 *value;
    int i;

#pragma unroll
    for (i = 0; i < 16; i++) {
        key.addr[i] = addr[i];
    }

    value = bpf_map_lookup_elem(&guard_whitelist_v6, &key);
    return value != 0;
}

static __always_inline int allow_port_match(__be16 port_be) {
    __u32 port = (__u32)bpf_ntohs(port_be);
    __u8 *value;

    value = bpf_map_lookup_elem(&guard_allow_tcp_ports, &port);
    return value != 0;
}

static __always_inline int match_http(const __u8 *payload, __u32 len) {
    if (len >= 4 && payload[0] == 'G' && payload[1] == 'E' && payload[2] == 'T' && payload[3] == ' ') {
        return 1;
    }
    if (len >= 5 && payload[0] == 'P' && payload[1] == 'O' && payload[2] == 'S' && payload[3] == 'T' && payload[4] == ' ') {
        return 1;
    }
    if (len >= 5 && payload[0] == 'H' && payload[1] == 'E' && payload[2] == 'A' && payload[3] == 'D' && payload[4] == ' ') {
        return 1;
    }
    if (len >= 4 && payload[0] == 'P' && payload[1] == 'U' && payload[2] == 'T' && payload[3] == ' ') {
        return 1;
    }
    if (len >= 7 && payload[0] == 'D' && payload[1] == 'E' && payload[2] == 'L' && payload[3] == 'E' && payload[4] == 'T' && payload[5] == 'E' && payload[6] == ' ') {
        return 1;
    }
    if (len >= 8 && payload[0] == 'O' && payload[1] == 'P' && payload[2] == 'T' && payload[3] == 'I' && payload[4] == 'O' && payload[5] == 'N' && payload[6] == 'S' && payload[7] == ' ') {
        return 1;
    }
    if (len >= 6 && payload[0] == 'P' && payload[1] == 'A' && payload[2] == 'T' && payload[3] == 'C' && payload[4] == 'H' && payload[5] == ' ') {
        return 1;
    }
    if (len >= 8 && payload[0] == 'C' && payload[1] == 'O' && payload[2] == 'N' && payload[3] == 'N' && payload[4] == 'E' && payload[5] == 'C' && payload[6] == 'T' && payload[7] == ' ') {
        return 1;
    }
    if (len >= 6 && payload[0] == 'T' && payload[1] == 'R' && payload[2] == 'A' && payload[3] == 'C' && payload[4] == 'E' && payload[5] == ' ') {
        return 1;
    }
    return 0;
}

static __always_inline int match_tls_client_hello(const __u8 *payload, __u32 len) {
    if (len < 6) {
        return 0;
    }
    if (payload[0] != 0x16) {
        return 0;
    }
    if (payload[1] != 0x03) {
        return 0;
    }
    if (payload[2] > 0x04) {
        return 0;
    }
    if (payload[5] != 0x01) {
        return 0;
    }
    return 1;
}

static __always_inline int match_socks(const __u8 *payload, __u32 len) {
    if (len >= 3 && payload[0] == 0x05 && payload[1] >= 0x01 && payload[1] <= 0x10) {
        return 1;
    }
    if (len >= 8 && payload[0] == 0x04 && (payload[1] == 0x01 || payload[1] == 0x02)) {
        return 1;
    }
    return 0;
}

static __always_inline int inspect_tcp_payload(struct __sk_buff *skb, __u32 payload_offset, __u32 payload_len, const struct guard_settings *settings) {
    __u8 payload[64];
    if (payload_len >= 8) {
        if (bpf_skb_load_bytes(skb, payload_offset, payload, 8) < 0) {
            stat_inc(STAT_PARSE_SKIP);
            return TC_ACT_OK;
        }
        if (settings->block_http && match_http(payload, 8)) {
            stat_inc(STAT_HTTP_DROP);
            return TC_ACT_SHOT;
        }
        if (settings->block_tls && match_tls_client_hello(payload, 8)) {
            stat_inc(STAT_TLS_DROP);
            return TC_ACT_SHOT;
        }
        if (settings->block_socks && match_socks(payload, 8)) {
            stat_inc(STAT_SOCKS_DROP);
            return TC_ACT_SHOT;
        }
        return TC_ACT_OK;
    }

    if (payload_len >= 6) {
        if (bpf_skb_load_bytes(skb, payload_offset, payload, 6) < 0) {
            stat_inc(STAT_PARSE_SKIP);
            return TC_ACT_OK;
        }
        if (settings->block_http && match_http(payload, 6)) {
            stat_inc(STAT_HTTP_DROP);
            return TC_ACT_SHOT;
        }
        if (settings->block_tls && match_tls_client_hello(payload, 6)) {
            stat_inc(STAT_TLS_DROP);
            return TC_ACT_SHOT;
        }
        if (settings->block_socks && match_socks(payload, 6)) {
            stat_inc(STAT_SOCKS_DROP);
            return TC_ACT_SHOT;
        }
        return TC_ACT_OK;
    }

    if (payload_len >= 5) {
        if (bpf_skb_load_bytes(skb, payload_offset, payload, 5) < 0) {
            stat_inc(STAT_PARSE_SKIP);
            return TC_ACT_OK;
        }
        if (settings->block_http && match_http(payload, 5)) {
            stat_inc(STAT_HTTP_DROP);
            return TC_ACT_SHOT;
        }
        if (settings->block_socks && match_socks(payload, 5)) {
            stat_inc(STAT_SOCKS_DROP);
            return TC_ACT_SHOT;
        }
        return TC_ACT_OK;
    }

    if (payload_len >= 4) {
        if (bpf_skb_load_bytes(skb, payload_offset, payload, 4) < 0) {
            stat_inc(STAT_PARSE_SKIP);
            return TC_ACT_OK;
        }
        if (settings->block_http && match_http(payload, 4)) {
            stat_inc(STAT_HTTP_DROP);
            return TC_ACT_SHOT;
        }
        return TC_ACT_OK;
    }

    if (payload_len >= 3) {
        if (bpf_skb_load_bytes(skb, payload_offset, payload, 3) < 0) {
            stat_inc(STAT_PARSE_SKIP);
            return TC_ACT_OK;
        }
        if (settings->block_socks && match_socks(payload, 3)) {
            stat_inc(STAT_SOCKS_DROP);
            return TC_ACT_SHOT;
        }
    }

    return TC_ACT_OK;
}

SEC("tc")
int ingress_guard(struct __sk_buff *skb) {
    __u32 settings_key = 0;
    struct guard_settings *settings;
    struct ethhdr eth;
    __u16 ether_type;
    __u32 l4_offset;
    __u32 payload_offset;
    __u32 payload_len;
    struct tcphdr_min tcp;

    stat_inc(STAT_TOTAL);

    settings = bpf_map_lookup_elem(&guard_settings, &settings_key);
    if (!settings) {
        return TC_ACT_OK;
    }

    if (bpf_skb_load_bytes(skb, 0, &eth, sizeof(eth)) < 0) {
        stat_inc(STAT_PARSE_SKIP);
        return TC_ACT_OK;
    }

    ether_type = bpf_ntohs(eth.h_proto);
    if (ether_type == ETH_P_IP) {
        struct ipv4hdr_min ip4;
        __u32 ip_header_len;

        if (bpf_skb_load_bytes(skb, ETH_HLEN, &ip4, sizeof(ip4)) < 0) {
            stat_inc(STAT_PARSE_SKIP);
            return TC_ACT_OK;
        }
        if (ip4.protocol != IPPROTO_TCP) {
            return TC_ACT_OK;
        }
        if (settings->whitelist_enabled && whitelist_match_v4(ip4.saddr)) {
            stat_inc(STAT_WHITELIST_HIT);
            return TC_ACT_OK;
        }
        ip_header_len = (__u32)(ip4.version_ihl & 0x0f) * 4;
        if (ip_header_len < sizeof(ip4)) {
            stat_inc(STAT_PARSE_SKIP);
            return TC_ACT_OK;
        }
        l4_offset = ETH_HLEN + ip_header_len;
    } else if (ether_type == ETH_P_IPV6) {
        struct ipv6hdr_min ip6;

        if (bpf_skb_load_bytes(skb, ETH_HLEN, &ip6, sizeof(ip6)) < 0) {
            stat_inc(STAT_PARSE_SKIP);
            return TC_ACT_OK;
        }
        if (ip6.nexthdr != IPPROTO_TCP) {
            return TC_ACT_OK;
        }
        if (settings->whitelist_enabled && whitelist_match_v6(ip6.saddr)) {
            stat_inc(STAT_WHITELIST_HIT);
            return TC_ACT_OK;
        }
        l4_offset = ETH_HLEN + sizeof(ip6);
    } else {
        return TC_ACT_OK;
    }

    if (bpf_skb_load_bytes(skb, l4_offset, &tcp, sizeof(tcp)) < 0) {
        stat_inc(STAT_PARSE_SKIP);
        return TC_ACT_OK;
    }

    if (!allow_port_match(tcp.dest)) {
        return TC_ACT_OK;
    }

    payload_offset = l4_offset + ((__u32)(tcp.doff_res >> 4) * 4);
    if (payload_offset <= l4_offset) {
        stat_inc(STAT_PARSE_SKIP);
        return TC_ACT_OK;
    }
    if (payload_offset >= skb->len) {
        return TC_ACT_OK;
    }

    payload_len = skb->len - payload_offset;
    return inspect_tcp_payload(skb, payload_offset, payload_len, settings);
}
