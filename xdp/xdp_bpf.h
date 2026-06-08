#ifndef PFWD_XDP_BPF_H
#define PFWD_XDP_BPF_H

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;
typedef signed int __s32;
typedef __u16 __be16;
typedef __u32 __be32;

#define SEC(name) __attribute__((section(name), used))
#define __always_inline inline __attribute__((always_inline))
#define __uint(name, val) int (*name)[val]
#define __type(name, val) val *name

enum {
    BPF_MAP_TYPE_HASH = 1,
    BPF_MAP_TYPE_ARRAY = 2,
    BPF_MAP_TYPE_PERF_EVENT_ARRAY = 4,
    BPF_MAP_TYPE_PERCPU_ARRAY = 6,
    BPF_MAP_TYPE_LRU_HASH = 9,
    BPF_MAP_TYPE_LPM_TRIE = 11,
};

enum {
    BPF_ANY = 0,
};

#define BPF_F_CURRENT_NETNS ((__u64)-1)

enum {
    BPF_F_NO_PREALLOC = 1,
};

enum {
    BPF_SK_LOOKUP_F_REPLACE = 1U << 0,
};

enum {
    BPF_F_INGRESS = 1U << 0,
};

enum {
    TC_ACT_OK = 0,
    TC_ACT_SHOT = 2,
    TC_ACT_REDIRECT = 7,
};

enum {
    SK_DROP = 0,
    SK_PASS = 1,
};

enum {
    XDP_ABORTED = 0,
    XDP_DROP = 1,
    XDP_PASS = 2,
    XDP_TX = 3,
    XDP_REDIRECT = 4,
};

#define AF_INET 2
#define AF_INET6 10
#define ETH_ALEN 6
#define ETH_HLEN 14
#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define PFWD_MAX_RULES 4096
#define PFWD_MAX_USERS 4096
#define PFWD_RATIO_SCALE 1000000ULL

#define BPF_FIB_LOOKUP_DIRECT (1U << 0)
#define BPF_FIB_LKUP_RET_SUCCESS 0

struct __sk_buff {
    __u32 len;
    __u32 pkt_type;
    __u32 mark;
    __u32 queue_mapping;
    __u32 protocol;
    __u32 vlan_present;
    __u32 vlan_tci;
    __u32 vlan_proto;
    __u32 priority;
    __u32 ingress_ifindex;
    __u32 ifindex;
    __u32 tc_index;
    __u32 cb[5];
    __u32 hash;
    __u32 tc_classid;
    __u32 data;
    __u32 data_end;
};

struct xdp_md {
    __u32 data;
    __u32 data_end;
    __u32 data_meta;
    __u32 ingress_ifindex;
    __u32 rx_queue_index;
    __u32 egress_ifindex;
};

struct bpf_sock;

struct bpf_sk_lookup {
    struct bpf_sock *sk;
    __u32 family;
    __u32 protocol;
    __u32 remote_ip4;
    __u32 remote_ip6[4];
    __be16 remote_port;
    __u16 pad0;
    __u32 local_ip4;
    __u32 local_ip6[4];
    __u32 local_port;
    __u32 ingress_ifindex;
};

struct ethhdr {
    __u8 h_dest[ETH_ALEN];
    __u8 h_source[ETH_ALEN];
    __be16 h_proto;
};

struct ipv4hdr_min {
    __u8 version_ihl;
    __u8 tos;
    __be16 tot_len;
    __be16 id;
    __be16 frag_off;
    __u8 ttl;
    __u8 protocol;
    __be16 check;
    __be32 saddr;
    __be32 daddr;
};

struct ipv6hdr_min {
    __u32 ver_tc_flow;
    __be16 payload_len;
    __u8 nexthdr;
    __u8 hop_limit;
    __u8 saddr[16];
    __u8 daddr[16];
};

struct tcphdr_min {
    __be16 source;
    __be16 dest;
    __u32 seq;
    __u32 ack_seq;
    __u8 doff_res;
    __u8 flags;
    __be16 window;
    __be16 check;
    __be16 urg_ptr;
};

struct udphdr_min {
    __be16 source;
    __be16 dest;
    __be16 len;
    __be16 check;
};

struct bpf_fib_lookup {
    __u8 family;
    __u8 l4_protocol;
    __be16 sport;
    __be16 dport;
    union {
        __u16 tot_len;
        __u16 mtu_result;
    };
    __u32 ifindex;
    union {
        __u8 tos;
        __u32 flowinfo;
        __u32 rt_metric;
    };
    union {
        __be32 ipv4_src;
        __u32 ipv6_src[4];
    };
    union {
        __be32 ipv4_dst;
        __u32 ipv6_dst[4];
    };
    __be16 h_vlan_proto;
    __be16 h_vlan_TCI;
    __u8 smac[ETH_ALEN];
    __u8 dmac[ETH_ALEN];
};

struct bpf_sock_tuple {
    union {
        struct {
            __be32 saddr;
            __be32 daddr;
            __be16 sport;
            __be16 dport;
        } ipv4;
        struct {
            __be32 saddr[4];
            __be32 daddr[4];
            __be16 sport;
            __be16 dport;
        } ipv6;
    };
};

static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;
static long (*bpf_map_update_elem)(void *map, const void *key, const void *value, __u64 flags) = (void *)2;
static long (*bpf_map_delete_elem)(void *map, const void *key) = (void *)3;
static long (*bpf_probe_read_kernel)(void *dst, __u32 size, const void *unsafe_ptr) = (void *)113;
static long (*bpf_skb_load_bytes)(const void *skb, __u32 offset, void *to, __u32 len) = (void *)26;
static long (*bpf_skb_pull_data)(struct __sk_buff *skb, __u32 len) = (void *)39;
static long (*bpf_fib_lookup)(void *ctx, struct bpf_fib_lookup *params, int plen, __u32 flags) = (void *)69;
static long (*bpf_redirect)(__u32 ifindex, __u64 flags) = (void *)23;
static long (*bpf_redirect_neigh)(__u32 ifindex, void *params, int plen, __u64 flags) = (void *)152;
static struct bpf_sock *(*bpf_sk_lookup_tcp)(void *ctx, struct bpf_sock_tuple *tuple, __u32 tuple_size, __u64 netns, __u64 flags) = (void *)84;
static struct bpf_sock *(*bpf_sk_lookup_udp)(void *ctx, struct bpf_sock_tuple *tuple, __u32 tuple_size, __u64 netns, __u64 flags) = (void *)85;
static long (*bpf_sk_release)(void *sock) = (void *)86;
static long (*bpf_sk_assign)(void *ctx, void *sk, __u64 flags) = (void *)124;
static __u64 (*bpf_ktime_get_ns)(void) = (void *)5;

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
static __always_inline __u16 bpf_ntohs(__u16 value) { return __builtin_bswap16(value); }
static __always_inline __u16 bpf_htons(__u16 value) { return __builtin_bswap16(value); }
static __always_inline __u32 bpf_ntohl(__u32 value) { return __builtin_bswap32(value); }
static __always_inline __u32 bpf_htonl(__u32 value) { return __builtin_bswap32(value); }
#else
static __always_inline __u16 bpf_ntohs(__u16 value) { return value; }
static __always_inline __u16 bpf_htons(__u16 value) { return value; }
static __always_inline __u32 bpf_ntohl(__u32 value) { return value; }
static __always_inline __u32 bpf_htonl(__u32 value) { return value; }
#endif

static __always_inline void pfwd_memcpy6(__u8 dst[ETH_ALEN], const __u8 src[ETH_ALEN]) {
    int i;
#pragma unroll
    for (i = 0; i < ETH_ALEN; i++) {
        dst[i] = src[i];
    }
}

static __always_inline void pfwd_memcpy16(__u8 dst[16], const __u8 src[16]) {
    int i;
#pragma unroll
    for (i = 0; i < 16; i++) {
        dst[i] = src[i];
    }
}

static __always_inline __u16 csum_fold(__u32 csum) {
    csum = (csum & 0xffff) + (csum >> 16);
    csum = (csum & 0xffff) + (csum >> 16);
    return (__u16)~csum;
}

static __always_inline __u32 csum_unfold(__u16 csum) {
    return (__u32)~csum & 0xffff;
}

static __always_inline __u16 csum_replace16(__u16 csum, __u16 old, __u16 new_value) {
    __u32 sum = csum_unfold(csum);
    sum += (__u32)~old & 0xffff;
    sum += (__u32)new_value;
    return csum_fold(sum);
}

static __always_inline __u16 csum_replace32(__u16 csum, __u32 old, __u32 new_value) {
    __u32 sum = csum_unfold(csum);
    sum += (__u32)~(old >> 16) & 0xffff;
    sum += (__u32)~old & 0xffff;
    sum += new_value >> 16;
    sum += new_value & 0xffff;
    return csum_fold(sum);
}

#endif
