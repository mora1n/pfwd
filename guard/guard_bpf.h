#ifndef PFWD_GUARD_BPF_H
#define PFWD_GUARD_BPF_H

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;
typedef __u16 __be16;
typedef __u32 __be32;

#define SEC(name) __attribute__((section(name), used))
#define __always_inline inline __attribute__((always_inline))
#define __uint(name, val) int (*name)[val]
#define __type(name, val) val *name

enum {
    BPF_MAP_TYPE_ARRAY = 2,
    BPF_MAP_TYPE_HASH = 1,
    BPF_MAP_TYPE_LPM_TRIE = 11,
};

enum {
    BPF_ANY = 0,
};

enum {
    BPF_F_NO_PREALLOC = 1,
};

enum {
    TC_ACT_OK = 0,
    TC_ACT_SHOT = 2,
};

#define IPPROTO_TCP 6
#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD
#define ETH_HLEN 14

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
    __u32 napi_id;
    __u32 family;
    __u32 remote_ip4;
    __u32 local_ip4;
    __u32 remote_ip6[4];
    __u32 local_ip6[4];
    __u32 remote_port;
    __u32 local_port;
    __u32 data_meta;
};

struct ethhdr {
    unsigned char h_dest[6];
    unsigned char h_source[6];
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

static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;
static long (*bpf_map_update_elem)(void *map, const void *key, const void *value, __u64 flags) = (void *)2;
static long (*bpf_skb_load_bytes)(const void *skb, __u32 offset, void *to, __u32 len) = (void *)26;

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
static __always_inline __u16 bpf_ntohs(__u16 value) {
    return __builtin_bswap16(value);
}

static __always_inline __u32 bpf_ntohl(__u32 value) {
    return __builtin_bswap32(value);
}
#else
static __always_inline __u16 bpf_ntohs(__u16 value) {
    return value;
}

static __always_inline __u32 bpf_ntohl(__u32 value) {
    return value;
}
#endif

#endif
