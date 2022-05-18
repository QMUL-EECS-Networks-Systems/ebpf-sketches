#include <uapi/linux/bpf.h>
#include <uapi/linux/filter.h>
#include <uapi/linux/icmp.h>
#include <uapi/linux/if_arp.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/if_packet.h>
#include <uapi/linux/in.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/pkt_cls.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/udp.h>
#include <uapi/linux/bpf.h>
#include <uapi/linux/types.h>
#include <stddef.h>

#include "common.h"

#if _HASH_NUM == 0
#include <linux/jhash.h> //already in linux
#elif _HASH_NUM == 1
#include "lookup3.h"
#elif _HASH_NUM == 2
#include "fasthash.h"
#elif _HASH_NUM == 3
#include "xxhash32.h"
#elif _HASH_NUM == 4
#include "csiphash.h"
#elif _HASH_NUM == 5
#include "xxhash32_danny.h"
#elif _HASH_NUM == 6
#include "murmurhash3.h"
#endif

BPF_PERCPU_ARRAY(dropcnt, long, 1);

static inline int parse_ipv4(void *data, u64 nh_off, void *data_end) {
    struct iphdr *iph = data + nh_off;

    if ((void*)&iph[1] > data_end)
        return 0;
    return iph->protocol;
}

struct pkt_ippair {
  __be32 src_ip;
  __be32 dst_ip;
} __attribute__((packed));

struct pkt_5tuple {
  volatile __be32 src_ip;
  __be32 dst_ip;
  __be16 src_port;
  __be16 dst_port;
  uint8_t proto;
} __attribute__((packed));

int xdp_prog1(struct xdp_md *ctx) {
#if _PARSE_PACKET == 1
    uint16_t h_proto;
    uint64_t nh_off = 0;
    
    void* data_end = (void*)(long)ctx->data_end;
    void* data = (void*)(long)ctx->data;
    
    struct ethhdr *eth = data;
    if (data + sizeof(*eth)  > data_end)
         goto DROP; 

    h_proto = eth->h_proto;

    if (h_proto != htons(ETH_P_IP))
         goto DROP; 
    
    struct iphdr *ip = data + sizeof(*eth);

    if ((void*)&ip[1] > data_end)
         goto DROP; 
    
    struct pkt_ippair ippair;
    struct pkt_5tuple pkt;
    
    ippair.src_ip=pkt.src_ip = ip->saddr;
    ippair.dst_ip=pkt.dst_ip = ip->daddr;
    pkt.proto = ip->protocol;
    
    switch (ip->protocol) {
        case IPPROTO_TCP: {
            struct tcphdr *tcp = NULL;
            tcp=data + sizeof(*eth) + sizeof(*ip);
            if (data + sizeof(*eth) + sizeof(*ip) + sizeof(*tcp) > data_end)
                goto DROP;               
            // bpf_trace_printk("Packet is TCP: src_port %u, dst_port %u", bpf_ntohs(tcp->source), bpf_ntohs(tcp->dest));
            pkt.src_port = tcp->source;
            pkt.dst_port = tcp->dest;
            break;
        }
        case IPPROTO_UDP: {
            struct udphdr *udp = NULL;
            udp=data + sizeof(*eth) + sizeof(*ip);
            if (data + sizeof(*eth) + sizeof(*ip) + sizeof(*udp) > data_end)
                goto DROP; 
            // bpf_trace_printk("Packet is UDP: src_port %u, dst_port %u", bpf_ntohs(udp->source), bpf_ntohs(udp->dest));
            pkt.src_port = udp->source;
            pkt.dst_port = udp->dest;
            break;
        }
        default:
            // bpf_trace_printk("Unknown L4 proto %d, dropping", ip->protocol);
            goto DROP;
    }
#else
    struct pkt_5tuple pkt;
    
    pkt.src_ip=1;
    pkt.dst_ip=2;
    pkt.src_port=3;
    pkt.dst_port=4;
    pkt.proto=6;
#endif
    
    const uint64_t N = _HASH_CYCLES;
    volatile uint32_t hashvalue = _HASH_START_VALUE;
#if _HASH_NUM == 0
// Using unroll the hash calculation is a LOT faster then with normal loop
// #pragma clang loop unroll(full)
    for(int i = 0; i < N; i++) {
        pkt.src_ip=hashvalue;
        hashvalue ^= jhash(&pkt, sizeof(pkt), i*i);
    }
#elif _HASH_NUM == 1
// #pragma clang loop unroll(full)
    for(int i = 0; i < N; i++) {
        pkt.src_ip=hashvalue;
        hashvalue ^= hashlittle(&pkt, sizeof(pkt), i*i);
    }
#elif _HASH_NUM == 2
// #pragma clang loop unroll(full)
    for(int i = 0; i < N; i++) {
        pkt.src_ip=hashvalue;
        hashvalue ^= fasthash32(&pkt, sizeof(pkt), i*i);
    }
#elif _HASH_NUM == 3
// #pragma clang loop unroll(full)
    for(int i = 0; i < N; i++) {
        pkt.src_ip=hashvalue;
        hashvalue ^= xxhash32(&pkt, sizeof(pkt), i*i);
    }
#elif _HASH_NUM == 4
// #pragma clang loop unroll(full)
    for(int i = 0; i < N; i++) {
        pkt.src_ip=hashvalue;
        unsigned char value[16] = {0};
        __builtin_memcpy(value, &i, sizeof(i));
        hashvalue ^= siphash24(&pkt, sizeof(pkt), value);
    }
#elif _HASH_NUM == 5
// #pragma clang loop unroll(full)
    for(int i = 0; i < N; i++) {
        pkt.src_ip=hashvalue;
        hashvalue ^= xxhash32(&pkt, sizeof(pkt), i*i);
    }
#elif _HASH_NUM == 6
// #pragma clang loop unroll(full)
    for(int i = 0; i < N; i++) {
        pkt.src_ip=hashvalue;
        hashvalue ^= MurmurHash3_x86_32(&pkt, sizeof(pkt), i*i);
    }
#endif

    if (hashvalue == 0x1234) {
        bpf_trace_printk("Error! This should never happen.");
        return XDP_DROP;
    }
    
    
    uint32_t zero = 0;
    long *value = dropcnt.lookup(&zero);
    if (value) NO_TEAR_INC(*value);

DROP:
    return XDP_DROP;
}

