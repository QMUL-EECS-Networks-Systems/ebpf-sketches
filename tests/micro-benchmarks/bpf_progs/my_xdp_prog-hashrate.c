
#define MAPTYPE "percpu_array" 
		//array
//#define MAPTYPE array

#include <uapi/linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/udp.h>

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

BPF_TABLE( MAPTYPE, uint32_t, long, dropcnt, 256);

static inline int parse_ipv4(void *data, u64 nh_off, void *data_end) {
    struct iphdr *iph = data + nh_off;

    if ((void*)&iph[1] > data_end)
        return 0;
    return iph->protocol;
}

static inline int parse_ipv6(void *data, u64 nh_off, void *data_end) {
    struct ipv6hdr *ip6h = data + nh_off;

    if ((void*)&ip6h[1] > data_end)
        return 0;
    return ip6h->nexthdr;
}

struct pkt_ippair {
  __be32 src_ip;
  __be32 dst_ip;
} __attribute__((packed));

struct pkt_5tuple {
  __be32 src_ip;
  __be32 dst_ip;
  __be16 src_port;
  __be16 dst_port;
  uint8_t proto;
} __attribute__((packed));


int xdp_prog1(struct xdp_md *ctx) {
    // drop packets
    //int rc = XDP_DROP; // let pass XDP_PASS or redirect to tx via XDP_TX
    long *value;
    uint16_t h_proto;
    uint64_t nh_off = 0;
    uint32_t index;

    
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
        
#if _HASH_NUM == 0
    uint32_t hashvalue = 0;
    #if _NUM_HASHES > 0
        hashvalue ^= jhash(&pkt, sizeof(pkt), 0x12344321);
    #endif

    #if _NUM_HASHES > 1
        hashvalue ^= jhash(&pkt, sizeof(pkt), 0x32245892);
    #endif

    #if _NUM_HASHES > 2
        hashvalue ^= jhash(&pkt, sizeof(pkt), 0x98765432);
    #endif

    #if _NUM_HASHES > 3
        hashvalue ^= jhash(&pkt, sizeof(pkt), 0x65432109);
    #endif

    #if _NUM_HASHES > 4
        hashvalue ^= jhash(&pkt, sizeof(pkt), 0x6a5d1f0e);
    #endif
#elif _HASH_NUM == 1
    uint32_t hashvalue = 0;
    #if _NUM_HASHES > 0
        hashvalue ^= hashlittle(&pkt, sizeof(pkt), 0x12344321);
    #endif

    #if _NUM_HASHES > 1
        hashvalue ^= hashlittle(&pkt, sizeof(pkt), 0x32245892);
    #endif

    #if _NUM_HASHES > 2
        hashvalue ^= hashlittle(&pkt, sizeof(pkt), 0x98765432);
    #endif

    #if _NUM_HASHES > 3
        hashvalue ^= hashlittle(&pkt, sizeof(pkt), 0x65432109);
    #endif

    #if _NUM_HASHES > 4
        hashvalue ^= hashlittle(&pkt, sizeof(pkt), 0x6a5d1f0e);
    #endif
#elif _HASH_NUM == 2
    uint32_t hashvalue = 0;
    #if _NUM_HASHES > 0
        hashvalue ^= fasthash32(&pkt, sizeof(pkt), 0x12344521);
    #endif

    #if _NUM_HASHES > 1
        hashvalue ^= fasthash32(&pkt, sizeof(pkt), 0x22344392);
    #endif

    #if _NUM_HASHES > 2
        hashvalue ^= fasthash32(&pkt, sizeof(pkt), 0x92344399);
    #endif

    #if _NUM_HASHES > 3
        hashvalue ^= fasthash32(&pkt, sizeof(pkt), 0x89234314);
    #endif

    #if _NUM_HASHES > 4
        hashvalue ^= fasthash32(&pkt, sizeof(pkt), 0x6a5d1f0e);
    #endif
#elif _HASH_NUM == 3
    uint32_t hashvalue = 0;
    #if _NUM_HASHES > 0
        hashvalue ^= xxhash32(&pkt, sizeof(pkt), 0x12344321);
    #endif

    #if _NUM_HASHES > 1
        hashvalue ^= xxhash32(&pkt, sizeof(pkt), 0x22344323);
    #endif

    #if _NUM_HASHES > 2
        hashvalue ^= xxhash32(&pkt, sizeof(pkt), 0x92344139);
    #endif

    #if _NUM_HASHES > 3
        hashvalue ^= xxhash32(&pkt, sizeof(pkt), 0x78234321);
    #endif

    #if _NUM_HASHES > 4
        hashvalue ^= xxhash32(&pkt, sizeof(pkt), 0x6a5d1f0e);
    #endif
#elif _HASH_NUM == 4
    uint64_t hashvalue = 0;
    #if _NUM_HASHES > 0
        hashvalue ^= siphash24(&pkt, sizeof(pkt), "deadbeeflonglong");
    #endif

    #if _NUM_HASHES > 1
        hashvalue ^= siphash24(&pkt, sizeof(pkt), "bbadbeeflongkkkk");
    #endif

    #if _NUM_HASHES > 2
        hashvalue ^= siphash24(&pkt, sizeof(pkt), "ffffbeefaaaakkkk");
    #endif

    #if _NUM_HASHES > 3
        hashvalue ^= siphash24(&pkt, sizeof(pkt), "bbadggggzzxxyyee");
    #endif

    #if _NUM_HASHES > 4
        hashvalue ^= siphash24(&pkt, sizeof(pkt), "jkevfvhfbuhfdvhh");
    #endif
#elif _HASH_NUM == 5
    uint32_t hashvalue = 0;
    #if _NUM_HASHES > 0
        hashvalue ^= xxhash32(&pkt, sizeof(pkt), 0x12344321);
    #endif

    #if _NUM_HASHES > 1
        hashvalue ^= xxhash32(&pkt, sizeof(pkt), 0x22344323);
    #endif

    #if _NUM_HASHES > 2
        hashvalue ^= xxhash32(&pkt, sizeof(pkt), 0x92344139);
    #endif

    #if _NUM_HASHES > 3
        hashvalue ^= xxhash32(&pkt, sizeof(pkt), 0x78234321);
    #endif

    #if _NUM_HASHES > 4
        hashvalue ^= xxhash32(&pkt, sizeof(pkt), 0x6a5d1f0e);
    #endif
#elif _HASH_NUM == 6
    uint32_t hashvalue = 0;
    #if _NUM_HASHES > 0
        hashvalue ^= MurmurHash3_x86_32(&pkt, sizeof(pkt), 0x12344321);
    #endif

    #if _NUM_HASHES > 1
        hashvalue ^= MurmurHash3_x86_32(&pkt, sizeof(pkt), 0x22344323);
    #endif

    #if _NUM_HASHES > 2
        hashvalue ^= MurmurHash3_x86_32(&pkt, sizeof(pkt), 0x92344139);
    #endif

    #if _NUM_HASHES > 3
        hashvalue ^= MurmurHash3_x86_32(&pkt, sizeof(pkt), 0x78234321);
    #endif

    #if _NUM_HASHES > 4
        hashvalue ^= MurmurHash3_x86_32(&pkt, sizeof(pkt), 0x6a5d1f0e);
    #endif
#endif

    if(hashvalue==0x1234)
        return XDP_DROP;
    
    
    index = ip->protocol;
    value = dropcnt.lookup(&index);
    if (value)
        __sync_fetch_and_add(value, 1);

    DROP:
    return XDP_DROP;
}

