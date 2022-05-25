

#include <uapi/linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/udp.h>

#include "common.h"


//array
#define MAPTYPE array
// percpu_array or array

BPF_PERCPU_ARRAY(dropcnt, long, 1);

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
    
    volatile __u32 rndval = 0;
    __u32 atom;

    const uint64_t N = _RAND_CYCLES;

    for (int i = 0; i < N; i++) {
        atom=bpf_get_prandom_u32();
        rndval^=atom;
    }

    if(rndval==0x1234) return XDP_DROP;
   
    uint32_t zero = 0;
    long *value = dropcnt.lookup(&zero);
    if (value) NO_TEAR_INC(*value);

DROP:
    return XDP_DROP;
}

