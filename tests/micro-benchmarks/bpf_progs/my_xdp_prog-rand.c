
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

#define _PARSING_ON 0

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
    uint32_t index = 0;
    
#if _PARSING_ON
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

    index = ip->protocol;
    }
#endif
    
#if _NUM_RAND > 0
    uint32_t rand1 = bpf_get_prandom_u32();
    
    if (rand1 == 0) goto DROP;
#endif

#if _NUM_RAND > 1
    uint32_t rand2 = bpf_get_prandom_u32();
    
    if (rand2 == 0) goto DROP;
#endif

#if _NUM_RAND > 2
    uint32_t rand3 = bpf_get_prandom_u32();
    
    if (rand3 == 0) goto DROP;
#endif

#if _NUM_RAND > 3
    uint32_t rand4 = bpf_get_prandom_u32();
    
    if (rand4 == 0) goto DROP;
#endif
    
    value = dropcnt.lookup(&index);
    if (value)
        __sync_fetch_and_add(value, 1);

DROP:
    return XDP_DROP;
}

