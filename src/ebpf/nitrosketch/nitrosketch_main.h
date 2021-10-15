/*
 * Copyright 2021 Sebastiano Miano <mianosebastiano@gmail.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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
#include <linux/if_vlan.h>
#include <stddef.h>

#include "common.h"
#include "fasthash.h"

#define HASHFN_N _CS_ROWS
#define COLUMNS _CS_COLUMNS

_Static_assert((COLUMNS & (COLUMNS - 1)) == 0, "COLUMNS must be a power of two");

struct countsketch {
	__u32 values[HASHFN_N][COLUMNS];
};

struct pkt_md {
  uint32_t cnt;
  uint32_t geo_sampling_idx;
#if _COUNT_PACKETS == 1
  uint64_t drop_cnt;
#endif
#if _COUNT_BYTES == 1
  uint64_t bytes_cnt;
#endif
  uint32_t geo_sampling_array[MAX_GEOSAMPLING_SIZE];
};

struct pkt_5tuple {
  __be32 src_ip;
  __be32 dst_ip;
  __be16 src_port;
  __be16 dst_port;
  uint8_t proto;
} __attribute__((packed));

BPF_PERCPU_ARRAY(metadata, struct pkt_md, 1);
BPF_PERCPU_ARRAY(countsketch, struct countsketch, 1);

static void __always_inline nitrosketch_add_with_hash(struct countsketch *cs, uint16_t *hashes, uint32_t row_to_update)
{
	uint16_t hash;

	if (row_to_update >= HASHFN_N) {
		return;
	}

    hash = hashes[row_to_update];

	uint16_t target_idx = hash & (COLUMNS - 1);
    if (CHECK_BIT(hash, 15)) {
        // cs->values[row_to_update][target_idx]++;
        NO_TEAR_ADD(cs->values[row_to_update][target_idx], 1);
    } else {
        // cs->values[row_to_update][target_idx]--;
        NO_TEAR_ADD(cs->values[row_to_update][target_idx], -1);
    }		
}

int xdp_prog1(struct CTXTYPE *ctx) {
    void* data_end = (void*)(long)ctx->data_end;
    void* data = (void*)(long)ctx->data;

    uint32_t zero = 0;
    struct pkt_md *md;
    
    md = metadata.lookup(&zero);
    if (!md) {
        bpf_trace_printk("Error! Invalid metadata.");
        goto DROP;
    }

    if (md->cnt >= HASHFN_N) {
        md->cnt -= HASHFN_N;
        goto SKIP;
    }

    uint64_t nh_off = 0;
    struct eth_hdr *eth = data;
    nh_off = sizeof(*eth);
    if (data + nh_off > data_end)
        goto DROP;

    uint16_t h_proto = eth->proto;

    // parse double vlans
    #pragma unroll
    for (int i=0; i < 2; i++) {
        if (h_proto == htons(ETH_P_8021Q) || h_proto == htons(ETH_P_8021AD)) {
            struct vlan_hdr *vhdr;
            vhdr = data + nh_off;
            nh_off += sizeof(struct vlan_hdr);
            if (data + nh_off > data_end)
                goto DROP;
            h_proto = vhdr->h_vlan_encapsulated_proto;
        }
    }

    switch (h_proto) {
        case htons(ETH_P_IP):
            break;
        default:
            return XDP_PASS;
    }

    struct pkt_5tuple pkt;

    struct iphdr *ip = data + nh_off;
    if ((void*)&ip[1] > data_end)
        goto DROP;

    pkt.src_ip = ip->saddr;
    pkt.dst_ip = ip->daddr;
    pkt.proto = ip->protocol;

    switch (ip->protocol) {
        case IPPROTO_TCP: {
            struct tcp_hdr *tcp = NULL;
            tcp = data + nh_off + sizeof(*ip);
            if (data + nh_off + sizeof(*ip) + sizeof(*tcp) > data_end)
                goto DROP;               
            pkt.src_port = tcp->source;
            pkt.dst_port = tcp->dest;
            break;
        }
        case IPPROTO_UDP: {
            struct udphdr *udp = NULL;
            udp = data + nh_off + sizeof(*ip);
            if (data + nh_off + sizeof(*ip) + sizeof(*udp) > data_end)
                goto DROP; 
            pkt.src_port = udp->source;
            pkt.dst_port = udp->dest;
            break;
        }
        default:
            goto DROP;
    }

    struct countsketch *cm;
    cm = countsketch.lookup(&zero);

    if (!cm) {
        bpf_trace_printk("Invalid entry in the countsketch sketch");
        goto DROP;
    }

    uint32_t row_to_update;
    uint32_t next_geo_value;

    // This is required otherwise the verifier triggers an error
    bpf_probe_read_kernel(&row_to_update, sizeof(row_to_update),  &md->cnt);

    // Calculate just a single hash and re-use it to update and query the sketch
    uint64_t h = fasthash64(&pkt, sizeof(pkt), _SEED_HASHFN);

    uint16_t hashes[4];
    hashes[0] =  (h & 0xFFFF);
    hashes[1] =  h  >> 16 & 0xFFFF;
    hashes[2] =  h  >> 32 & 0xFFFF;
    hashes[3] =  h  >> 48 & 0xFFFF;
    
    // In the worst case, we do HASHFN_N cycles to update the counters
    // But in most of the case we jump out of the cycle because of the 
    // geometric variable that increases the row_to_update
    for (int i = 0; i < HASHFN_N; i++) {
        // Here we start updating the sketch
        nitrosketch_add_with_hash(cm, hashes, row_to_update);

        // We should now generate again a new discrete variable for the geometric sampling
        uint32_t geo_value_idx = md->geo_sampling_idx;

        geo_value_idx = (geo_value_idx + 1) & (MAX_GEOSAMPLING_SIZE - 1);
        next_geo_value = md->geo_sampling_array[geo_value_idx];
        row_to_update += next_geo_value;
        // geo_value_idx = (geo_value_idx + 1) & (MAX_GEOSAMPLING_SIZE - 1);
        md->geo_sampling_idx = geo_value_idx;
        
        if (row_to_update >= HASHFN_N) break;
    }

    if (next_geo_value > 0) {
        md->cnt = next_geo_value - 1;
    } else {
        bpf_trace_printk("Geo sammpling variable is 0. This should never happen");
        goto DROP;
    }

SKIP:;
#if _COUNT_PACKETS == 1
    NO_TEAR_INC(md->drop_cnt);
#endif
#if _COUNT_BYTES == 1
    uint16_t pkt_len = (uint16_t)(data_end - data);
    NO_TEAR_ADD(md->bytes_cnt, pkt_len);
#endif

#if _ACTION_DROP
    return XDP_DROP;
#else   
    return bpf_redirect(_OUTPUT_INTERFACE_IFINDEX, 0);
#endif

DROP:;
    bpf_trace_printk("Error. Dropping packet\n");
    return XDP_DROP;
}

// This is only used when the action is redirect
int xdp_dummy(struct xdp_md *ctx) {
    return XDP_PASS;
}