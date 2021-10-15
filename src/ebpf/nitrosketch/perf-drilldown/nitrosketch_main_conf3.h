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
};

struct pkt_5tuple {
  __be32 src_ip;
  __be32 dst_ip;
  __be16 src_port;
  __be16 dst_port;
  uint8_t proto;
} __attribute__((packed));

BPF_PERCPU_ARRAY(metadata, struct pkt_md, 1);
BPF_PERCPU_ARRAY(dropcnt, uint64_t, 1);
BPF_PERCPU_ARRAY(countsketch, struct countsketch, 1);
BPF_ARRAY(geo_sampling, uint32_t, MAX_GEOSAMPLING_SIZE);

static void __always_inline nitrosketch_add(struct countsketch *cm, void *element, __u64 len, uint32_t row_to_update)
{
	uint32_t hash;

	if (row_to_update >= HASHFN_N) {
		return;
	}

	switch (row_to_update) {
		case 0:
			hash = fasthash32(element, len, 0x2d31e867);
			break;
		case 1:
			hash = fasthash32(element, len, 0x6ad611c4);
			break;
		case 2:
			hash = fasthash32(element, len, 0x00000000);
			break;
		case 3:
			hash = fasthash32(element, len, 0xffffffff);
			break;
	}

	__u32 target_idx = hash & (COLUMNS - 1);
	if (CHECK_BIT(hash, 31)) {
		cm->values[row_to_update][target_idx]++;
	} else {
		cm->values[row_to_update][target_idx]--;
	}		
}

int xdp_prog1(struct CTXTYPE *ctx) {
    void* data_end = (void*)(long)ctx->data_end;
    void* data = (void*)(long)ctx->data;

    struct eth_hdr *eth = data;
    if ( (void *)eth + sizeof(*eth) > data_end )
        goto DROP;

    switch (eth->proto) {
        case htons(ETH_P_IP):
            break;
        default:
            return XDP_PASS;
    }

    struct pkt_5tuple pkt;

    struct iphdr *ip = data + sizeof(*eth);
    if ( (void *)ip + sizeof(*ip) > data_end )
        goto DROP;

    pkt.src_ip = ip->saddr;
    pkt.dst_ip = ip->daddr;
    pkt.proto = ip->protocol;

    switch (ip->protocol) {
        case IPPROTO_TCP: {
            struct tcp_hdr *tcp = NULL;
            tcp = data + sizeof(struct eth_hdr) + sizeof(*ip);
            if (data + sizeof(struct eth_hdr) + sizeof(*ip) + sizeof(*tcp) > data_end)
                goto DROP;               
            pkt.src_port = tcp->source;
            pkt.dst_port = tcp->dest;
            break;
        }
        case IPPROTO_UDP: {
            struct udphdr *udp = NULL;
            udp = data + sizeof(struct eth_hdr) + sizeof(*ip);
            if (data + sizeof(struct eth_hdr) + sizeof(*ip) + sizeof(*udp) > data_end)
                goto DROP; 
            pkt.src_port = udp->source;
            pkt.dst_port = udp->dest;
            break;
        }
        default:
            goto DROP;
    }

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
    
    for (int i = 0; i < HASHFN_N; i++) {
        // Here we start updating the sketch
        nitrosketch_add(cm, &pkt, sizeof(pkt), row_to_update);

        // We should now generate again a new discrete variable for the geometric sampling
        uint32_t geo_value_idx = md->geo_sampling_idx;

        if (geo_value_idx < MAX_GEOSAMPLING_SIZE) {
            uint32_t *geo_value = geo_sampling.lookup(&geo_value_idx);
            if (!geo_value) {
                bpf_trace_printk("Runtime error. Geometric variable not found in the map");
                goto DROP;
            }

            next_geo_value = *geo_value;
            row_to_update += next_geo_value;
            geo_value_idx = (geo_value_idx + 1) & (MAX_GEOSAMPLING_SIZE - 1);
            md->geo_sampling_idx = geo_value_idx;
        } else {
            bpf_trace_printk("Runtime error. Index of geometric sampling cannot be greater than MAX_GEOSAMPLING_SIZE");
            goto DROP;
        }
        
        if (row_to_update >= HASHFN_N) break;
    }

    if (next_geo_value > 0) {
        md->cnt = next_geo_value - 1;
    } else {
        bpf_trace_printk("Geo sammpling variable is 0. This should never happen");
        goto DROP;
    }

SKIP:;
    uint64_t *value;
    value = dropcnt.lookup(&zero);
    if (value)
        NO_TEAR_INC(*value);

#if _ACTION_DROP
    return XDP_DROP;
#else   
    return bpf_redirect(_OUTPUT_INTERFACE_IFINDEX, 0);
#endif

DROP:;
    return XDP_DROP;
}

// This is only used when the action is redirect
int xdp_dummy(struct xdp_md *ctx) {
    return XDP_PASS;
}