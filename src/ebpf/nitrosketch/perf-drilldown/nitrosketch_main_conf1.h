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
#include "xxhash32.h"

#define HASHFN_N _CS_ROWS
#define COLUMNS _CS_COLUMNS

_Static_assert((COLUMNS & (COLUMNS - 1)) == 0, "COLUMNS must be a power of two");

struct countsketch {
	__u32 values[HASHFN_N][COLUMNS];
};

struct pkt_md {
  uint64_t drop_cnt;
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

// add element and determine count
static void __always_inline nitrosketch_add(struct countsketch *cm, void *element, __u64 len, uint32_t row_to_update)
{
	//u32 layerhash = hashlittle(element, len, 0xffffffeee);
	uint32_t hash;

	if (row_to_update >= HASHFN_N) {
		return;
	}

	switch (row_to_update) {
		case 0:
			hash = xxhash32(element, len, 0x2d31e867);
			break;
		case 1:
			hash = xxhash32(element, len, 0x6ad611c4);
			break;
		case 2:
			hash = xxhash32(element, len, 0x00000000);
			break;
		case 3:
			hash = xxhash32(element, len, 0xffffffff);
			break;
	}

	__u32 target_idx = hash & (COLUMNS - 1);
	// TODO: In the future we might want to use the packet lenght to update the counter
	if (CHECK_BIT(hash, 31)) {
		cm->values[row_to_update][target_idx]++;
		// __sync_fetch_and_add(&cm->values[row_to_update][target_idx], 1);
	} else {
		cm->values[row_to_update][target_idx]--;
		// __sync_fetch_and_sub(&cm->values[row_to_update][target_idx], 1);
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

    struct countsketch *cm;
    cm = countsketch.lookup(&zero);

    if (!cm) {
        bpf_trace_printk("Invalid entry in the countsketch sketch");
        goto DROP;
    }

    for (int i = 0; i < HASHFN_N; i++) {
        u32 rand = bpf_get_prandom_u32();
        if (rand < UPDATE_PROBABILITY) {
            // Here we start updating the sketch
            nitrosketch_add(cm, &pkt, sizeof(pkt), i);
        }
    }

SKIP:;
    NO_TEAR_INC(md->drop_cnt);

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