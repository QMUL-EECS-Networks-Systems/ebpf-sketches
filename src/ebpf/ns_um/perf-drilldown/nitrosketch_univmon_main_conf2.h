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
#include <linux/jhash.h>
#include <uapi/linux/types.h>
#include <stddef.h>

#include "common.h"
#include "xxhash32.h"

struct pkt_5tuple {
  __be32 src_ip;
  __be32 dst_ip;
  __be16 src_port;
  __be16 dst_port;
  uint8_t proto;
} __attribute__((packed));

struct topk_entry {
    int value;
    struct pkt_5tuple tuple;
};

struct pkt_md {
  uint32_t cnt;
  uint32_t geo_sampling_idx;
};

#define HASHFN_N _CS_ROWS
#define COLUMNS _CS_COLUMNS

_Static_assert((COLUMNS & (COLUMNS - 1)) == 0, "COLUMNS must be a power of two");

struct countsketch {
	__u32 values[HASHFN_N][COLUMNS];
    struct topk_entry topks[_HEAP_SIZE];
};

BPF_PERCPU_ARRAY(metadata, struct pkt_md, 1);
BPF_PERCPU_ARRAY(dropcnt, uint64_t, 1);
BPF_PERCPU_ARRAY(ns_um, struct countsketch, _NM_LAYERS);
BPF_ARRAY(geo_sampling, uint32_t, MAX_GEOSAMPLING_SIZE);

static void __always_inline ns_um_add(struct countsketch *cs, void *element, __u64 len, uint32_t row_to_update)
{
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
		// We should probably split the coin here to swap the sign for the countsketch implementation
		if (CHECK_BIT(hash, 31)) {
			cs->values[row_to_update][target_idx]++;
		} else {
			cs->values[row_to_update][target_idx]--;
		}
}

static int __always_inline query_sketch(struct countsketch *cs, void *element, __u64 len) {
	const __u32 hashes[] = {
		xxhash32(element, len, 0x2d31e867),
		xxhash32(element, len, 0x6ad611c4),
		xxhash32(element, len, 0x00000000),
		xxhash32(element, len, 0xffffffff)
	};

	_Static_assert(ARRAY_SIZE(hashes) == HASHFN_N, "Missing hash function");

	int value[HASHFN_N];
	for (int i = 0; i < ARRAY_SIZE(hashes); i++) {
		__u32 target_idx = hashes[i] & (COLUMNS - 1);
		if (CHECK_BIT(hashes[i], 31)) {
			value[i] = cs->values[i][target_idx];
		} else {
			value[i] = -cs->values[i][target_idx];
		}	
	}	// TREAP (min heap)

	// Median return value should be float. We are loosing something here
	return median(value, ARRAY_SIZE(value));
}

static int __always_inline compare_pkt_struct(struct pkt_5tuple *origin_pkt, struct pkt_5tuple *new_pkt) {
    if (origin_pkt->dst_ip == new_pkt->dst_ip &&
        origin_pkt->src_ip == new_pkt->dst_ip &&
        origin_pkt->proto == new_pkt->proto &&
        origin_pkt->dst_port == new_pkt->dst_port &&
        origin_pkt->src_port == new_pkt->src_port)
        return 0;

    return 1;
}

static void __always_inline insertionSort(struct countsketch *md) {
    int i, j;
    struct topk_entry key;

#pragma clang loop unroll(full)
    for (i = 1; i < _HEAP_SIZE; i++) {
        // __builtin_memcpy(&key, &arr[i], sizeof(struct topk_entry));
        key = md->topks[i];
        j = i - 1;
 
        while(j >= 0 && md->topks[j].value < key.value){
            md->topks[j+1] = md->topks[j];		
            j = j - 1;		
        }

        // __builtin_memcpy(&arr[j + 1], &key, sizeof(struct topk_entry));
        md->topks[j + 1] = key;
    }
}

static void __always_inline insert_into_heap(struct countsketch *md, int median, struct pkt_5tuple *pkt) {
    int index = -1;

    for (int i = 0; i < _HEAP_SIZE; i++) {
        struct pkt_5tuple origin_pkt = md->topks[i].tuple;
        // bpf_probe_read_kernel(&origin, sizeof(origin), &md->topks[layer][i].tuple);
        if (origin_pkt.dst_ip == pkt->dst_ip &&
            origin_pkt.src_ip == pkt->src_ip &&
            origin_pkt.proto == pkt->proto &&
            origin_pkt.dst_port == pkt->dst_port &&
            origin_pkt.src_port == pkt->src_port) {
                index = i;
                break;
        }
    }

    if (index >= 0) {
        if (md->topks[index].value < median) {
            md->topks[index].value = median;
            md->topks[index].tuple = *pkt;
        } else {
            return;
        }
    } else {
        // The element is not in the array, let's insert a new one.
        // What I do is to insert in the last position, and then sort the array
        if (md->topks[_HEAP_SIZE-1].value < median) {
            md->topks[_HEAP_SIZE-1].value = median;
            md->topks[_HEAP_SIZE-1].tuple = *pkt;
        } else {
            return;
        }
    }
    insertionSort(md);
}

static uint32_t trailing_zeros(uint32_t V) {
	V = V-(V&(V-1));
	return( ( ( V & 0xFFFF0000 ) != 0 ? ( V &= 0xFFFF0000, 16 ) : 0 ) | ( ( V & 0xFF00FF00 ) != 0 ? ( V &= 0xFF00FF00, 8 ) : 0 ) | ( ( V & 0xF0F0F0F0 ) != 0 ? ( V &= 0xF0F0F0F0, 4 ) : 0 ) | ( ( V & 0xCCCCCCCC ) != 0 ? ( V &= 0xCCCCCCCC, 2 ) : 0 ) | ( ( V & 0xAAAAAAAA ) != 0 ) );
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
        bpf_trace_printk("Error! Invalid metadata.\n");
        goto DROP;
    }

    if (md->cnt >= HASHFN_N) {
        md->cnt -= HASHFN_N;
        goto SKIP;
    }

    uint32_t layerhash = xxhash32(&pkt, sizeof(pkt), 0xdeadbeef);

    // always insert into layer 0, set least significant bit to 0 (we count from right)
    layerhash &= ~1;
    uint32_t max_l = trailing_zeros(layerhash);
	max_l = min(max_l, _NM_LAYERS);

    struct countsketch *cm;    
    cm = ns_um.lookup(&max_l);
    if (!cm) {
        bpf_trace_printk("Invalid entry in the countsketch sketch\n");
        goto DROP;
    }

    uint32_t row_to_update;
    uint32_t next_geo_value;
    // This is required otherwise the verifier triggers an error
    bpf_probe_read_kernel(&row_to_update, sizeof(row_to_update), &md->cnt);

	for (int i = 0; i < HASHFN_N; i++) {
        // Update the sketch
        ns_um_add(cm, &pkt, sizeof(pkt), i);

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
        bpf_trace_printk("Geo sampling variable is 0. This should never happen");
        goto DROP;
    }

    u32 rand = bpf_get_prandom_u32();
    if (rand < UPDATE_PROBABILITY) {
        int median = query_sketch(cm, &pkt, sizeof(pkt));
        int value = median;

        insert_into_heap(cm, value, &pkt);
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