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
#include <linux/if_vlan.h>
#include <stddef.h>

#include "common.h"
#include "fasthash.h"

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
#if _COUNT_PACKETS == 1
  uint64_t drop_cnt;
#endif
#if _COUNT_BYTES == 1
  uint64_t bytes_cnt;
#endif
  uint32_t geo_sampling_array[MAX_GEOSAMPLING_SIZE];
};

#define HASHFN_N _CS_ROWS
#define COLUMNS _CS_COLUMNS

_Static_assert((COLUMNS & (COLUMNS - 1)) == 0, "COLUMNS must be a power of two");

struct countsketch {
	__u32 values[HASHFN_N][COLUMNS];
    struct topk_entry topks[_HEAP_SIZE];
};

BPF_PERCPU_ARRAY(ns_um, struct countsketch, _NM_LAYERS);
BPF_PERCPU_ARRAY(metadata, struct pkt_md, 1);

static void __always_inline ns_um_add_with_hash(struct countsketch *cs, uint16_t *hashes, uint32_t row_to_update)
{
		uint16_t hash;

		if (row_to_update >= HASHFN_N) {
			return;
		}

		hash = hashes[row_to_update];

		uint16_t target_idx = hash & (COLUMNS - 1);
		// We should probably split the coin here to swap the sign for the countsketch implementation
		if (CHECK_BIT(hash, 15)) {
			// cs->values[row_to_update][target_idx]++;
            NO_TEAR_ADD(cs->values[row_to_update][target_idx], 1);
		} else {
            // cs->values[row_to_update][target_idx]--;
            NO_TEAR_ADD(cs->values[row_to_update][target_idx], -1);
		}
}

static int __always_inline query_sketch_with_hash(struct countsketch *cs, uint16_t *hashes) {
	int value[HASHFN_N];
	for (int i = 0; i < HASHFN_N; i++) {
		__u32 target_idx = hashes[i] & (COLUMNS - 1);
		if (CHECK_BIT(hashes[i], 15)) {
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

    uint32_t layerhash = fasthash32(&pkt, sizeof(pkt), _SEED_LAYERHASH);
    // // always insert into layer 0, set most significant bit to 1
    // layerhash |= 1 << 31; 

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

    // Calculate just a single hash and re-use it to update and query the sketch
    uint64_t h = fasthash64(&pkt, sizeof(pkt), _SEED_HASHFN);

    uint16_t hashes[4];
    hashes[0] =  (h & 0xFFFF);
    hashes[1] =  h  >> 16 & 0xFFFF;
    hashes[2] =  h  >> 32 & 0xFFFF;
    hashes[3] =  h  >> 48 & 0xFFFF;

	for (int i = 0; i < HASHFN_N; i++) {
        // Update the sketch
        ns_um_add_with_hash(cm, hashes, row_to_update);

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
        bpf_trace_printk("Geo sampling variable is 0. This should never happen");
        goto DROP;
    }

    u32 rand = bpf_get_prandom_u32();
    if (rand < UPDATE_PROBABILITY) {
        int median = query_sketch_with_hash(cm, hashes);
        int value = median;

        insert_into_heap(cm, value, &pkt);
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