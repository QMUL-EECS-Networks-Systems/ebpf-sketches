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

struct pkt_md {
  uint64_t drop_cnt;
} __attribute__((packed));

BPF_PERCPU_ARRAY(metadata, struct pkt_md, 1);

BPF_ARRAY(sketch_map_single, __u32, _CS_COLUMNS);
#if _NUM_WRITES > 0
    BPF_ARRAY(sketch_map_single1, __u32, _CS_COLUMNS);
#endif
#if _NUM_WRITES > 1
    BPF_ARRAY(sketch_map_single2, __u32, _CS_COLUMNS);
#endif
#if _NUM_WRITES > 2
    BPF_ARRAY(sketch_map_single3, __u32, _CS_COLUMNS);
#endif
#if _NUM_WRITES > 3
    BPF_ARRAY(sketch_map_single4, __u32, _CS_COLUMNS);
#endif
#if _NUM_WRITES > 4
    BPF_ARRAY(sketch_map_single5, __u32, _CS_COLUMNS);
#endif

BPF_ARRAY_OF_MAPS(sketch_map, "sketch_map_single", _CS_ROWS);

int xdp_prog1(struct CTXTYPE *ctx) {
    void* data_end = (void*)(long)ctx->data_end;
    void* data = (void*)(long)ctx->data;

    uint32_t zero = 0;
    struct pkt_md *md;
    
    md = metadata.lookup(&zero);
    if (!md) {
        bpf_trace_printk("Error! Invalid metadata.");
        goto DROP_ONLY;
    }

    uint32_t rand = bpf_get_prandom_u32();

    for (uint32_t i = 0; i < _NUM_WRITES; i++) {
        if (i >= _CS_ROWS) {
            bpf_trace_printk("Error! Invalid row.");
            goto DROP_ONLY;
        }

        uint32_t idx = i;

        void *sketch = sketch_map.lookup(&idx);
        if (!sketch) {
            bpf_trace_printk("Error! Invalid map of map: sketch_map.");
            goto DROP_ONLY;
        }

        uint32_t col = rand & (_CS_COLUMNS - 1);
        bpf_map_update_elem(sketch, &col, &rand, BPF_ANY);
    }

DROP:;
    __sync_fetch_and_add(&md->drop_cnt, 1);

DROP_ONLY:;
    return XDP_DROP;
}