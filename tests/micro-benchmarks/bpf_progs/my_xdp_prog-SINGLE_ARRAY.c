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

struct sketch {
	__u32 values[_CS_ROWS][_CS_COLUMNS];
};

BPF_PERCPU_ARRAY(metadata, struct pkt_md, 1);

BPF_TABLE(EXPERIMENT_MAPTYPE, uint32_t, struct sketch, sketch_map, 1);
// BPF_ARRAY(sketch_map, struct countsketch, 1);

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

    struct sketch *s = sketch_map.lookup(&zero);

    if (!s) {
        bpf_trace_printk("Error! Invalid sketch map.");
        goto DROP_ONLY;
    }


    for (int i = 0; i < _NUM_WRITES; i++) {
        if (i >= _CS_ROWS) goto DROP_ONLY;
        uint32_t col = rand & (_CS_COLUMNS - 1);

    #if _USE_ATOMIC == 1
        __sync_fetch_and_add(&s->values[i][col], 1);
    #else
        s->values[i][col] = rand;
    #endif
    }

DROP:;
    __sync_fetch_and_add(&md->drop_cnt, 1);

DROP_ONLY:;
    return XDP_DROP;
}