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

BPF_ARRAY(geo_sampling, uint32_t, 32768);

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

    // uint32_t rand = bpf_get_prandom_u32();
    // uint32_t index = rand & (32768 - 1);
    uint32_t index = 0;

#if _NUM_LOOKUPS > 0
    uint32_t *val1 = geo_sampling.lookup(&index);

    if (val1) {
        index = *val1;
    } else {
        bpf_trace_printk("Runtime error\n");
        goto DROP_ONLY;
    }
#endif

#if _NUM_LOOKUPS > 1
    index &= (32768 - 1);
    uint32_t *val2 = geo_sampling.lookup(&index);

    if (val2) {
        index = *val2;
    } else {
        bpf_trace_printk("Runtime error\n");
        goto DROP_ONLY;
    }
#endif

#if _NUM_LOOKUPS > 2
    index &= (32768 - 1);
    uint32_t *val3 = geo_sampling.lookup(&index);

    if (val3) {
        index = *val3;
    } else {
        bpf_trace_printk("Runtime error\n");
        goto DROP_ONLY;
    }
#endif

#if _NUM_LOOKUPS > 3
    index &= (32768 - 1);
    uint32_t *val4 = geo_sampling.lookup(&index);

    if (val4) {
        index = *val4;
    } else {
        bpf_trace_printk("Runtime error\n");
        goto DROP_ONLY;
    }
#endif

#if _NUM_LOOKUPS > 4
    index &= (32768 - 1);
    uint32_t *val5 = geo_sampling.lookup(&index);

    if (val5) {
        index = *val5;
    } else {
        bpf_trace_printk("Runtime error\n");
        goto DROP_ONLY;
    }
#endif

DROP:;
    __sync_fetch_and_add(&md->drop_cnt, 1);

DROP_ONLY:;
    return XDP_DROP;
}