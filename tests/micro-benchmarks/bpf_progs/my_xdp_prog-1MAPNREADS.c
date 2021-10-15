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

struct geo_value {
    uint32_t geo_array[32768];
};

BPF_PERCPU_ARRAY(metadata, struct pkt_md, 1);

BPF_ARRAY(geo_sampling, struct geo_value, 1);

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
    struct geo_value *value = geo_sampling.lookup(&zero);

    if (value) {
        index = value->geo_array[index];
    } else {
        bpf_trace_printk("Runtime error\n");
    }
#endif

#if _NUM_LOOKUPS > 1
    index &= (32768 - 1);
    index = value->geo_array[index];
#endif

#if _NUM_LOOKUPS > 2
    index &= (32768 - 1);
    index = value->geo_array[index];
#endif

#if _NUM_LOOKUPS > 3
    index &= (32768 - 1);
    index = value->geo_array[index];
#endif

#if _NUM_LOOKUPS > 4
    index &= (32768 - 1);
    if (value->geo_array[index] == 123) {
        goto DROP;
    }
#endif

DROP:;
    __sync_fetch_and_add(&md->drop_cnt, 1);

DROP_ONLY:;
    return XDP_DROP;
}