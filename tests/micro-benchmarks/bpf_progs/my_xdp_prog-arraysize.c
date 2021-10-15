#include <uapi/linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/udp.h>

struct pkt_md {
  uint64_t drop_cnt;
};

BPF_PERCPU_ARRAY(dropcnt, struct pkt_md, 1);

BPF_TABLE( EXPERIMENT_MAPTYPE, uint32_t, uint32_t, experiment_array, EXPERIMENT_TABLE_SIZE  );

static inline uint32_t array_experiment_exec(uint32_t hashvalue){
    const uint32_t ERROR_RETURN=0x1234;
    
    uint32_t index = hashvalue % EXPERIMENT_NUM_ELEM;    
    
#ifdef ACTION_READ
    uint32_t* value = experiment_array.lookup(&index);
    if(!value) return ERROR_RETURN;
    return *value;
#endif
     
#ifdef ACTION_WRITE
    uint32_t* value = experiment_array.lookup(&index);
    if(!value) return ERROR_RETURN;
    *value = hashvalue;
    return 0;
#endif

#ifdef ACTION_WRITE_UPDATE
    experiment_array.update(&index, &hashvalue);
    return 0;
#endif
     
#ifdef ACTION_INC
    uint32_t* value = experiment_array.lookup(&index);
    if(!value) return ERROR_RETURN;
    experiment_array.increment(index, 1);
    return 0;
#endif
    
    return 0x1234;
}

int xdp_prog1(struct xdp_md *ctx) {
    void* data_end = (void*)(long)ctx->data_end;
    void* data = (void*)(long)ctx->data;

    long *value;
    uint32_t zero = 0;

    struct pkt_md *md = dropcnt.lookup(&zero);
    if (!md) {
        bpf_trace_printk("Error! Invalid metadata.");
        goto DROP;
    }
    
    u32 rndval = bpf_get_prandom_u32();
    uint32_t result = array_experiment_exec(rndval);
    if(result==0x1234) return XDP_TX;
    
    __sync_fetch_and_add(&md->drop_cnt, 1);

DROP:
    return XDP_DROP;
}

