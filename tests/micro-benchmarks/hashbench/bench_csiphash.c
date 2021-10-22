//benchmark several hash function implementations

#include <linux/types.h>

#include "stdio.h"
#include "stdint.h"
#include "time.h"

#include "csiphash.h"

struct pkt_5tuple {
  __be32 src_ip;
  __be32 dst_ip;
  __be16 src_port;
  __be16 dst_port;
  uint8_t proto;
} __attribute__((packed));

int main(){
    printf("Hello, world CSIPHASH.\n");
    
    struct pkt_5tuple pkt;
    
    pkt.src_ip=1;
    pkt.dst_ip=2;
    pkt.src_port=3;
    pkt.dst_port=4;
    pkt.proto=6;
    
    const uint64_t N=1000*1000*1000;
    volatile uint64_t hashvalue = 0;//uint32_t
    for(uint64_t i=0;i<N;i+=20) {
        unsigned char value[16] = {0};
        __builtin_memcpy(value,&i,sizeof(i));
        hashvalue^=siphash24((void *)&pkt, sizeof(pkt), value);//warmup
    }
        
    struct timespec tstart={0,0}, tend={0,0};
    clock_gettime(CLOCK_MONOTONIC, &tstart);
    {
        for(uint64_t i=0;i<N;i++){
            pkt.src_ip=i;
            unsigned char value[16] = {0};
            __builtin_memcpy(value,&i,sizeof(i));
            hashvalue ^= siphash24((void *)&pkt, sizeof(pkt), value);
        }
    }
    clock_gettime(CLOCK_MONOTONIC, &tend);
    printf("Hash calc took about %.5f seconds, final value=%ld\n",
           ((double)tend.tv_sec + 1.0e-9*tend.tv_nsec) - 
           ((double)tstart.tv_sec + 1.0e-9*tstart.tv_nsec), hashvalue);
    
    double timediff=((double)tend.tv_sec + 1.0e-9*tend.tv_nsec) - 
           ((double)tstart.tv_sec + 1.0e-9*tstart.tv_nsec);
    double hashrate_hs=N/timediff;
    double hashrate_Mhs=hashrate_hs/1e6;
    printf("Hashrate: %.4f Mh/s\n" , hashrate_Mhs);
    
    return 0;
}