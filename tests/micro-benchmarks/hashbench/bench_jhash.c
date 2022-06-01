// benchmark several hash function implementations

#include <linux/types.h>

#include "stdio.h"
#include "stdint.h"
#include "time.h"

#include "jhash.h"
#include "utils.h"

struct pkt_5tuple {
  volatile __be32 src_ip;
  __be32 dst_ip;
  __be16 src_port;
  __be16 dst_port;
  uint8_t proto;
};

int main() {
  printf("Hello, world. JHASH\n");

  struct pkt_5tuple pkt;

  pkt.src_ip = 1;
  pkt.dst_ip = 2;
  pkt.src_port = 3;
  pkt.dst_port = 4;
  pkt.proto = 6;

  const uint64_t N = 1000 * 1000 * 1000;
  volatile uint32_t hashvalue = 0; // uint32_t
  for (uint64_t i = 0; i < N; i += 20)
    hashvalue ^= jhash((void *)&pkt, sizeof(pkt), i); // warmup

  struct timespec tstart = {0, 0}, tend = {0, 0};
  clock_gettime(CLOCK_MONOTONIC, &tstart);
  {
    for (int i = 0; i < N; i++) {
      pkt.src_ip = hashvalue;
      hashvalue ^= jhash((void *)&pkt, sizeof(pkt), i * i);
    }
  }
  clock_gettime(CLOCK_MONOTONIC, &tend);

  print_results(&tstart, &tend, N, hashvalue);

  return 0;
}