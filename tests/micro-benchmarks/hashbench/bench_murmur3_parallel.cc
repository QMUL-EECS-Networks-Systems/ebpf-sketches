// benchmark several hash function implementations

#include <linux/types.h>

#include "stdio.h"
#include "stdint.h"
#include "time.h"
#include <string.h>

#include "parallel-murmur3.h"
#include "utils.h"

struct pkt_5tuple {
  __be32 src_ip;
  __be32 dst_ip;
  __be16 src_port;
  __be16 dst_port;
  uint8_t proto;
};

int main() {
  printf("Hello, world. MURMUR3 Parallel\n");

  struct pkt_5tuple pkts[8] = { 0 };

  for (int i = 0; i < 8; i++) {
    pkts[i].src_ip = 1;
    pkts[i].dst_ip = 2;
    pkts[i].src_port = 3;
    pkts[i].dst_port = 4;
    pkts[i].proto = 6;
  }

  const uint64_t N = 1000 * 1000 * 1000;
  volatile uint32_t hashvalue = 0; // uint32_t

  printf("Size of pkt_5tuple struct is: %lu\n", sizeof(pkts[0]));

  if ((sizeof(pkts[0]) % sizeof(uint32_t)) != 0) {
    printf("Struct is not 4-bytes aligned\n");
    return 1;
  }

  const int size = sizeof(pkts[0]) / sizeof(uint32_t);

  uint32_t rows[8][size];

  for (int i = 0; i < 8; i++) {
    for (int j = 0; j < size; j++) {
      uint32_t *pkt_ptr = (uint32_t*)&pkts[i];
      rows[i][j] = pkt_ptr[j];
    }
  }

  uint32_t cols[size][8];
  for (int i = 0; i < size; i++) {
    for (int j = 0; j < 8; j++) {
      cols[i][j] = rows[j][i];
      // printf("Cols[%u][%u] = %u\n", i, j, cols[i][j]);
    }
  }

  uint32_t hashes[8];
  for (uint64_t i = 0; i < N; i += 20 + 8) {
    for (int j = 0; j < 8; j++) {
      uint32_t* row = rows[j];
      hashes[j] ^= murmur3<size>::scalar(row, i); // warmup
    }
  }

  // for (int i = 0; i < 8; i++) {
  //   cols[0][i] = hashes[i];
  // }

  struct timespec tstart = {0, 0}, tend = {0, 0};
  clock_gettime(CLOCK_MONOTONIC, &tstart);
  {
    for (int i = 0; i < N; i+=8) {
      uint32_t res[8];
      murmur3<size>::parallel(cols[0], i*i, res);

      for (int j = 0; j < 8; j++) {
        hashes[j] ^= res[j];
        cols[0][j] = hashes[j];
      }
    }
  }
  clock_gettime(CLOCK_MONOTONIC, &tend);

  print_results(&tstart, &tend, N, hashes[0]);

  return 0;
}