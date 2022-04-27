#pragma once

#include "stdio.h"
#include "stdint.h"
#include "time.h"

#ifdef NO_SIMD
#pragma GCC push_options
#pragma GCC optimize("-ftree-vectorize")
void __attribute__((target("sse2"), target("mmx"), target("avx"),
                    target("avx512f")))
print_results(struct timespec *tstart, struct timespec *tend, uint64_t N,
              volatile uint32_t hashvalue) {
#else
void inline __attribute__((__always_inline__))
print_results(struct timespec *tstart, struct timespec *tend, uint64_t N,
              volatile uint32_t hashvalue) {
#endif
  printf("Hash calc took about %.5f seconds, final value=%u\n",
         ((double)tend->tv_sec + 1.0e-9 * tend->tv_nsec) -
             ((double)tstart->tv_sec + 1.0e-9 * tstart->tv_nsec),
         hashvalue);

  double timediff = ((double)tend->tv_sec + 1.0e-9 * tend->tv_nsec) -
                    ((double)tstart->tv_sec + 1.0e-9 * tstart->tv_nsec);
  double hashrate_hs = N / timediff;
  double hashrate_Mhs = hashrate_hs / 1e6;
  printf("Hashrate: %.4f Mh/s\n", hashrate_Mhs);
}