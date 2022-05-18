#pragma once

#include <stdio.h>
#include <stdint.h>
#include <time.h>

void print_results(struct timespec *tstart, struct timespec *tend, uint64_t N,
              	   volatile uint32_t rand_value) {
  printf("Rand calc took about %.5f seconds, final value=%u\n",
         ((double)tend->tv_sec + 1.0e-9 * tend->tv_nsec) -
             ((double)tstart->tv_sec + 1.0e-9 * tstart->tv_nsec),
         rand_value);

  double timediff = ((double)tend->tv_sec + 1.0e-9 * tend->tv_nsec) -
                    ((double)tstart->tv_sec + 1.0e-9 * tstart->tv_nsec);
  double randrate_hs = N / timediff;
  double randrate_Mhs = randrate_hs / 1e6;
  printf("Random generation rate: %.4f Mrand/s\n", randrate_Mhs);
}