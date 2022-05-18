#include <cstdio>
#include <sys/random.h>
#include <stdlib.h>
#include <time.h>
#include <stdint.h>

#include "prandom.h"
#include "utils.h"
struct rnd_state net_rand_state;

u32 prandom_u32_state(struct rnd_state *state)
{
#define TAUSWORTHE(s, a, b, c, d) ((s & c) << d) ^ (((s << a) ^ s) >> b)
	state->s1 = TAUSWORTHE(state->s1,  6U, 13U, 4294967294U, 18U);
	state->s2 = TAUSWORTHE(state->s2,  2U, 27U, 4294967288U,  2U);
	state->s3 = TAUSWORTHE(state->s3, 13U, 21U, 4294967280U,  7U);
	state->s4 = TAUSWORTHE(state->s4,  3U, 12U, 4294967168U, 13U);

	return (state->s1 ^ state->s2 ^ state->s3 ^ state->s4);
}


/**
 *	prandom_u32 - pseudo random number generator
 *
 *	A 32 bit pseudo-random number is generated using a fast
 *	algorithm suitable for simulation. This algorithm is NOT
 *	considered safe for cryptographic use.
 */
u32 prandom_u32(void)
{
	struct rnd_state *state = (&net_rand_state);
	u32 res = prandom_u32_state(state);
	//put_cpu_ptr(&net_rand_state);
	return res;
}

static void prandom_warmup(struct rnd_state *state)
{
	/* Calling RNG ten times to satisfy recurrence condition */
	prandom_u32_state(state);
	prandom_u32_state(state);
	prandom_u32_state(state);
	prandom_u32_state(state);
	prandom_u32_state(state);
	prandom_u32_state(state);
	prandom_u32_state(state);
	prandom_u32_state(state);
	prandom_u32_state(state);
	prandom_u32_state(state);
}

int prandom_seed_full_state(){
	int i=0;
	struct rnd_state *state = (&net_rand_state);
	u32 seeds[4];

	int ret = getrandom(&seeds, sizeof(seeds), 0);
	if (ret < 0 || ret != sizeof(seeds)) {
		printf("Error in getting random numbers\n");
		return -1;
	}

	state->s1 = __seed(seeds[0],   2U);
	state->s2 = __seed(seeds[1],   8U);
	state->s3 = __seed(seeds[2],  16U);
	state->s4 = __seed(seeds[3], 128U);

	prandom_warmup(state);
	return 0;
}

const int N=1000*1000*2000;
int main(){
	if (prandom_seed_full_state() < 0) {
		exit(1);
	}

	struct timespec tstart = {0, 0}, tend = {0, 0};
  	clock_gettime(CLOCK_MONOTONIC, &tstart);
	u32 ret=0;
	for(int i = 0; i < N; i++){
		u32 r = prandom_u32();
		ret ^= r;
	}
	clock_gettime(CLOCK_MONOTONIC, &tend);

	print_results(&tstart, &tend, N, ret);
	return 0;
}
