#include "prandom.h"
#include <cstdio>

#include "prandom.h"
#include "utils.h"

struct siprand_state {
	unsigned long v0;
	unsigned long v1;
	unsigned long v2;
	unsigned long v3;
};
struct siprand_state net_rand_state;

static inline u32 siprand_u32(struct siprand_state *s)
{
	unsigned long v0 = s->v0, v1 = s->v1, v2 = s->v2, v3 = s->v3;
	unsigned long n = (net_rand_noise);

	v3 ^= n;
	PRND_SIPROUND(v0, v1, v2, v3);
	PRND_SIPROUND(v0, v1, v2, v3);
	v0 ^= n;
	s->v0 = v0;  s->v1 = v1;  s->v2 = v2;  s->v3 = v3;
	return v1 + v3;
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
	struct siprand_state *state = (&net_rand_state);
	u32 res = siprand_u32(state);
	//put_cpu_ptr(&net_rand_state);
	return res;
}

void prandom_seed(u32 entropy){
	int i=0;
	struct siprand_state *state = (&net_rand_state);
		unsigned long v0 = state->v0, v1 = state->v1;
		unsigned long v2 = state->v2, v3 = state->v3;

		do {
			v3 ^= entropy;
			PRND_SIPROUND(v0, v1, v2, v3);
			PRND_SIPROUND(v0, v1, v2, v3);
			v0 ^= entropy;
		} while ((!v0 || !v1 || !v2 || !v3));

		(state->v0=v0);
		(state->v1=v1);
		(state->v2=v2);
		(state->v3=v3);
}


const int N=1000*1000*2000;
int main(){
	prandom_seed(1234);

	struct timespec tstart = {0, 0}, tend = {0, 0};
  	clock_gettime(CLOCK_MONOTONIC, &tstart);
	u32 ret=0;
	for(int i=0;i<N;i++){
		u32 r=prandom_u32();
		ret^=r;
	}
	clock_gettime(CLOCK_MONOTONIC, &tend);
	
	print_results(&tstart, &tend, N, ret);
	return 0;
}
