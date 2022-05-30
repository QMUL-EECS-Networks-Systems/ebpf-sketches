/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <sys/queue.h>
#include <math.h>
#include <unistd.h>
#include <time.h>

#include <rte_memory.h>
#include <rte_launch.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_lcore.h>
#include <rte_debug.h>
#include <rte_mbuf.h>
#include <rte_ethdev.h>
#include <rte_log.h>
#include <stdint.h>
#include <semaphore.h>

#include "../prandom.h"
#include "../utils.h"

#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024

#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32

#define CONTROL_VALUE 1234

#ifndef _NUM_RAND_CYCLES
#define _NUM_RAND_CYCLES 4
#endif

#ifdef DEBUG
#define DEBUG_TEST 1
#else
#define DEBUG_TEST 0
#endif

#define MAX_GEOSAMPLING_SIZE 32768

#define debug_print(...) \
            do { if (DEBUG_TEST) fprintf(stderr, __VA_ARGS__); } while (0)

struct siprand_state {
	unsigned long v0;
	unsigned long v1;
	unsigned long v2;
	unsigned long v3;
};

struct thread_ctx {
    sem_t*              sem_stop;
    unsigned int        thread_id;
	struct timespec 	tstart;
	struct timespec 	tend;
};

struct siprand_state net_rand_state;

struct rand_value {
    uint32_t rand_array[MAX_GEOSAMPLING_SIZE];
};

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

static const struct rte_eth_conf port_conf_default = {
	.rxmode = {
		.max_rx_pkt_len = RTE_ETHER_MAX_LEN,
	},
};


volatile uint64_t tmp_idx = 0;

uint64_t rdtsc(){
    unsigned int lo,hi;
    __asm__ __volatile__ ("rdtsc" : "=a" (lo), "=d" (hi));
    return ((uint64_t)hi << 32) | lo;
}

static inline int
port_init(uint8_t port, struct rte_mempool *mbuf_pool)
{
	struct rte_eth_conf port_conf = port_conf_default;
	struct rte_ether_addr addr;
	const uint16_t rx_rings = 1, tx_rings = 1;
	int retval;
	uint16_t q;
	struct rte_eth_dev_info dev_info;
	struct rte_eth_txconf txconf;

	if (!rte_eth_dev_is_valid_port(port))
		return -1;

	retval = rte_eth_dev_info_get(port, &dev_info);
	if (retval != 0) {
		debug_print("Error during getting device (port %u) info: %s\n",
				port, strerror(-retval));
		return retval;
	}

	if (dev_info.tx_offload_capa & DEV_TX_OFFLOAD_MBUF_FAST_FREE)
		port_conf.txmode.offloads |=
			DEV_TX_OFFLOAD_MBUF_FAST_FREE;

	/* Configure the Ethernet device. */
	retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
	if (retval != 0)
		return retval;

	/* Allocate and set up 1 RX queue per Ethernet port. */
	for (q = 0; q < rx_rings; q++) {
		retval = rte_eth_rx_queue_setup(port, q, RX_RING_SIZE,
				rte_eth_dev_socket_id(port), NULL, mbuf_pool);
		if (retval < 0)
			return retval;
	}

	txconf = dev_info.default_txconf;
	txconf.offloads = port_conf.txmode.offloads;
	/* Allocate and set up 1 TX queue per Ethernet port. */
	for (q = 0; q < tx_rings; q++) {
		retval = rte_eth_tx_queue_setup(port, q, TX_RING_SIZE,
				rte_eth_dev_socket_id(port), &txconf);
		if (retval < 0)
			return retval;
	}

	/* Start the Ethernet port. */
	retval = rte_eth_dev_start(port);
	if (retval < 0)
		return retval;

	/* Display the port MAC address. */
	retval = rte_eth_macaddr_get(port, &addr);
	if (retval != 0)
		return retval;

	debug_print("Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
			   " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
			port,
			addr.addr_bytes[0], addr.addr_bytes[1],
			addr.addr_bytes[2], addr.addr_bytes[3],
			addr.addr_bytes[4], addr.addr_bytes[5]);

	/* Enable RX in promiscuous mode for the Ethernet device. */
	retval = rte_eth_promiscuous_enable(port);
	if (retval != 0)
		return retval;

	return 0;
}

static void init_rand_array(struct rand_value *rand) {
	for (int i = 0; i < MAX_GEOSAMPLING_SIZE; i++) {
		rand->rand_array[i] = prandom_u32();
	}
}

static int lcore_hello(void* thread_ctx)
{
	struct thread_ctx*  ctx;
	debug_print("\nHello forwarding packets.");
	uint16_t port;
	int sem_value = 0;
	struct rand_value rand;
	uint32_t geo_sampling_idx = 0;

	if (!thread_ctx)
        return (EINVAL);

	/* retrieve thread context */
    ctx = (struct thread_ctx*)thread_ctx;
	/*
	 * Check that the port is on the same NUMA node as the polling thread
	 * for best performance.
	 */
	RTE_ETH_FOREACH_DEV(port)
		if (rte_eth_dev_socket_id(port) >= 0 &&
			rte_eth_dev_socket_id(port) != (int)rte_socket_id()) {
			debug_print("\n\n");
			debug_print("WARNING: port %u is on remote NUMA node ",
			       port);
			debug_print("to polling thread.\n");
			debug_print("Performance will not be optimal.\n");
		}
	debug_print("\nCore %u forwarding packets. ", rte_lcore_id());
	debug_print("\nRunning with %u rand calls in cycle.\n", _NUM_RAND_CYCLES);
	debug_print("[Ctrl+C to quit]\n");
	uint32_t idx;
	const uint64_t N = _NUM_RAND_CYCLES;

	prandom_seed(1234);

	init_rand_array(&rand);

	struct timespec tstart = {0, 0}, tend = {0, 0};
  	clock_gettime(CLOCK_MONOTONIC, &tstart);

	while (!sem_value) {
		RTE_ETH_FOREACH_DEV(port) {
			/* Get burst of RX packets, from first port of pair. */
			struct rte_mbuf *bufs[BURST_SIZE];
			const uint16_t nb_rx = rte_eth_rx_burst(port, 0,
					bufs, BURST_SIZE);

			if (unlikely(nb_rx == 0))
				continue;

			for (int i=0; i < nb_rx; i++) {
				volatile __u32 rndval = 0;
    			__u32 atom;

				struct rte_mbuf *pkt = bufs[i];
				
				for (int i = 0; i < N; i++) {
        			geo_sampling_idx = (geo_sampling_idx + 1) & (32768 - 1);
        			atom=rand.rand_array[geo_sampling_idx];
        			rndval^=atom;
    			}

				if (rndval == CONTROL_VALUE) {
					rte_pktmbuf_free(pkt);
					continue;
				}
			}

			/* Send burst of TX packets, to second port of pair. */
			const uint16_t nb_tx = rte_eth_tx_burst(port ^ 1, 0, bufs, nb_rx);

			/* Free any unsent packets. */
			if (unlikely(nb_tx < nb_rx)) {
				uint16_t buf;

				for (buf = nb_tx; buf < nb_rx; buf++)
					rte_pktmbuf_free(bufs[buf]);		
			}


			sem_getvalue(ctx->sem_stop, &sem_value);
            if (sem_value > 0) {
				debug_print("Received STOP signal\n");
				rte_eth_dev_stop(port);

				clock_gettime(CLOCK_MONOTONIC, &tend);

				ctx->tstart = tstart;
				ctx->tend = tend;
                break;
            }
		}
	}

	return (0);
}

int
main(int argc, char **argv)
{
	int ret;
	unsigned lcore_id;
	struct thread_ctx ctx;
	struct rte_mempool *mbuf_pool;
	uint16_t nb_ports;
	uint16_t portid;
	int socket_id;
	sem_t sem_stop;

#ifndef DEBUG
	rte_log_set_global_level(RTE_LOG_EMERG);
#endif

	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

	/* Check that there is an even number of ports to send/receive on. */
	nb_ports = rte_eth_dev_count_avail();
	if (nb_ports < 2 || (nb_ports & 1))
		rte_exit(EXIT_FAILURE, "Error: number of ports must be even\n");

	/* Creates a new mempool in memory to hold the mbufs. */
	mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS * nb_ports,
		MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

	if (mbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

	/* Initialize all ports. */
	RTE_ETH_FOREACH_DEV(portid)
		if (port_init(portid, mbuf_pool) != 0)
			rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu8 "\n",
					portid);

	if (rte_lcore_count() > 2)
		debug_print("\nWARNING: Too many lcores enabled. Only 1 used.\n");

	socket_id = rte_eth_dev_socket_id(0);

	if (sem_init(&sem_stop, 0, 0)) {
        fprintf(stderr, "sem_init failed: %s\n", strerror(errno));
        return (errno);
    }

	ctx.sem_stop = &sem_stop;

	debug_print("Launching remote thread\n");
	ret = rte_eal_mp_remote_launch(lcore_hello, &ctx, 0); /* skip fake master core */
	if (ret) {
		fprintf(stderr, "rte_eal_remote_launch failed: %s\n", strerror(ret));
		return (ret);
	}

	/* call it on main lcore too */
	// lcore_hello(NULL);
	
	for(int i = 0; i < 60; i++) {
		debug_print("Running %d/60\n", i);
		sleep(1);
	}
	ret = sem_post(&sem_stop);
	if (ret) {
		fprintf(stderr, "sem_post failed: %s\n", strerror(errno));
		return (errno);
	}

	rte_eal_mp_wait_lcore();

	struct rte_eth_stats stats;
	ret = rte_eth_stats_get(1, &stats);
	if (ret) {
		debug_print("Error while reading stats from port: %u\n", 1);
	} else {
		debug_print("-> Stats for port: %u\n\n", 1);
		debug_print("%u,%"PRIu64",%"PRIu64",%"PRIu64",%"PRIu64"\n", 
				1,
				stats.ipackets,
				stats.ibytes,
				stats.opackets,
				stats.obytes);
	}

	debug_print("Rand calc took about %.5f seconds\n", ((double)ctx.tend.tv_sec + 1.0e-9 * ctx.tend.tv_nsec) -
           										  ((double)ctx.tstart.tv_sec + 1.0e-9 * ctx.tstart.tv_nsec));

  	double timediff = ((double)ctx.tend.tv_sec + 1.0e-9 * ctx.tend.tv_nsec) -
                      ((double)ctx.tstart.tv_sec + 1.0e-9 * ctx.tstart.tv_nsec);

	double randrate_hs = (stats.opackets*_NUM_RAND_CYCLES)/timediff;
	double randrate_Mhs = randrate_hs / 1e6;
	debug_print("Random generation rate: %.4f Mrand/s\n", randrate_Mhs);

	printf("%.4f", randrate_Mhs);

	/* clean up the EAL */
	rte_eal_cleanup();

	return 0;
}
