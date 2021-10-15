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

#include <rte_memory.h>
#include <rte_launch.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_lcore.h>
#include <rte_debug.h>
#include <rte_mbuf.h>
#include <rte_ethdev.h>

#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024

#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32

#define GEO_ARRAY_SIZE 32768
#define CONTROL_VALUE 123

#define _NUM_LOOKUPS 4

struct geo_value {
    uint32_t geo_array[GEO_ARRAY_SIZE];
} geo_table1;

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

unsigned int ran_geometric (const double p)
{
	unsigned int k;
	do {
		double u = (double)rand()/RAND_MAX;

		if (p == 1.0) {
			k = 1;
		}
		else {
			k = log (u) / log (1 - p) + 1;
		}
	} while (k == CONTROL_VALUE);

	return k;
}

void init_geo_array() {
	for (int i = 0; i < GEO_ARRAY_SIZE; i++)
        geo_table1.geo_array[i] = ran_geometric(0.1);
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
		printf("Error during getting device (port %u) info: %s\n",
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

	printf("Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
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

static __rte_noreturn void
lcore_hello(__rte_unused void *arg)
{
	uint16_t port;
	/*
	 * Check that the port is on the same NUMA node as the polling thread
	 * for best performance.
	 */
	RTE_ETH_FOREACH_DEV(port)
		if (rte_eth_dev_socket_id(port) >= 0 &&
			rte_eth_dev_socket_id(port) != (int)rte_socket_id()) {
			printf("\n\n");
			printf("WARNING: port %u is on remote NUMA node\n",
			       port);
			printf("to polling thread.\n");
			printf("Performance will not be optimal.\n");
		}
	printf("\nCore %u forwarding packets. ", rte_lcore_id());
	printf("\nRunning with %u consecutive reads in the single map.\n", _NUM_LOOKUPS);
	printf("[Ctrl+C to quit]\n");
	uint32_t idx;

	for (;;) {
		RTE_ETH_FOREACH_DEV(port) {
			/* Get burst of RX packets, from first port of pair. */
			struct rte_mbuf *bufs[BURST_SIZE];
			const uint16_t nb_rx = rte_eth_rx_burst(port, 0,
					bufs, BURST_SIZE);

			if (unlikely(nb_rx == 0))
				continue;

			for (int i=0; i < nb_rx; i++) {
				struct rte_mbuf *pkt = bufs[i];
				uint32_t start_idx = (uint32_t)rand()%GEO_ARRAY_SIZE;
				// Here I do the processing
				#if _NUM_LOOKUPS > 0
					idx = geo_table1.geo_array[start_idx];
				#endif

				#if _NUM_LOOKUPS > 1
					idx &= (GEO_ARRAY_SIZE - 1);
					idx = geo_table1.geo_array[idx];
				#endif

				#if _NUM_LOOKUPS > 2
					idx &= (GEO_ARRAY_SIZE - 1);
					idx = geo_table1.geo_array[idx];
				#endif

				#if _NUM_LOOKUPS > 3
					idx &= (GEO_ARRAY_SIZE - 1);
					if (geo_table1.geo_array[idx] == CONTROL_VALUE) {
						printf("Error, found the CONTROL VALUE; this should never happen");
						rte_pktmbuf_free(pkt);
					}
				#endif

				// uint64_t start = rdtsc();
				// while ((rdtsc() - start) < 4000) {
				// 	tmp_idx++;
				// }
				

				rte_eth_tx_burst(port ^ 1, 0, bufs, nb_rx);
			}

			// /* Send burst of TX packets, to second port of pair. */
			// const uint16_t nb_tx = rte_eth_tx_burst(port ^ 1, 0,
			// 		bufs, nb_rx);

			// /* Free any unsent packets. */
			// if (unlikely(nb_tx < nb_rx)) {
			// 	uint16_t buf;

			// 	for (buf = nb_tx; buf < nb_rx; buf++)
			// 		rte_pktmbuf_free(bufs[buf]);
			// }
		
		}
	}
	// unsigned lcore_id;
	// lcore_id = rte_lcore_id();
	// printf("hello from core %u\n", lcore_id);
}

int
main(int argc, char **argv)
{
	int ret;
	unsigned lcore_id;
	struct rte_mempool *mbuf_pool;
	uint16_t nb_ports;
	uint16_t portid;
	int socket_id;

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

	if (rte_lcore_count() > 1)
		printf("\nWARNING: Too many lcores enabled. Only 1 used.\n");

	socket_id = rte_eth_dev_socket_id(0);

	/* call lcore_hello() on every worker lcore */
	// RTE_LCORE_FOREACH_WORKER(lcore_id) {
	// 	rte_eal_remote_launch(lcore_hello, NULL, lcore_id);
	// }

	srand(time(NULL)); 
	init_geo_array();

	/* call it on main lcore too */
	lcore_hello(NULL);

	// rte_eal_mp_wait_lcore();

	/* clean up the EAL */
	rte_eal_cleanup();

	return 0;
}
