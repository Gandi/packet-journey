/*
 * Packet-journey userland router which uses DPDK for its fastpath switching
 *
 */
/*
 * Copyright (c) 2015 Gandi S.A.S.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
/*
 * Parts from:
 *
 * Copyright(c) 2010-2015 Intel Corporation. All rights reserved.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * * Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 * * Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in
 *   the documentation and/or other materials provided with the
 *   distribution.
 * * Neither the name of Intel Corporation nor the names of its
 *   contributors may be used to endorse or promote products derived
 *   from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <sys/queue.h>
#include <stdarg.h>
#include <errno.h>
#include <getopt.h>

#include <netinet/in.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <signal.h>

#include <rte_common.h>
#include <rte_log.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_memzone.h>
#include <rte_tailq.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_launch.h>
#include <rte_atomic.h>
#include <rte_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_interrupts.h>
#include <rte_pci.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_ring.h>
#include <rte_log.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_string_fns.h>
#include <rte_cycles.h>
#include <rte_malloc.h>
#include <cmdline_parse.h>
#include <cmdline_parse_ipaddr.h>
#include <rte_kni.h>

#include <libneighbour.h>

#include "common.h"
#include "routing.h"
#include "kni.h"
#include "config.h"

/* Total octets in ethernet header */
#define KNI_ENET_HEADER_SIZE 14

/* Total octets in the FCS */
#define KNI_ENET_FCS_SIZE 4

struct kni_port_params* kni_port_params_array[RTE_MAX_ETHPORTS];
uint8_t kni_port_rdy[RTE_MAX_ETHPORTS] = {0};

static int kni_change_mtu(uint8_t port_id, unsigned new_mtu);
static int kni_config_network_interface(uint8_t port_id, uint8_t if_up);

static rte_atomic32_t kni_stop = RTE_ATOMIC32_INIT(0);

void
kni_burst_free_mbufs(struct rte_mbuf** pkts, unsigned num)
{
	unsigned i;

	if (pkts == NULL)
		return;

	for (i = 0; i < num; i++) {
		rte_pktmbuf_free(pkts[i]);
		pkts[i] = NULL;
	}
}

void
kni_stop_loop(void)
{
	rte_atomic32_inc(&kni_stop);
}

/**
 * Interface to dequeue mbufs from tx_q and burst tx
 */
static void
kni_egress(struct kni_port_params* p, uint32_t lcore_id)
{
	uint8_t i, port_id;
	unsigned nb_tx, num;
	uint32_t nb_kni;
	struct rte_mbuf* pkts_burst[MAX_PKT_BURST];
	uint16_t queue_num;

	if (p == NULL)
		return;

	nb_kni = p->nb_kni;
	port_id = p->port_id;
	queue_num = p->tx_queue_id;
	for (i = 0; i < nb_kni; i++) {
		/* Burst rx from kni */
		num = rte_kni_rx_burst(p->kni[i], pkts_burst, MAX_PKT_BURST);
		if (unlikely(num > MAX_PKT_BURST)) {
			RTE_LOG(ERR, KNI, "Error receiving from KNI\n");
			return;
		}
		/* Burst tx to eth */
		nb_tx = rte_eth_tx_burst(port_id, queue_num, pkts_burst,
					 (uint16_t)num);
		rte_kni_handle_request(p->kni[i]);
		stats[lcore_id].nb_kni_rx += num;
		stats[lcore_id].nb_tx += nb_tx;
		if (unlikely(nb_tx < num)) {
			/* Free mbufs not tx to NIC */
			kni_burst_free_mbufs(&pkts_burst[nb_tx], num - nb_tx);
			stats[lcore_id].nb_kni_dropped += num - nb_tx;
		}
	}
}

int
kni_main_loop(void* arg)
{
	uint8_t i, nb_ports = rte_eth_dev_count();
	int32_t f_stop;
	const unsigned lcore_id = (uintptr_t)arg;

	RTE_LOG(INFO, KNI, "entering kni main loop on lcore %u\n", lcore_id);

	while (1) {
		f_stop = rte_atomic32_read(&kni_stop);
		if (f_stop)
			break;
		for (i = 0; i < nb_ports; i++) {
			kni_egress(kni_port_params_array[i], lcore_id);
		}
		usleep(1000);
	}

	return 0;
}

/* Parse the arguments given in the command line of the application */
/* Initialize KNI subsystem */
void
init_kni(void)
{
	unsigned int num_of_kni_ports = 0, i;
	struct kni_port_params** params = kni_port_params_array;

	/* Calculate the maximum number of KNI interfaces that will be used */
	for (i = 0; i < RTE_MAX_ETHPORTS; i++) {
		if (kni_port_params_array[i]) {
			RTE_LOG(INFO, KNI, "number of kni lcore %d\n",
				params[i]->nb_lcore_k);
			num_of_kni_ports +=
			    (params[i]->nb_lcore_k ? params[i]->nb_lcore_k : 1);
		}
	}

	RTE_LOG(INFO, KNI, "number of kni %d\n", num_of_kni_ports);
	/* Invoke rte KNI init to preallocate the ports */
	rte_kni_init(num_of_kni_ports);
	RTE_LOG(INFO, KNI, "finished init_kni\n");
}

/* Callback for request of changing MTU */
static int
kni_change_mtu(uint8_t port_id, unsigned new_mtu)
{
	int ret;
	uint16_t nb_rx_queue;
	struct rte_eth_conf conf;

	if (port_id >= rte_eth_dev_count()) {
		RTE_LOG(ERR, KNI, "Invalid port id %d\n", port_id);
		return -EINVAL;
	}

	RTE_LOG(INFO, KNI, "-----------------Change MTU of port %d to %u\n",
		port_id, new_mtu);

	/* Stop specific port */
	rte_eth_dev_stop(port_id);

	memcpy(&conf, &port_conf, sizeof(conf));
	/* Set new MTU */
	if (new_mtu > ETHER_MAX_LEN)
		conf.rxmode.jumbo_frame = 1;
	else
		conf.rxmode.jumbo_frame = 0;

	/* mtu + length of header + length of FCS = max pkt length */
	conf.rxmode.max_rx_pkt_len =
	    new_mtu + KNI_ENET_HEADER_SIZE + KNI_ENET_FCS_SIZE;

	nb_rx_queue = get_port_n_rx_queues(port_id);
	// XXX nb_rx_queue +1 for the kni
	ret =
	    rte_eth_dev_configure(port_id, nb_rx_queue, nb_rx_queue + 1, &conf);
	if (ret < 0) {
		RTE_LOG(ERR, KNI, "Fail to reconfigure port %d\n", port_id);
		return ret;
	}

	/* Restart specific port */
	ret = rte_eth_dev_start(port_id);
	if (ret < 0) {
		RTE_LOG(ERR, KNI, "Fail to restart port %d\n", port_id);
		return ret;
	}

	return 0;
}

/* Callback for request of configuring network interface up/down */
static int
kni_config_network_interface(uint8_t port_id, uint8_t if_up)
{
	int ret = 0;

	RTE_LOG(INFO, KNI, "----   kni_config_network_interface\n");
	if (port_id >= rte_eth_dev_count() || port_id >= RTE_MAX_ETHPORTS) {
		RTE_LOG(ERR, KNI, "Invalid port id %d\n", port_id);
		return -EINVAL;
	}

	RTE_LOG(INFO, KNI, "Configure network interface of %d %s\n", port_id,
		if_up ? "up" : "down");

	if (if_up != 0) { /* Configure network interface up */
		rte_eth_dev_stop(port_id);
		ret = rte_eth_dev_start(port_id);
		kni_port_rdy[port_id]++;
	} else /* Configure network interface down */
		rte_eth_dev_stop(port_id);

	if (ret < 0)
		RTE_LOG(ERR, KNI, "Failed to start port %d\n", port_id);

	RTE_LOG(INFO, KNI, "finished kni_config_network_interface\n");
	return ret;
}

int
kni_alloc(uint8_t port_id, struct rte_mempool* pktmbuf_pool)
{
	uint8_t i;
	struct rte_kni* kni;
	struct rte_kni_conf conf;
	struct kni_port_params** params = kni_port_params_array;

	if (port_id >= RTE_MAX_ETHPORTS || !params[port_id])
		return -1;

	params[port_id]->nb_kni =
	    params[port_id]->nb_lcore_k ? params[port_id]->nb_lcore_k : 1;

	for (i = 0; i < params[port_id]->nb_kni; i++) {
		/* Clear conf at first */
		memset(&conf, 0, sizeof(conf));
		if (params[port_id]->nb_lcore_k > 1) {
			snprintf(conf.name, RTE_KNI_NAMESIZE, "dpdk%u_%u",
				 port_id, i);
			conf.core_id = params[port_id]->lcore_k[i];
			conf.force_bind = 1;
		} else
			snprintf(conf.name, RTE_KNI_NAMESIZE, "dpdk%u",
				 port_id);
		conf.group_id = (uint16_t)port_id;
		conf.mbuf_size = MAX_PACKET_SZ;
		/*
		 * The first KNI device associated to a port
		 * is the master, for multiple kernel thread
		 * environment.
		 */
		if (i == 0) {
			struct rte_kni_ops ops;
			struct rte_eth_dev_info dev_info;

			memset(&dev_info, 0, sizeof(dev_info));
			rte_eth_dev_info_get(port_id, &dev_info);
			conf.addr = dev_info.pci_dev->addr;
			conf.id = dev_info.pci_dev->id;

			memset(&ops, 0, sizeof(ops));
			ops.port_id = port_id;
			ops.change_mtu = kni_change_mtu;
			ops.config_network_if = kni_config_network_interface;

			kni = rte_kni_alloc(pktmbuf_pool, &conf, &ops);
		} else
			kni = rte_kni_alloc(pktmbuf_pool, &conf, NULL);

		if (!kni)
			rte_exit(EXIT_FAILURE,
				 "Fail to create kni for "
				 "port: %d\n",
				 port_id);
		params[port_id]->kni[i] = kni;
	}

	return 0;
}

int
kni_free_kni(uint8_t port_id)
{
	uint8_t i;
	struct kni_port_params** p = kni_port_params_array;

	if (port_id >= RTE_MAX_ETHPORTS || !p[port_id])
		return -1;

	for (i = 0; i < p[port_id]->nb_kni; i++) {
		rte_kni_release(p[port_id]->kni[i]);
		p[port_id]->kni[i] = NULL;
	}

	return 0;
}
