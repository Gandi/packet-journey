/*-
 *   BSD LICENSE
 *
 *   Copyright(c) 2010-2014 Intel Corporation. All rights reserved.
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
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
#include <rte_kni.h>

#include "kni.h"


/* Max size of a single packet */
#define MAX_PACKET_SZ           2048

/* Number of bytes needed for each mbuf */
#define MBUF_SZ \
	(MAX_PACKET_SZ + sizeof(struct rte_mbuf) + RTE_PKTMBUF_HEADROOM)

/* Number of mbufs in mempool that is created */
#define NB_MBUF                 (8192 * 16)

/* How many packets to attempt to read from NIC in one go */
#define PKT_BURST_SZ            32

/* How many objects (mbufs) to keep in per-lcore mempool cache */
#define MEMPOOL_CACHE_SZ        PKT_BURST_SZ

/* Number of RX ring descriptors */
#define NB_RXD                  128

/* Number of TX ring descriptors */
#define NB_TXD                  512

/* Total octets in ethernet header */
#define KNI_ENET_HEADER_SIZE    14

/* Total octets in the FCS */
#define KNI_ENET_FCS_SIZE       4

#define KNI_US_PER_SECOND       1000000
#define KNI_SECOND_PER_DAY      86400

struct kni_port_params *kni_port_params_array[RTE_MAX_ETHPORTS];
uint8_t kni_port_rdy[RTE_MAX_ETHPORTS] = { 0 };


/* Options for configuring ethernet port */
static struct rte_eth_conf port_conf = {
	.rxmode = {
			   .header_split = 0,	/* Header Split disabled */
			   .hw_ip_checksum = 0,	/* IP checksum offload disabled */
			   .hw_vlan_filter = 0,	/* VLAN filtering disabled */
			   .jumbo_frame = 0,	/* Jumbo Frame Support disabled */
			   .hw_strip_crc = 0,	/* CRC stripped by hardware */
			   },
	.txmode = {
			   .mq_mode = ETH_MQ_TX_NONE,
			   },
};

/* Structure type for recording kni interface specific stats */
struct kni_interface_stats {
	/* number of pkts received from NIC, and sent to KNI */
	uint64_t rx_packets;

	/* number of pkts received from NIC, but failed to send to KNI */
	uint64_t rx_dropped;

	/* number of pkts received from KNI, and sent to NIC */
	uint64_t tx_packets;

	/* number of pkts received from KNI, but failed to send to NIC */
	uint64_t tx_dropped;
};

/* kni device statistics array */
static struct kni_interface_stats kni_stats[RTE_MAX_ETHPORTS];

static int kni_change_mtu(uint8_t port_id, unsigned new_mtu);
static int kni_config_network_interface(uint8_t port_id, uint8_t if_up);

static rte_atomic32_t kni_stop = RTE_ATOMIC32_INIT(0);

#if 0
/* Print out statistics on packets handled */
static void print_stats(void)
{
	uint8_t i;

	printf("\n**KNI example application statistics**\n"
		   "======  ==============  ============  ============  ============  ============\n"
		   " Port    Lcore(RX/TX)    rx_packets    rx_dropped    tx_packets    tx_dropped\n"
		   "------  --------------  ------------  ------------  ------------  ------------\n");
	for (i = 0; i < RTE_MAX_ETHPORTS; i++) {
		if (!kni_port_params_array[i])
			continue;

		printf("%7d %10u/%2u %13" PRIu64 " %13" PRIu64 " %13" PRIu64 " "
			   "%13" PRIu64 "\n", i,
			   kni_port_params_array[i]->lcore_rx,
			   kni_port_params_array[i]->lcore_tx,
			   kni_stats[i].rx_packets,
			   kni_stats[i].rx_dropped,
			   kni_stats[i].tx_packets, kni_stats[i].tx_dropped);
	}
	printf
		("======  ==============  ============  ============  ============  ============\n");
}

#endif

void kni_burst_free_mbufs(struct rte_mbuf **pkts, unsigned num)
{
	unsigned i;

	if (pkts == NULL)
		return;

	for (i = 0; i < num; i++) {
		rte_pktmbuf_free(pkts[i]);
		pkts[i] = NULL;
	}
}

/**
 * Interface to burst rx and enqueue mbufs into rx_q
 */
static void kni_ingress(struct kni_port_params *p)
{
	uint8_t i, port_id;
	unsigned nb_rx, num;
	uint32_t nb_kni;
	struct rte_mbuf *pkts_burst[PKT_BURST_SZ];

	if (p == NULL)
		return;

	nb_kni = p->nb_kni;
	port_id = p->port_id;
	for (i = 0; i < nb_kni; i++) {
		/* Burst rx from eth */
		nb_rx = rte_eth_rx_burst(port_id, 0, pkts_burst, PKT_BURST_SZ);
		if (unlikely(nb_rx > PKT_BURST_SZ)) {
			RTE_LOG(ERR, KNI, "Error receiving from eth\n");
			return;
		}
		/* Burst tx to kni */
		num = rte_kni_tx_burst(p->kni[i], pkts_burst, nb_rx);
		kni_stats[port_id].rx_packets += num;

		rte_kni_handle_request(p->kni[i]);
		if (unlikely(num < nb_rx)) {
			/* Free mbufs not tx to kni interface */
			kni_burst_free_mbufs(&pkts_burst[num], nb_rx - num);
			kni_stats[port_id].rx_dropped += nb_rx - num;
		}
	}
}

/**
 * Interface to dequeue mbufs from tx_q and burst tx
 */
static void kni_egress(struct kni_port_params *p)
{
	uint8_t i, port_id;
	unsigned nb_tx, num;
	uint32_t nb_kni;
	struct rte_mbuf *pkts_burst[PKT_BURST_SZ];

	if (p == NULL)
		return;

	nb_kni = p->nb_kni;
	port_id = p->port_id;
	for (i = 0; i < nb_kni; i++) {
		/* Burst rx from kni */
		num = rte_kni_rx_burst(p->kni[i], pkts_burst, PKT_BURST_SZ);
		if (unlikely(num > PKT_BURST_SZ)) {
			RTE_LOG(ERR, KNI, "Error receiving from KNI\n");
			return;
		}
		/* Burst tx to eth */
		nb_tx = rte_eth_tx_burst(port_id, 0, pkts_burst, (uint16_t) num);
		kni_stats[port_id].tx_packets += nb_tx;
		if (unlikely(nb_tx < num)) {
			/* Free mbufs not tx to NIC */
			kni_burst_free_mbufs(&pkts_burst[nb_tx], num - nb_tx);
			kni_stats[port_id].tx_dropped += num - nb_tx;
		}
	}
}

int kni_main_loop(__rte_unused void *arg)
{
	uint8_t i, nb_ports = rte_eth_dev_count();
	int32_t f_stop;
	const unsigned lcore_id = rte_lcore_id();
	enum lcore_rxtx {
		LCORE_NONE,
		LCORE_RX,
		LCORE_TX,
		LCORE_MAX
	};
	enum lcore_rxtx flag = LCORE_NONE;
	RTE_LOG(INFO, KNI, "entering kni main loop on lcore %u\n", lcore_id);

	nb_ports = (uint8_t) (nb_ports < RTE_MAX_ETHPORTS ?
						  nb_ports : RTE_MAX_ETHPORTS);
	for (i = 0; i < nb_ports; i++) {
		if (!kni_port_params_array[i])
			continue;
		if (kni_port_params_array[i]->lcore_rx == (uint8_t) lcore_id) {
			flag = LCORE_RX;
			break;
		} else if (kni_port_params_array[i]->lcore_tx ==
				   (uint8_t) lcore_id) {
			flag = LCORE_TX;
			break;
		}
	}

	if (flag == LCORE_RX) {
		RTE_LOG(INFO, KNI, "Lcore %u is reading from port %d\n",
				kni_port_params_array[i]->lcore_rx,
				kni_port_params_array[i]->port_id);
		while (1) {
			f_stop = rte_atomic32_read(&kni_stop);
			if (f_stop)
				break;
			kni_ingress(kni_port_params_array[i]);
		}
	} else if (flag == LCORE_TX) {
		RTE_LOG(INFO, KNI, "Lcore %u is writing to port %d\n",
				kni_port_params_array[i]->lcore_tx,
				kni_port_params_array[i]->port_id);
		while (1) {
			f_stop = rte_atomic32_read(&kni_stop);
			if (f_stop)
				break;
			kni_egress(kni_port_params_array[i]);
		}
	} else
		RTE_LOG(INFO, KNI, "Lcore %u has nothing to do\n", lcore_id);

	return 0;
}


static void print_config(void)
{
	uint32_t i, j;
	struct kni_port_params **p = kni_port_params_array;

	for (i = 0; i < RTE_MAX_ETHPORTS; i++) {
		if (!p[i])
			continue;
		RTE_LOG(DEBUG, KNI, "Port ID: %d\n", p[i]->port_id);
		RTE_LOG(DEBUG, KNI, "Rx lcore ID: %u, Tx lcore ID: %u\n",
				p[i]->lcore_rx, p[i]->lcore_tx);
		for (j = 0; j < p[i]->nb_lcore_k; j++)
			RTE_LOG(DEBUG, KNI, "Kernel thread lcore ID: %u\n",
					p[i]->lcore_k[j]);
	}
}

int kni_parse_config(const char *arg)
{
	const char *p, *p0 = arg;
	char s[256], *end;
	unsigned size;
	enum fieldnames {
		FLD_PORT = 0,
		FLD_LCORE_RX,
		FLD_LCORE_TX,
		_NUM_FLD = KNI_MAX_KTHREAD + 3,
	};
	int i, j, nb_token;
	char *str_fld[_NUM_FLD];
	unsigned long int_fld[_NUM_FLD];
	uint8_t port_id, nb_kni_port_params = 0;

	memset(&kni_port_params_array, 0, sizeof(kni_port_params_array));
	while (((p = strchr(p0, '(')) != NULL) &&
		   nb_kni_port_params < RTE_MAX_ETHPORTS) {
		p++;
		if ((p0 = strchr(p, ')')) == NULL)
			goto fail;
		size = p0 - p;
		if (size >= sizeof(s)) {
			printf("Invalid config parameters\n");
			goto fail;
		}
		snprintf(s, sizeof(s), "%.*s", size, p);
		nb_token = rte_strsplit(s, sizeof(s), str_fld, _NUM_FLD, ',');
		if (nb_token <= FLD_LCORE_TX) {
			printf("Invalid config parameters\n");
			goto fail;
		}
		for (i = 0; i < nb_token; i++) {
			errno = 0;
			int_fld[i] = strtoul(str_fld[i], &end, 0);
			if (errno != 0 || end == str_fld[i]) {
				printf("Invalid config parameters\n");
				goto fail;
			}
		}

		i = 0;
		port_id = (uint8_t) int_fld[FLD_PORT];
		if (port_id >= RTE_MAX_ETHPORTS) {
			printf("Port ID %d could not exceed the maximum %d\n",
				   port_id, RTE_MAX_ETHPORTS);
			goto fail;
		}
		if (kni_port_params_array[port_id]) {
			printf("Port %d has been configured\n", port_id);
			goto fail;
		}
		kni_port_params_array[port_id] =
			(struct kni_port_params *) rte_zmalloc("KNI_port_params",
												   sizeof(struct
														  kni_port_params),
												   RTE_CACHE_LINE_SIZE);
		kni_port_params_array[port_id]->port_id = port_id;
		//XXX we don't want to do RX in our case.
		//kni_port_params_array[port_id]->lcore_rx = (uint8_t) int_fld[FLD_LCORE_RX];
		kni_port_params_array[port_id]->lcore_rx = 127;

		kni_port_params_array[port_id]->lcore_tx =
			(uint8_t) int_fld[FLD_LCORE_TX];
		if (kni_port_params_array[port_id]->lcore_rx >= RTE_MAX_LCORE
			|| kni_port_params_array[port_id]->lcore_tx >= RTE_MAX_LCORE) {
			printf("lcore_rx %u or lcore_tx %u ID could not "
				   "exceed the maximum %u\n",
				   kni_port_params_array[port_id]->lcore_rx,
				   kni_port_params_array[port_id]->lcore_tx,
				   (unsigned) RTE_MAX_LCORE);
			goto fail;
		}
		i = FLD_LCORE_TX + 1;
		for (j = 0; i < nb_token && j < KNI_MAX_KTHREAD; i++, j++)
			kni_port_params_array[port_id]->lcore_k[j] =
				(uint8_t) int_fld[i];
		kni_port_params_array[port_id]->nb_lcore_k = j;
	}
	print_config();

	return 0;

  fail:
	for (i = 0; i < RTE_MAX_ETHPORTS; i++) {
		if (kni_port_params_array[i]) {
			rte_free(kni_port_params_array[i]);
			kni_port_params_array[i] = NULL;
		}
	}

	return -1;
}

int kni_validate_parameters(uint32_t portmask)
{
	uint32_t i;

	if (!portmask) {
		printf("No port configured in port mask\n");
		return -1;
	}

	for (i = 0; i < RTE_MAX_ETHPORTS; i++) {
		if (((portmask & (1 << i)) && !kni_port_params_array[i]) ||
			(!(portmask & (1 << i)) && kni_port_params_array[i]))
			rte_exit(EXIT_FAILURE, "portmask is not consistent "
					 "to port ids specified in --config\n");
		//XXX we don't want to check that, the lcore_rx is set to 127
		/*
		   if (kni_port_params_array[i] && !rte_lcore_is_enabled((unsigned)
		   (kni_port_params_array[i]->lcore_rx)))
		   rte_exit(EXIT_FAILURE,
		   "lcore id %u for " "port %d receiving not enabled\n",
		   kni_port_params_array[i]->lcore_rx,
		   kni_port_params_array[i]->port_id);
		 */
		if (kni_port_params_array[i] && !rte_lcore_is_enabled((unsigned)
															  (kni_port_params_array[i]->lcore_tx)))
			rte_exit(EXIT_FAILURE,
					 "lcore id %u for "
					 "port %d transmitting not enabled\n",
					 kni_port_params_array[i]->lcore_tx,
					 kni_port_params_array[i]->port_id);

	}

	return 0;
}

/* Parse the arguments given in the command line of the application */
/* Initialize KNI subsystem */
void init_kni(void)
{
	unsigned int num_of_kni_ports = 0, i;
	struct kni_port_params **params = kni_port_params_array;

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
}

#if 0

/* Initialise a single port on an Ethernet device */
void init_kni_port(uint8_t port)
{
	int ret;

	/* Initialise device and RX/TX queues */
	RTE_LOG(INFO, KNI, "Initialising port %u ...\n", (unsigned) port);
	fflush(stdout);
	ret = rte_eth_dev_configure(port, 1, 1, &port_conf);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Could not configure port%u (%d)\n",
				 (unsigned) port, ret);

	ret = rte_eth_rx_queue_setup(port, 0, NB_RXD,
								 rte_eth_dev_socket_id(port), NULL,
								 pktmbuf_pool);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Could not setup up RX queue for "
				 "port%u (%d)\n", (unsigned) port, ret);

	ret = rte_eth_tx_queue_setup(port, 0, NB_TXD,
								 rte_eth_dev_socket_id(port), NULL);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Could not setup up TX queue for "
				 "port%u (%d)\n", (unsigned) port, ret);

	ret = rte_eth_dev_start(port);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Could not start port%u (%d)\n",
				 (unsigned) port, ret);

	if (promiscuous_on)
		rte_eth_promiscuous_enable(port);
}
#endif
/* Callback for request of changing MTU */
static int kni_change_mtu(uint8_t port_id, unsigned new_mtu)
{
	int ret;
	struct rte_eth_conf conf;

	if (port_id >= rte_eth_dev_count()) {
		RTE_LOG(ERR, KNI, "Invalid port id %d\n", port_id);
		return -EINVAL;
	}

	RTE_LOG(INFO, KNI, "Change MTU of port %d to %u\n", port_id, new_mtu);

	/* Stop specific port */
	rte_eth_dev_stop(port_id);

	memcpy(&conf, &port_conf, sizeof(conf));
	/* Set new MTU */
	if (new_mtu > ETHER_MAX_LEN)
		conf.rxmode.jumbo_frame = 1;
	else
		conf.rxmode.jumbo_frame = 0;

	/* mtu + length of header + length of FCS = max pkt length */
	conf.rxmode.max_rx_pkt_len = new_mtu + KNI_ENET_HEADER_SIZE +
		KNI_ENET_FCS_SIZE;
	ret = rte_eth_dev_configure(port_id, 1, 1, &conf);
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
static int kni_config_network_interface(uint8_t port_id, uint8_t if_up)
{
	int ret = 0;

	RTE_LOG(INFO, KNI, "----   kni_config_network_interface\n");
	if (port_id >= rte_eth_dev_count() || port_id >= RTE_MAX_ETHPORTS) {
		RTE_LOG(ERR, KNI, "Invalid port id %d\n", port_id);
		return -EINVAL;
	}

	RTE_LOG(INFO, KNI, "Configure network interface of %d %s\n",
			port_id, if_up ? "up" : "down");

	if (if_up != 0) {			/* Configure network interface up */
		rte_eth_dev_stop(port_id);
		ret = rte_eth_dev_start(port_id);
		kni_port_rdy[port_id]++;
	} else						/* Configure network interface down */
		rte_eth_dev_stop(port_id);

	if (ret < 0)
		RTE_LOG(ERR, KNI, "Failed to start port %d\n", port_id);

	return ret;
}

int kni_alloc(uint8_t port_id, struct rte_mempool *pktmbuf_pool)
{
	uint8_t i;
	struct rte_kni *kni;
	struct rte_kni_conf conf;
	struct kni_port_params **params = kni_port_params_array;

	if (port_id >= RTE_MAX_ETHPORTS || !params[port_id])
		return -1;

	params[port_id]->nb_kni = params[port_id]->nb_lcore_k ?
		params[port_id]->nb_lcore_k : 1;

	for (i = 0; i < params[port_id]->nb_kni; i++) {
		/* Clear conf at first */
		memset(&conf, 0, sizeof(conf));
		if (params[port_id]->nb_lcore_k) {
			snprintf(conf.name, RTE_KNI_NAMESIZE, "vEth%u_%u", port_id, i);
			conf.core_id = params[port_id]->lcore_k[i];
			conf.force_bind = 1;
		} else
			snprintf(conf.name, RTE_KNI_NAMESIZE, "vEth%u", port_id);
		conf.group_id = (uint16_t) port_id;
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
			rte_exit(EXIT_FAILURE, "Fail to create kni for "
					 "port: %d\n", port_id);
		params[port_id]->kni[i] = kni;
	}

	return 0;
}

int kni_free_kni(uint8_t port_id)
{
	uint8_t i;
	struct kni_port_params **p = kni_port_params_array;

	if (port_id >= RTE_MAX_ETHPORTS || !p[port_id])
		return -1;

	for (i = 0; i < p[i]->nb_kni; i++) {
		rte_kni_release(p[i]->kni[i]);
		p[i]->kni[i] = NULL;
	}
	rte_eth_dev_stop(port_id);

	return 0;
}

#if 0

/* Custom handling of signals to handle stats and kni processing */
static void signal_handler(int signum)
{
	/* When we receive a USR1 signal, print stats */
	if (signum == SIGUSR1) {
		print_stats();
	}

	/* When we receive a USR2 signal, reset stats */
	if (signum == SIGUSR2) {
		memset(&kni_stats, 0, sizeof(kni_stats));
		printf("\n**Statistics have been reset**\n");
		return;
	}

	/* When we receive a RTMIN or SIGINT signal, stop kni processing */
	if (signum == SIGRTMIN || signum == SIGINT) {
		printf("SIGRTMIN is received, and the KNI processing is "
			   "going to stop\n");
		rte_atomic32_inc(&kni_stop);
		return;
	}
}


/* Initialise ports/queues etc. and start main loop on each core */
int main(int argc, char **argv)
{
	int ret;
	uint8_t nb_sys_ports, port;
	unsigned i;

	/* Associate signal_hanlder function with USR signals */
	signal(SIGUSR1, signal_handler);
	signal(SIGUSR2, signal_handler);
	signal(SIGRTMIN, signal_handler);
	signal(SIGINT, signal_handler);

	/* Initialise EAL */
	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Could not initialise EAL (%d)\n", ret);
	argc -= ret;
	argv += ret;

	/* Parse application arguments (after the EAL ones) */
	ret = parse_args(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Could not parse input parameters\n");

	/* Create the mbuf pool */
	pktmbuf_pool = rte_mempool_create("mbuf_pool", NB_MBUF, MBUF_SZ,
									  MEMPOOL_CACHE_SZ,
									  sizeof(struct
											 rte_pktmbuf_pool_private),
									  rte_pktmbuf_pool_init, NULL,
									  rte_pktmbuf_init, NULL,
									  rte_socket_id(), 0);
	if (pktmbuf_pool == NULL) {
		rte_exit(EXIT_FAILURE, "Could not initialise mbuf pool\n");
		return -1;
	}

	/* Get number of ports found in scan */
	nb_sys_ports = rte_eth_dev_count();
	if (nb_sys_ports == 0)
		rte_exit(EXIT_FAILURE, "No supported Ethernet device found\n");

	/* Check if the configured port ID is valid */
	for (i = 0; i < RTE_MAX_ETHPORTS; i++)
		if (kni_port_params_array[i] && i >= nb_sys_ports)
			rte_exit(EXIT_FAILURE, "Configured invalid "
					 "port ID %u\n", i);

	/* Initialize KNI subsystem */
	init_kni();

	/* Initialise each port */
	for (port = 0; port < nb_sys_ports; port++) {
		/* Skip ports that are not enabled */
		if (!(ports_mask & (1 << port)))
			continue;
		init_port(port);

		if (port >= RTE_MAX_ETHPORTS)
			rte_exit(EXIT_FAILURE, "Can not use more than "
					 "%d ports for kni\n", RTE_MAX_ETHPORTS);

		kni_alloc(port);
	}
	check_all_ports_link_status(nb_sys_ports, ports_mask);

	/* Launch per-lcore function on every lcore */
	rte_eal_mp_remote_launch(main_loop, NULL, CALL_MASTER);
	RTE_LCORE_FOREACH_SLAVE(i) {
		if (rte_eal_wait_lcore(i) < 0)
			return -1;
	}

	/* Release resources */
	for (port = 0; port < nb_sys_ports; port++) {
		if (!(ports_mask & (1 << port)))
			continue;
		kni_free_kni(port);
	}
#ifdef RTE_LIBRTE_XEN_DOM0
	rte_kni_close();
#endif
	for (i = 0; i < RTE_MAX_ETHPORTS; i++)
		if (kni_port_params_array[i]) {
			rte_free(kni_port_params_array[i]);
			kni_port_params_array[i] = NULL;
		}

	return 0;
}

/* Display usage instructions */
static void print_usage(const char *prgname)
{
	RTE_LOG(INFO, KNI, "\nUsage: %s [EAL options] -- -p PORTMASK -P "
			"[--config (port,lcore_rx,lcore_tx,lcore_kthread...)"
			"[,(port,lcore_rx,lcore_tx,lcore_kthread...)]]\n"
			"    -p PORTMASK: hex bitmask of ports to use\n"
			"    -P : enable promiscuous mode\n"
			"    --config (port,lcore_rx,lcore_tx,lcore_kthread...): "
			"port and lcore configurations\n", prgname);
}

/* Convert string to unsigned number. 0 is returned if error occurs */
static uint32_t parse_unsigned(const char *portmask)
{
	char *end = NULL;
	unsigned long num;

	num = strtoul(portmask, &end, 16);
	if ((portmask[0] == '\0') || (end == NULL) || (*end != '\0'))
		return 0;

	return (uint32_t) num;
}
#endif
