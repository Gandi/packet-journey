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

#define _GNU_SOURCE
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <string.h>
#include <sys/queue.h>
#include <stdarg.h>
#include <errno.h>
#include <getopt.h>
#include <arpa/inet.h>
#include <signal.h>

#include <rte_common.h>
#include <rte_vect.h>
#include <rte_byteorder.h>
#include <rte_log.h>
#include <rte_memory.h>
#include <rte_malloc.h>
#include <rte_memcpy.h>
#include <rte_memzone.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_launch.h>
#include <rte_atomic.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_interrupts.h>
#include <rte_pci.h>
#include <rte_random.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_ring.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_string_fns.h>
#include <rte_spinlock.h>
#include <rte_kni.h>
#include <rte_atomic.h>
#include <rte_lpm.h>
#include <rte_lpm6.h>

#include <libneighbour.h>

#include "common.h"
#include "routing.h"
#include "control.h"
#include "kni.h"
#include "cmdline.h"

lookup_struct_t *ipv4_l3fwd_lookup_struct[NB_SOCKETS];
lookup6_struct_t *ipv6_l3fwd_lookup_struct[NB_SOCKETS];
neighbor_struct_t *neighbor4_struct[NB_SOCKETS];
neighbor_struct_t *neighbor6_struct[NB_SOCKETS];

void *control_handle[NB_SOCKETS];


#ifndef IPv6_BYTES
#define IPv6_BYTES_FMT "%02x%02x:%02x%02x:%02x%02x:%02x%02x:"\
                       "%02x%02x:%02x%02x:%02x%02x:%02x%02x"
#define IPv6_BYTES(addr) \
	addr[0],  addr[1], addr[2],  addr[3], \
	addr[4],  addr[5], addr[6],  addr[7], \
	addr[8],  addr[9], addr[10], addr[11],\
	addr[12], addr[13],addr[14], addr[15]
#endif

#define MAX_JUMBO_PKT_LEN  9600

#define IPV6_ADDR_LEN 16

#define MEMPOOL_CACHE_SIZE 256

#define MBUF_SIZE (MAX_PACKET_SZ + sizeof(struct rte_mbuf) + RTE_PKTMBUF_HEADROOM)

/*
 * This expression is used to calculate the number of mbufs needed depending on user input, taking
 *  into account memory for rx and tx hardware rings, cache per lcore and mtable per port per lcore.
 *  RTE_MAX is used to ensure that NB_MBUF never goes below a minimum value of 8192
 */

#define NB_MBUF RTE_MAX	(																	\
				(nb_ports*nb_rx_queue*RTE_TEST_RX_DESC_DEFAULT +							\
				nb_ports*nb_lcores*MAX_PKT_BURST +											\
				nb_ports*n_tx_queue*RTE_TEST_TX_DESC_DEFAULT +								\
				nb_lcores*MEMPOOL_CACHE_SIZE),												\
				(unsigned)8192)

#define BURST_TX_DRAIN_US 100	/* TX drain every ~100us */

/*
 * Try to avoid TX buffering if we have at least MAX_TX_BURST packets to send.
 */
#define	MAX_TX_BURST	(MAX_PKT_BURST / 2)


/* Configure how many packets ahead to prefetch, when reading packets */
#define PREFETCH_OFFSET	3

/*
 * Configurable number of RX/TX ring descriptors
 */
#define RTE_TEST_RX_DESC_DEFAULT 128
#define RTE_TEST_TX_DESC_DEFAULT 512
static uint16_t nb_rxd = RTE_TEST_RX_DESC_DEFAULT;
static uint16_t nb_txd = RTE_TEST_TX_DESC_DEFAULT;

/* ethernet addresses of ports */
struct ether_addr ports_eth_addr[RTE_MAX_ETHPORTS];

/* replace first 12B of the ethernet header. */
#define	MASK_ETH	0x3f

/* mask of enabled ports */
static uint32_t enabled_port_mask = 0;
static int promiscuous_on = 0; /**< Ports set in promiscuous mode off by default. */
static int numa_on = 1;	/**< NUMA is enabled by default. */
static char *callback_setup = NULL;
static const char *unixsock_path = "/tmp/rdpdk.sock";

struct mbuf_table {
	uint16_t len;
	struct rte_mbuf *m_table[MAX_PKT_BURST];
};

struct lcore_rx_queue {
	uint8_t port_id;
	uint8_t queue_id;
} __rte_cache_aligned;

#define MAX_RX_QUEUE_PER_LCORE 16
#define MAX_TX_QUEUE_PER_PORT 4
#define MAX_RX_QUEUE_PER_PORT 128

#define MAX_LCORE_PARAMS 1024
struct lcore_params {
	uint8_t port_id;
	uint8_t queue_id;
	uint8_t lcore_id;
} __rte_cache_aligned;

static struct lcore_params lcore_params_array[MAX_LCORE_PARAMS];
static struct lcore_params lcore_params_array_default[] = {
	{0, 0, 2},
	{0, 1, 2},
	{0, 2, 2},
	{1, 0, 2},
	{1, 1, 2},
	{1, 2, 2},
	{2, 0, 2},
	{3, 0, 3},
	{3, 1, 3},
};

static struct lcore_params *lcore_params = lcore_params_array_default;
static uint16_t nb_lcore_params = sizeof(lcore_params_array_default) /
	sizeof(lcore_params_array_default[0]);

static struct rte_eth_conf port_conf = {
	.rxmode = {
			   .mq_mode = ETH_MQ_RX_RSS,
			   .max_rx_pkt_len = ETHER_MAX_LEN,
			   .split_hdr_size = 0,
			   .header_split = 0,
							 /**< Header Split disabled */
			   .hw_ip_checksum = 0,
							 /**< IP checksum offload enabled */
			   .hw_vlan_filter = 0,
							 /**< VLAN filtering disabled */
			   .jumbo_frame = 0,
							 /**< Jumbo Frame Support disabled */
			   .hw_strip_crc = 0,
							 /**< CRC stripped by hardware */
			   },
	.rx_adv_conf = {
					.rss_conf = {
								 .rss_key = NULL,
								 .rss_hf = ETH_RSS_IP,
								 },
					},
	.txmode = {
			   .mq_mode = ETH_MQ_TX_NONE,
			   },
};

static struct rte_mempool *pktmbuf_pool[NB_SOCKETS];
static struct rte_mempool *knimbuf_pool[RTE_MAX_ETHPORTS];
struct nei_entry kni_neighbor[RTE_MAX_ETHPORTS];

#define IPV4_L3FWD_LPM_MAX_RULES         524288
#define IPV6_L3FWD_LPM_MAX_RULES         524288
#define IPV6_L3FWD_LPM_NUMBER_TBL8S (1 << 16)

struct lcore_conf {
	uint16_t n_rx_queue;
	struct lcore_rx_queue rx_queue_list[MAX_RX_QUEUE_PER_LCORE];
	uint16_t tx_queue_id[RTE_MAX_ETHPORTS];
	struct mbuf_table tx_mbufs[RTE_MAX_ETHPORTS];
	lookup_struct_t *ipv4_lookup_struct;
	lookup6_struct_t *ipv6_lookup_struct;
	neighbor_struct_t *neighbor4_struct;
	neighbor_struct_t *neighbor6_struct;
} __rte_cache_aligned;

struct lcore_stats stats[RTE_MAX_LCORE] __rte_cache_aligned;

static struct lcore_conf lcore_conf[RTE_MAX_LCORE];
static rte_spinlock_t spinlock_conf[RTE_MAX_ETHPORTS] =
	{ RTE_SPINLOCK_INITIALIZER };
static rte_atomic32_t main_loop_stop = RTE_ATOMIC32_INIT(0);

/* Send burst of packets on an output interface */
static inline int
send_burst(struct lcore_conf *qconf, uint16_t n, uint8_t port)
{
	struct rte_mbuf **m_table;
	int ret;
	uint16_t queueid;

	queueid = qconf->tx_queue_id[port];
	m_table = (struct rte_mbuf **) qconf->tx_mbufs[port].m_table;

	rte_spinlock_lock(&spinlock_conf[port]);
	ret = rte_eth_tx_burst(port, queueid, m_table, n);
	rte_spinlock_unlock(&spinlock_conf[port]);

	if (unlikely(ret < n)) {
		do {
			rte_pktmbuf_free(m_table[ret]);
		} while (++ret < n);
	}

	return 0;
}

static inline __attribute__ ((always_inline))
void
send_packetsx4(struct lcore_conf *qconf, uint8_t port,
			   struct rte_mbuf *m[], uint32_t num)
{
	uint32_t len, j, n;

	len = qconf->tx_mbufs[port].len;

	/*
	 * If TX buffer for that queue is empty, and we have enough packets,
	 * then send them straightway.
	 */
	if (num >= MAX_TX_BURST && len == 0) {
		rte_spinlock_lock(&spinlock_conf[port]);
		n = rte_eth_tx_burst(port, qconf->tx_queue_id[port], m, num);
		rte_spinlock_unlock(&spinlock_conf[port]);
		if (unlikely(n < num)) {
			do {
				rte_pktmbuf_free(m[n]);
			} while (++n < num);
		}
		return;
	}

	/*
	 * Put packets into TX buffer for that queue.
	 */

	n = len + num;
	n = (n > MAX_PKT_BURST) ? MAX_PKT_BURST - len : num;

	j = 0;
	switch (n % FWDSTEP) {
		while (j < n) {
	case 0:
			qconf->tx_mbufs[port].m_table[len + j] = m[j];
			j++;
	case 3:
			qconf->tx_mbufs[port].m_table[len + j] = m[j];
			j++;
	case 2:
			qconf->tx_mbufs[port].m_table[len + j] = m[j];
			j++;
	case 1:
			qconf->tx_mbufs[port].m_table[len + j] = m[j];
			j++;
		}
	}

	len += n;

	/* enough pkts to be sent */
	if (unlikely(len == MAX_PKT_BURST)) {

		send_burst(qconf, MAX_PKT_BURST, port);

		/* copy rest of the packets into the TX buffer. */
		len = num - n;
		j = 0;
		switch (len % FWDSTEP) {
			while (j < len) {
		case 0:
				qconf->tx_mbufs[port].m_table[j] = m[n + j];
				j++;
		case 3:
				qconf->tx_mbufs[port].m_table[j] = m[n + j];
				j++;
		case 2:
				qconf->tx_mbufs[port].m_table[j] = m[n + j];
				j++;
		case 1:
				qconf->tx_mbufs[port].m_table[j] = m[n + j];
				j++;
			}
		}
	}

	qconf->tx_mbufs[port].len = len;
}

static inline uint8_t
get_ipv4_dst_port(void *ipv4_hdr, uint8_t portid,
				  lookup_struct_t * ipv4_l3fwd_lookup_struct)
{
	uint8_t next_hop;

	return (uint8_t) ((rte_lpm_lookup(ipv4_l3fwd_lookup_struct,
									  rte_be_to_cpu_32(((struct ipv4_hdr *)
														ipv4_hdr)->dst_addr),
									  &next_hop) ==
					   0) ? next_hop : portid);
}

static inline uint8_t
get_ipv6_dst_port(void *ipv6_hdr, uint8_t portid,
				  lookup6_struct_t * ipv6_l3fwd_lookup_struct)
{
	uint8_t next_hop;
	return (uint8_t) ((rte_lpm6_lookup(ipv6_l3fwd_lookup_struct,
									   ((struct ipv6_hdr *)
										ipv6_hdr)->dst_addr,
									   &next_hop) ==
					   0) ? next_hop : portid);
}

#define	IPV4_MIN_VER_IHL	0x45
#define	IPV4_MAX_VER_IHL	0x4f
#define	IPV4_MAX_VER_IHL_DIFF	(IPV4_MAX_VER_IHL - IPV4_MIN_VER_IHL)

/* Minimum value of IPV4 total length (20B) in network byte order. */
#define	IPV4_MIN_LEN_BE	(sizeof(struct ipv4_hdr) << 8)

/*
 * From http://www.rfc-editor.org/rfc/rfc1812.txt section 5.2.2:
 * - The IP version number must be 4.
 * - The IP header length field must be large enough to hold the
 *    minimum length legal IP datagram (20 bytes = 5 words).
 * - The IP total length field must be large enough to hold the IP
 *   datagram header, whose length is specified in the IP header length
 *   field.
 * If we encounter invalid IPV4 packet, then set destination port for it
 * to BAD_PORT value.
 */
static inline __attribute__ ((always_inline))
void
rfc1812_process(struct ipv4_hdr *ipv4_hdr, uint16_t * dp, uint32_t flags)
{
	uint8_t ihl;

	if ((flags & PKT_RX_IPV4_HDR) != 0) {

		ihl = ipv4_hdr->version_ihl - IPV4_MIN_VER_IHL;

		ipv4_hdr->time_to_live--;
		ipv4_hdr->hdr_checksum++;

		if (ihl > IPV4_MAX_VER_IHL_DIFF ||
			((uint8_t) ipv4_hdr->total_length == 0 &&
			 ipv4_hdr->total_length < IPV4_MIN_LEN_BE)) {
			dp[0] = BAD_PORT;
		}
	}
}

static inline __attribute__ ((always_inline)) uint16_t
get_dst_port(const struct lcore_conf *qconf, struct rte_mbuf *pkt,
			 uint32_t dst_ipv4, struct nei_entry *kni_neighbor)
{
	uint8_t next_hop;
	struct ipv6_hdr *ipv6_hdr;
	struct ether_hdr *eth_hdr;

#ifdef RDPDK_QEMU
	eth_hdr = rte_pktmbuf_mtod(pkt, struct ether_hdr *);
	if (eth_hdr->ether_type == rte_be_to_cpu_16(ETHER_TYPE_IPv4)) {
#else
	if (pkt->ol_flags & PKT_RX_IPV4_HDR) {
#endif
		if (rte_lpm_lookup(qconf->ipv4_lookup_struct, dst_ipv4,
						   &next_hop) != 0)
			next_hop = 0;
#ifdef RDPDK_QEMU
	} else if (eth_hdr->ether_type == rte_be_to_cpu_16(ETHER_TYPE_IPv6)) {
#else
	} else if (pkt->ol_flags & PKT_RX_IPV6_HDR) {
		eth_hdr = rte_pktmbuf_mtod(pkt, struct ether_hdr *);
#endif
		ipv6_hdr = (struct ipv6_hdr *) (eth_hdr + 1);
		if (rte_lpm6_lookup(qconf->ipv6_lookup_struct,
							ipv6_hdr->dst_addr, &next_hop) != 0)
			next_hop = 0;
	} else {
		next_hop = kni_neighbor->port_id;
	}

	return next_hop;
}

static inline int
process_packet(struct lcore_conf *qconf, struct rte_mbuf *pkt,
			   uint16_t * dst_port, uint8_t portid, unsigned lcore_id)
{
	struct ether_hdr *eth_hdr;
	uint16_t dp;
	__m128i te, ve;
	struct ipv4_hdr *ipv4_hdr = 0;
	struct ipv6_hdr *ipv6_hdr;
	struct nei_entry *neighbor;

	eth_hdr = rte_pktmbuf_mtod(pkt, struct ether_hdr *);

#ifdef RDPDK_QEMU
	if (eth_hdr->ether_type == rte_be_to_cpu_16(ETHER_TYPE_IPv4)) {
#else
	if (pkt->ol_flags & PKT_RX_IPV4_HDR) {
#endif
		ipv4_hdr = (struct ipv4_hdr *) (eth_hdr + 1);

		dp = get_ipv4_dst_port(ipv4_hdr, 0, qconf->ipv4_lookup_struct);
		L3FWD_DEBUG_TRACE("process_packet4 res %d\n", dp);

		neighbor = &qconf->neighbor4_struct->entries.t4[dp].neighbor;
#ifdef RDPDK_QEMU
	} else if (eth_hdr->ether_type == rte_be_to_cpu_16(ETHER_TYPE_IPv6)) {
#else
	} else if (pkt->ol_flags & PKT_RX_IPV6_HDR) {
#endif
		ipv6_hdr = (struct ipv6_hdr *) (eth_hdr + 1);

		dp = get_ipv6_dst_port(ipv6_hdr, 0, qconf->ipv6_lookup_struct);
		neighbor = &qconf->neighbor6_struct->entries.t6[dp].neighbor;
		L3FWD_DEBUG_TRACE("process_packet6 res %d\n", dp);
	} else {
		L3FWD_DEBUG_TRACE("process_packet4 res kni\n");
		neighbor = &kni_neighbor[portid];
	}

	dst_port[0] = neighbor->port_id;

	if (likely(neighbor->action == NEI_ACTION_FWD)) {
		//TODO test it, may need to use eth = rte_pktmbuf_mtod(m, struct ether_hdr *); ether_addr_copy(from, eth->d_addr);
		te = _mm_load_si128((__m128i *) eth_hdr);
		ve = _mm_load_si128((__m128i *) & neighbor->nexthop_hwaddr);
		te = _mm_blend_epi16(te, ve, MASK_ETH);
		_mm_store_si128((__m128i *) eth_hdr, te);
		rfc1812_process(ipv4_hdr, dst_port, pkt->ol_flags);
		return 0;
		/* XXX: Need to rewrite source mac */
	} else if (neighbor->action == NEI_ACTION_KNI) {
		struct kni_port_params *p =
			kni_port_params_array[neighbor->port_id];
		uint32_t nb_kni = p->nb_kni;
		uint32_t k;
		int res;

		for (k = 0; k < nb_kni; k++) {
			res = rte_kni_tx_burst(p->kni[k], &pkt, 1);
			if (res == 1) {
				stats[lcore_id].nb_kni_tx++;
			} else {
				stats[lcore_id].nb_kni_tx++;
				kni_burst_free_mbufs(&pkt, 1);
			}
		}
		return 1;
	} else {
		return 0;
	}
}

/*
 * Read ol_flags and destination IPV4 addresses from 4 mbufs.
 */
static inline void
processx4_step1(struct rte_mbuf *pkt[FWDSTEP], __m128i * dip,
				uint32_t * flag)
{
	struct ipv4_hdr *ipv4_hdr;
	struct ether_hdr *eth_hdr;
	uint32_t x0, x1, x2, x3;

	eth_hdr = rte_pktmbuf_mtod(pkt[0], struct ether_hdr *);
	ipv4_hdr = (struct ipv4_hdr *) (eth_hdr + 1);
	x0 = ipv4_hdr->dst_addr;
	flag[0] = pkt[0]->ol_flags & PKT_RX_IPV4_HDR;

	eth_hdr = rte_pktmbuf_mtod(pkt[1], struct ether_hdr *);
	ipv4_hdr = (struct ipv4_hdr *) (eth_hdr + 1);
	x1 = ipv4_hdr->dst_addr;
	flag[0] &= pkt[1]->ol_flags;

	eth_hdr = rte_pktmbuf_mtod(pkt[2], struct ether_hdr *);
	ipv4_hdr = (struct ipv4_hdr *) (eth_hdr + 1);
	x2 = ipv4_hdr->dst_addr;
	flag[0] &= pkt[2]->ol_flags;

	eth_hdr = rte_pktmbuf_mtod(pkt[3], struct ether_hdr *);
	ipv4_hdr = (struct ipv4_hdr *) (eth_hdr + 1);
	x3 = ipv4_hdr->dst_addr;
	flag[0] &= pkt[3]->ol_flags;

	dip[0] = _mm_set_epi32(x3, x2, x1, x0);
}

/*
 * Lookup into LPM for neighbor id.
 * If lookup fails, drop.
 */
static inline void
processx4_step2(const struct lcore_conf *qconf, __m128i dip, uint32_t flag,
				struct rte_mbuf *pkt[FWDSTEP], uint16_t port_id,
				uint16_t neighbor[FWDSTEP])
{
	rte_xmm_t dst;
	const __m128i bswap_mask = _mm_set_epi8(12, 13, 14, 15, 8, 9, 10, 11,
											4, 5, 6, 7, 0, 1, 2, 3);
	struct nei_entry *neighbor_entry;

	/* Byte swap 4 IPV4 addresses. */
	/* XXX: Do we know this is V4 only yet? */
	dip = _mm_shuffle_epi8(dip, bswap_mask);

	/* if all 4 packets are IPV4. */
	if (likely(flag != 0)) {
		rte_lpm_lookupx4(qconf->ipv4_lookup_struct, dip, neighbor, 0);
		L3FWD_DEBUG_TRACE("lookpx4 res %d:%d:%d:%d\n", neighbor[0],
						  neighbor[1], neighbor[2], neighbor[3]);
	} else {
		dst.x = dip;
		neighbor_entry = &kni_neighbor[port_id];
		neighbor[0] =
			get_dst_port(qconf, pkt[0], dst.u32[0], neighbor_entry);
		neighbor[1] =
			get_dst_port(qconf, pkt[1], dst.u32[1], neighbor_entry);
		neighbor[2] =
			get_dst_port(qconf, pkt[2], dst.u32[2], neighbor_entry);
		neighbor[3] =
			get_dst_port(qconf, pkt[3], dst.u32[3], neighbor_entry);
		L3FWD_DEBUG_TRACE("get_dst_portx4 res %d:%d:%d:%d\n", neighbor[0],
						  neighbor[1], neighbor[2], neighbor[3]);
	}
}

static inline int
processx4_step_checkneighbor(struct lcore_conf *qconf,
							 struct rte_mbuf **pkt, uint16_t * dst_port,
							 __m128i * dip, uint32_t * flag, int nb_rx,
							 uint8_t portid, unsigned lcore_id)
{
	int i, j, num;
	uint32_t nb_kni, k;
	struct rte_mbuf *knimbuf[FWDSTEP];
	struct kni_port_params *p;
	uint8_t process;
	struct ether_hdr *eth_hdr;

	p = kni_port_params_array[portid];
	nb_kni = p->nb_kni;

	i = 0;
	j = 0;
	// duck device, first iteration use the switch dans go to nb_rx % FWDSTEP case
	switch (nb_rx % FWDSTEP) {
		while (j < nb_rx) {
			i = 0;				// reinit i here after the first duck device iteration

	case 0:
#ifdef RDPDK_QEMU
			eth_hdr = rte_pktmbuf_mtod(pkt[j], struct ether_hdr *);
			if (eth_hdr->ether_type == rte_be_to_cpu_16(ETHER_TYPE_IPv4)) {
#else
			if (pkt[j]->ol_flags & PKT_RX_IPV4_HDR) {
#endif
				process =
					!qconf->neighbor4_struct->entries.t4[dst_port[j]].
					neighbor.valid
					|| qconf->neighbor4_struct->entries.
					t4[dst_port[j]].neighbor.action == NEI_ACTION_KNI;

				L3FWD_DEBUG_TRACE("0: j %d process %d dst_port %d ipv4\n",
								  j, process, dst_port[j]);
#ifdef RDPDK_QEMU
			} else if (eth_hdr->ether_type ==
					   rte_be_to_cpu_16(ETHER_TYPE_IPv6)) {
#else
			} else if (pkt[j]->ol_flags & PKT_RX_IPV6_HDR) {
#endif
				process =
					!qconf->neighbor6_struct->entries.t6[dst_port[j]].
					neighbor.valid
					|| qconf->neighbor6_struct->entries.
					t6[dst_port[j]].neighbor.action == NEI_ACTION_KNI;
				L3FWD_DEBUG_TRACE("0: j %d process %d ipv6\n", j, process);
			} else {
				process = 1;
				eth_hdr = rte_pktmbuf_mtod(pkt[j], struct ether_hdr *);
				L3FWD_DEBUG_TRACE
					("0: j %d process %d olflags%lu eth_type %x\n", j,
					 process, pkt[j]->ol_flags, eth_hdr->ether_type);
			}

			if (unlikely(process)) {
				//no dest neighbor addr available, send it through the kni
				knimbuf[i++] = pkt[j];
				if (j != --nb_rx) {
					//we have more packets, deplace last one and its info
					pkt[j] = pkt[nb_rx];
					dst_port[j] = dst_port[nb_rx];
					dip[j] = dip[nb_rx];
					flag[j] = flag[nb_rx];
				}

				L3FWD_DEBUG_TRACE
					("0: j %d nb_rx %d i %d dst_port %d lcore_id %d\n", j,
					 nb_rx, i, dst_port[j], lcore_id);
			} else
				j++;
	case 3:
#ifdef RDPDK_QEMU
			eth_hdr = rte_pktmbuf_mtod(pkt[j], struct ether_hdr *);
			if (eth_hdr->ether_type == rte_be_to_cpu_16(ETHER_TYPE_IPv4)) {
#else
			if (pkt[j]->ol_flags & PKT_RX_IPV4_HDR) {
#endif
				process =
					!qconf->neighbor4_struct->entries.t4[dst_port[j]].
					neighbor.valid
					|| qconf->neighbor4_struct->entries.
					t4[dst_port[j]].neighbor.action == NEI_ACTION_KNI;
				L3FWD_DEBUG_TRACE("3: j %d process %d dst_port %d ipv4\n",
								  j, process, dst_port[j]);
#ifdef RDPDK_QEMU
			} else if (eth_hdr->ether_type ==
					   rte_be_to_cpu_16(ETHER_TYPE_IPv6)) {
#else
			} else if (pkt[j]->ol_flags & PKT_RX_IPV6_HDR) {
#endif
				process =
					!qconf->neighbor6_struct->entries.t6[dst_port[j]].
					neighbor.valid
					|| qconf->neighbor6_struct->entries.
					t6[dst_port[j]].neighbor.action == NEI_ACTION_KNI;
				L3FWD_DEBUG_TRACE("3: j %d process %d ipv6\n", j, process);
			} else {
				process = 1;
				eth_hdr = rte_pktmbuf_mtod(pkt[j], struct ether_hdr *);
				L3FWD_DEBUG_TRACE
					("3: j %d process %d olflags%lu eth_type %x\n", j,
					 process, pkt[j]->ol_flags, eth_hdr->ether_type);
			}

			if (unlikely(process)) {
				//no dest neighbor addr available, send it through the kni
				knimbuf[i++] = pkt[j];
				if (j != --nb_rx) {
					//we have more packets, deplace last one and its info
					pkt[j] = pkt[nb_rx];
					dst_port[j] = dst_port[nb_rx];
					dip[j] = dip[nb_rx];
					flag[j] = flag[nb_rx];
				}
				L3FWD_DEBUG_TRACE
					("3: j %d nb_rx %d i %d dst_port %d lcore_id %d\n", j,
					 nb_rx, i, dst_port[j], lcore_id);
			} else
				j++;
	case 2:
#ifdef RDPDK_QEMU
			eth_hdr = rte_pktmbuf_mtod(pkt[j], struct ether_hdr *);
			if (eth_hdr->ether_type == rte_be_to_cpu_16(ETHER_TYPE_IPv4)) {
#else
			if (pkt[j]->ol_flags & PKT_RX_IPV4_HDR) {
#endif
				process =
					!qconf->neighbor4_struct->entries.t4[dst_port[j]].
					neighbor.valid
					|| qconf->neighbor4_struct->entries.
					t4[dst_port[j]].neighbor.action == NEI_ACTION_KNI;
				L3FWD_DEBUG_TRACE("2: j %d process %d dst_port %d ipv4\n",
								  j, process, dst_port[j]);
#ifdef RDPDK_QEMU
			} else if (eth_hdr->ether_type ==
					   rte_be_to_cpu_16(ETHER_TYPE_IPv6)) {
#else
			} else if (pkt[j]->ol_flags & PKT_RX_IPV6_HDR) {
#endif
				process =
					!qconf->neighbor6_struct->entries.t6[dst_port[j]].
					neighbor.valid
					|| qconf->neighbor6_struct->entries.
					t6[dst_port[j]].neighbor.action == NEI_ACTION_KNI;
				L3FWD_DEBUG_TRACE("2: j %d process %d ipv6\n", j, process);
			} else {
				process = 1;
				eth_hdr = rte_pktmbuf_mtod(pkt[j], struct ether_hdr *);
				L3FWD_DEBUG_TRACE
					("2: j %d process %d olflags%lu eth_type %x\n", j,
					 process, pkt[j]->ol_flags, eth_hdr->ether_type);
			}

			if (unlikely(process)) {
				//no dest neighbor addr available, send it through the kni
				knimbuf[i++] = pkt[j];
				if (j != --nb_rx) {
					//we have more packets, deplace last one and its info
					pkt[j] = pkt[nb_rx];
					dst_port[j] = dst_port[nb_rx];
					dip[j] = dip[nb_rx];
					flag[j] = flag[nb_rx];
				}
				L3FWD_DEBUG_TRACE
					("2: j %d nb_rx %d i %d dst_port %d lcore_id %d\n", j,
					 nb_rx, i, dst_port[j], lcore_id);
			} else
				j++;
	case 1:
#ifdef RDPDK_QEMU
			eth_hdr = rte_pktmbuf_mtod(pkt[j], struct ether_hdr *);
			if (eth_hdr->ether_type == rte_be_to_cpu_16(ETHER_TYPE_IPv4)) {
#else
			if (pkt[j]->ol_flags & PKT_RX_IPV4_HDR) {
#endif
				process =
					!qconf->neighbor4_struct->entries.t4[dst_port[j]].
					neighbor.valid
					|| qconf->neighbor4_struct->entries.
					t4[dst_port[j]].neighbor.action == NEI_ACTION_KNI;
				L3FWD_DEBUG_TRACE("1: j %d process %d dst_port %d ipv4\n",
								  j, process, dst_port[j]);
#ifdef RDPDK_QEMU
			} else if (eth_hdr->ether_type ==
					   rte_be_to_cpu_16(ETHER_TYPE_IPv6)) {
#else
			} else if (pkt[j]->ol_flags & PKT_RX_IPV6_HDR) {
#endif
				process =
					!qconf->neighbor6_struct->entries.t6[dst_port[j]].
					neighbor.valid
					|| qconf->neighbor6_struct->entries.
					t6[dst_port[j]].neighbor.action == NEI_ACTION_KNI;
				L3FWD_DEBUG_TRACE("1: j %d process %d ipv6\n", j, process);
			} else {
				process = 1;
				eth_hdr = rte_pktmbuf_mtod(pkt[j], struct ether_hdr *);
				L3FWD_DEBUG_TRACE
					("1: j %d process %d olflags%lu eth_type %x\n", j,
					 process, pkt[j]->ol_flags, eth_hdr->ether_type);
			}

			if (unlikely(process)) {
				//no dest neighbor addr available, send it through the kni
				knimbuf[i++] = pkt[j];
				if (j != --nb_rx) {
					//we have more packets, deplace last one and its info
					pkt[j] = pkt[nb_rx];
					dst_port[j] = dst_port[nb_rx];
					dip[j] = dip[nb_rx];
					flag[j] = flag[nb_rx];
				}
				L3FWD_DEBUG_TRACE
					("1: j %d nb_rx %d i %d dst_port %d lcore_id %d\n", j,
					 nb_rx, i, dst_port[j], lcore_id);
			} else
				j++;
			if (i == 0)
				continue;
			for (k = 0; k < nb_kni; k++) {
				num = rte_kni_tx_burst(p->kni[k], knimbuf, i);
				stats[lcore_id].nb_kni_tx += nb_rx;
				rte_kni_handle_request(p->kni[k]);
				if (unlikely(num < i)) {
					/* Free mbufs not tx to kni interface */
					if (num > 0)
						kni_burst_free_mbufs(&knimbuf[num], i - num);
					else
						kni_burst_free_mbufs(&knimbuf[0], i);
				}
				L3FWD_DEBUG_TRACE
					("k %d nb_rx %d i %d num %d lcore_id %d\n", k, nb_rx,
					 i, num, lcore_id);
			}
		}						// while loop end
	}
	return nb_rx;
}

/*
 * Update source and destination MAC addresses in the ethernet header.
 * Perform RFC1812 checks and updates for IPV4 packets.
 */
static inline void
processx4_step3(struct lcore_conf *qconf, struct rte_mbuf *pkt[FWDSTEP],
				uint16_t dst_port[FWDSTEP])
{
	__m128i te[FWDSTEP];
	__m128i ve[FWDSTEP];
	__m128i *p[FWDSTEP];

	p[0] = (rte_pktmbuf_mtod(pkt[0], __m128i *));
	p[1] = (rte_pktmbuf_mtod(pkt[1], __m128i *));
	p[2] = (rte_pktmbuf_mtod(pkt[2], __m128i *));
	p[3] = (rte_pktmbuf_mtod(pkt[3], __m128i *));

	ve[0] =
		_mm_load_si128((__m128i *) & qconf->neighbor4_struct->
					   entries.t4[dst_port[0]].neighbor.nexthop_hwaddr);
	ve[1] =
		_mm_load_si128((__m128i *) & qconf->neighbor4_struct->
					   entries.t4[dst_port[1]].neighbor.nexthop_hwaddr);
	ve[2] =
		_mm_load_si128((__m128i *) & qconf->neighbor4_struct->
					   entries.t4[dst_port[2]].neighbor.nexthop_hwaddr);
	ve[3] =
		_mm_load_si128((__m128i *) & qconf->neighbor4_struct->
					   entries.t4[dst_port[3]].neighbor.nexthop_hwaddr);

	/* Pivot dst_port */
	dst_port[0] =
		qconf->neighbor4_struct->entries.t4[dst_port[0]].neighbor.port_id;
	dst_port[1] =
		qconf->neighbor4_struct->entries.t4[dst_port[1]].neighbor.port_id;
	dst_port[2] =
		qconf->neighbor4_struct->entries.t4[dst_port[2]].neighbor.port_id;
	dst_port[3] =
		qconf->neighbor4_struct->entries.t4[dst_port[3]].neighbor.port_id;

	te[0] = _mm_load_si128(p[0]);
	te[1] = _mm_load_si128(p[1]);
	te[2] = _mm_load_si128(p[2]);
	te[3] = _mm_load_si128(p[3]);

	/* Update first 12 bytes, keep rest bytes intact. */
	te[0] = _mm_blend_epi16(te[0], ve[0], MASK_ETH);
	te[1] = _mm_blend_epi16(te[1], ve[1], MASK_ETH);
	te[2] = _mm_blend_epi16(te[2], ve[2], MASK_ETH);
	te[3] = _mm_blend_epi16(te[3], ve[3], MASK_ETH);

	_mm_store_si128(p[0], te[0]);
	_mm_store_si128(p[1], te[1]);
	_mm_store_si128(p[2], te[2]);
	_mm_store_si128(p[3], te[3]);

	rfc1812_process((struct ipv4_hdr *) ((struct ether_hdr *) p[0] + 1),
					&dst_port[0], pkt[0]->ol_flags);
	rfc1812_process((struct ipv4_hdr *) ((struct ether_hdr *) p[1] + 1),
					&dst_port[1], pkt[1]->ol_flags);
	rfc1812_process((struct ipv4_hdr *) ((struct ether_hdr *) p[2] + 1),
					&dst_port[2], pkt[2]->ol_flags);
	rfc1812_process((struct ipv4_hdr *) ((struct ether_hdr *) p[3] + 1),
					&dst_port[3], pkt[3]->ol_flags);
}

#define	GRPSZ	(1 << FWDSTEP)
#define	GRPMSK	(GRPSZ - 1)

/*
 * Group consecutive packets with the same destination port in bursts of 4.
 * Suppose we have array of destionation ports:
 * dst_port[] = {a, b, c, d,, e, ... }
 * dp1 should contain: <a, b, c, d>, dp2: <b, c, d, e>.
 * We doing 4 comparisions at once and the result is 4 bit mask.
 * This mask is used as an index into prebuild array of pnum values.
 */
static inline uint16_t *port_groupx4(uint16_t pn[FWDSTEP + 1],
									 uint16_t * lp, __m128i dp1,
									 __m128i dp2)
{
	static const struct {
		uint64_t pnum;			/* prebuild 4 values for pnum[]. */
		int32_t idx;			/* index for new last updated elemnet. */
		uint16_t lpv;			/* add value to the last updated element. */
	} gptbl[GRPSZ] = {
		{
			/* 0: a != b, b != c, c != d, d != e */
		.pnum = UINT64_C(0x0001000100010001),.idx = 4,.lpv = 0,}, {
			/* 1: a == b, b != c, c != d, d != e */
		.pnum = UINT64_C(0x0001000100010002),.idx = 4,.lpv = 1,}, {
			/* 2: a != b, b == c, c != d, d != e */
		.pnum = UINT64_C(0x0001000100020001),.idx = 4,.lpv = 0,}, {
			/* 3: a == b, b == c, c != d, d != e */
		.pnum = UINT64_C(0x0001000100020003),.idx = 4,.lpv = 2,}, {
			/* 4: a != b, b != c, c == d, d != e */
		.pnum = UINT64_C(0x0001000200010001),.idx = 4,.lpv = 0,}, {
			/* 5: a == b, b != c, c == d, d != e */
		.pnum = UINT64_C(0x0001000200010002),.idx = 4,.lpv = 1,}, {
			/* 6: a != b, b == c, c == d, d != e */
		.pnum = UINT64_C(0x0001000200030001),.idx = 4,.lpv = 0,}, {
			/* 7: a == b, b == c, c == d, d != e */
		.pnum = UINT64_C(0x0001000200030004),.idx = 4,.lpv = 3,}, {
			/* 8: a != b, b != c, c != d, d == e */
		.pnum = UINT64_C(0x0002000100010001),.idx = 3,.lpv = 0,}, {
			/* 9: a == b, b != c, c != d, d == e */
		.pnum = UINT64_C(0x0002000100010002),.idx = 3,.lpv = 1,}, {
			/* 0xa: a != b, b == c, c != d, d == e */
		.pnum = UINT64_C(0x0002000100020001),.idx = 3,.lpv = 0,}, {
			/* 0xb: a == b, b == c, c != d, d == e */
		.pnum = UINT64_C(0x0002000100020003),.idx = 3,.lpv = 2,}, {
			/* 0xc: a != b, b != c, c == d, d == e */
		.pnum = UINT64_C(0x0002000300010001),.idx = 2,.lpv = 0,}, {
			/* 0xd: a == b, b != c, c == d, d == e */
		.pnum = UINT64_C(0x0002000300010002),.idx = 2,.lpv = 1,}, {
			/* 0xe: a != b, b == c, c == d, d == e */
		.pnum = UINT64_C(0x0002000300040001),.idx = 1,.lpv = 0,}, {
			/* 0xf: a == b, b == c, c == d, d == e */
	.pnum = UINT64_C(0x0002000300040005),.idx = 0,.lpv = 4,},};

	union {
		uint16_t u16[FWDSTEP + 1];
		uint64_t u64;
	} *pnum = (void *) pn;

	int32_t v;

	dp1 = _mm_cmpeq_epi16(dp1, dp2);
	dp1 = _mm_unpacklo_epi16(dp1, dp1);
	v = _mm_movemask_ps((__m128) dp1);

	/* update last port counter. */
	lp[0] += gptbl[v].lpv;

	/* if dest port value has changed. */
	if (v != GRPMSK) {
		lp = pnum->u16 + gptbl[v].idx;
		lp[0] = 1;
		pnum->u64 = gptbl[v].pnum;
	}

	return lp;
}

/* main processing loop */
static int main_loop(__rte_unused void *dummy)
{
	struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
	unsigned lcore_id;
	uint64_t prev_tsc, diff_tsc, cur_tsc;
	int i, j, nb_rx;
	uint8_t portid = 0, queueid;
	struct lcore_conf *qconf;
	const uint64_t drain_tsc = (rte_get_tsc_hz() + US_PER_S - 1) /
		US_PER_S * BURST_TX_DRAIN_US;
	int32_t k;
	int32_t f_stop;
	uint16_t dlp;
	uint16_t *lp;
	uint16_t dst_port[MAX_PKT_BURST];
	__m128i dip[MAX_PKT_BURST / FWDSTEP];
	uint32_t flag[MAX_PKT_BURST / FWDSTEP];
	uint16_t pnum[MAX_PKT_BURST + 1];

	prev_tsc = 0;

	lcore_id = rte_lcore_id();
	qconf = &lcore_conf[lcore_id];

	if (qconf->n_rx_queue == 0) {
		RTE_LOG(INFO, L3FWD, "lcore %u has nothing to do\n", lcore_id);
		return 0;
	}

	RTE_LOG(INFO, L3FWD, "entering main loop on lcore %u\n", lcore_id);

	for (i = 0; i < qconf->n_rx_queue; i++) {
		portid = qconf->rx_queue_list[i].port_id;
		stats[lcore_id].port_id = portid;
		queueid = qconf->rx_queue_list[i].queue_id;
		RTE_LOG(INFO, L3FWD, " -- lcoreid=%u portid=%hhu rxqueueid=%hhu\n",
				lcore_id, portid, queueid);
	}

	struct kni_port_params *p;
	p = kni_port_params_array[portid];
	int nb_kni = p->nb_kni;
	while (kni_port_rdy[portid] != nb_kni) {
		for (i = 0; i < nb_kni; i++) {
			rte_kni_handle_request(p->kni[i]);
		}
	}

	while (1) {
		f_stop = rte_atomic32_read(&main_loop_stop);
		if (f_stop)
			break;
		stats[lcore_id].nb_iteration_looped++;
		cur_tsc = rte_rdtsc();

		/*
		 * TX burst queue drain
		 */
		diff_tsc = cur_tsc - prev_tsc;
		if (unlikely(diff_tsc > drain_tsc)) {

			/*
			 * This could be optimized (use queueid instead of
			 * portid), but it is not called so often
			 */
			for (portid = 0; portid < RTE_MAX_ETHPORTS; portid++) {
				if (qconf->tx_mbufs[portid].len == 0)
					continue;
				send_burst(qconf, qconf->tx_mbufs[portid].len, portid);
				qconf->tx_mbufs[portid].len = 0;
			}

			prev_tsc = cur_tsc;
		}

		/*
		 * Read packet from RX queues
		 */
		for (i = 0; i < qconf->n_rx_queue; ++i) {
			portid = qconf->rx_queue_list[i].port_id;
			queueid = qconf->rx_queue_list[i].queue_id;
			nb_rx = rte_eth_rx_burst(portid, queueid, pkts_burst,
									 MAX_PKT_BURST);
			if (nb_rx == 0)
				continue;

			stats[lcore_id].nb_rx += nb_rx;

			/* Process up to last 3 packets one by one. */
			j = 0;
			L3FWD_DEBUG_TRACE("main_loop nb_rx %d before process_packet\n",
							  nb_rx);
			switch (nb_rx % FWDSTEP) {
			case 3:
				j = process_packet(qconf, pkts_burst[nb_rx - 3],
								   dst_port + nb_rx - 3, portid, lcore_id);
			case 2:
				j += process_packet(qconf, pkts_burst[nb_rx - 2],
									dst_port + nb_rx - 2, portid,
									lcore_id);
			case 1:
				j += process_packet(qconf, pkts_burst[nb_rx - 1],
									dst_port + nb_rx - 1, portid,
									lcore_id);
			}
			nb_rx -= j;
			L3FWD_DEBUG_TRACE("main_loop nb_rx %d after process_packet\n",
							  nb_rx);

			k = RTE_ALIGN_FLOOR(nb_rx, FWDSTEP);
			for (j = 0; j != k; j += FWDSTEP) {
				processx4_step1(&pkts_burst[j],
								&dip[j / FWDSTEP], &flag[j / FWDSTEP]);
			}

			k = RTE_ALIGN_FLOOR(nb_rx, FWDSTEP);
			for (j = 0; j != k; j += FWDSTEP) {
				processx4_step2(qconf, dip[j / FWDSTEP],
								flag[j / FWDSTEP],
								&pkts_burst[j], portid, &dst_port[j]);
			}

			//send through the kni packets which don't have an available neighbor
			if (likely(nb_rx))
				nb_rx =
					processx4_step_checkneighbor(qconf, pkts_burst,
												 dst_port, dip, flag,
												 nb_rx, portid, lcore_id);

			/*
			 * Finish packet processing and group consecutive
			 * packets with the same destination port.
			 */
			k = RTE_ALIGN_FLOOR(nb_rx, FWDSTEP);
			if (k != 0) {
				__m128i dp1, dp2;

				lp = pnum;
				lp[0] = 1;

				processx4_step3(qconf, pkts_burst, dst_port);

				/* dp1: <d[0], d[1], d[2], d[3], ... > */
				dp1 = _mm_loadu_si128((__m128i *) dst_port);

				for (j = FWDSTEP; j != k; j += FWDSTEP) {
					processx4_step3(qconf, &pkts_burst[j], &dst_port[j]);

					/*
					 * dp2:
					 * <d[j-3], d[j-2], d[j-1], d[j], ... >
					 */
					dp2 = _mm_loadu_si128((__m128i *)
										  & dst_port[j - FWDSTEP + 1]);
					lp = port_groupx4(&pnum[j - FWDSTEP], lp, dp1, dp2);

					/*
					 * dp1:
					 * <d[j], d[j+1], d[j+2], d[j+3], ... >
					 */
					dp1 = _mm_srli_si128(dp2,
										 (FWDSTEP - 1) *
										 sizeof(dst_port[0]));
				}

				/*
				 * dp2: <d[j-3], d[j-2], d[j-1], d[j-1], ... >
				 */
				dp2 = _mm_shufflelo_epi16(dp1, 0xf9);
				lp = port_groupx4(&pnum[j - FWDSTEP], lp, dp1, dp2);

				/*
				 * remove values added by the last repeated
				 * dst port.
				 */
				lp[0]--;
				dlp = dst_port[j - 1];
			} else {
				/* set dlp and lp to the never used values. */
				dlp = BAD_PORT - 1;
				lp = pnum + MAX_PKT_BURST;
			}

			/* Process up to last 3 packets one by one. */
			switch (nb_rx % FWDSTEP) {
			case 3:
				if (likely((dlp) == dst_port[j])) {
					lp[0]++;
				} else {
					dlp = dst_port[j];
					lp = &pnum[j];
					lp[0] = 1;
				}
				j++;
			case 2:
				if (likely((dlp) == dst_port[j])) {
					lp[0]++;
				} else {
					dlp = dst_port[j];
					lp = &pnum[j];
					lp[0] = 1;
				}
				j++;
			case 1:
				if (likely((dlp) == dst_port[j])) {
					lp[0]++;
				} else {
					lp = &pnum[j];
					lp[0] = 1;
				}
				j++;
			}

			/*
			 * Send packets out, through destination port.
			 * Consecuteve pacekts with the same destination port
			 * are already grouped together.
			 * If destination port for the packet equals BAD_PORT,
			 * then free the packet without sending it out.
			 */
			for (j = 0; j < nb_rx; j += k) {

				int32_t m;
				uint16_t pn;

				pn = dst_port[j];
				k = pnum[j];

				if (likely(pn != BAD_PORT)) {
					stats[lcore_id].nb_tx += k;
					send_packetsx4(qconf, pn, pkts_burst + j, k);
				} else {
					stats[lcore_id].nb_dropped += k;
					for (m = j; m != j + k; m++)
						rte_pktmbuf_free(pkts_burst[m]);
				}
			}
		}
	}
}

static int check_lcore_params(void)
{
	uint8_t queue, lcore;
	uint16_t i;
	int socketid;

	for (i = 0; i < nb_lcore_params; ++i) {
		queue = lcore_params[i].queue_id;
		if (queue >= MAX_RX_QUEUE_PER_PORT) {
			printf("invalid queue number: %hhu\n", queue);
			return -1;
		}
		lcore = lcore_params[i].lcore_id;
		if (!rte_lcore_is_enabled(lcore)) {
			printf("error: lcore %hhu is not enabled in lcore mask\n",
				   lcore);
			return -1;
		}
		if ((socketid = rte_lcore_to_socket_id(lcore) != 0) &&
			(numa_on == 0)) {
			printf("warning: lcore %hhu is on socket %d with numa off \n",
				   lcore, socketid);
		}
	}
	return 0;
}

static int check_port_config(const unsigned nb_ports)
{
	unsigned portid;
	uint16_t i;

	for (i = 0; i < nb_lcore_params; ++i) {
		portid = lcore_params[i].port_id;
		if ((enabled_port_mask & (1 << portid)) == 0) {
			printf("port %u is not enabled in port mask\n", portid);
			return -1;
		}
		if (portid >= nb_ports) {
			printf("port %u is not present on the board\n", portid);
			return -1;
		}
	}
	return 0;
}

static uint8_t get_port_n_rx_queues(const uint8_t port)
{
	int queue = -1;
	uint16_t i;

	for (i = 0; i < nb_lcore_params; ++i) {
		if (lcore_params[i].port_id == port
			&& lcore_params[i].queue_id > queue)
			queue = lcore_params[i].queue_id;
	}
	return (uint8_t) (++queue);
}

static int init_lcore_rx_queues(void)
{
	uint16_t i, nb_rx_queue;
	uint8_t lcore;

	for (i = 0; i < nb_lcore_params; ++i) {
		lcore = lcore_params[i].lcore_id;
		nb_rx_queue = lcore_conf[lcore].n_rx_queue;
		if (nb_rx_queue >= MAX_RX_QUEUE_PER_LCORE) {
			printf("error: too many queues (%u) for lcore: %u\n",
				   (unsigned) nb_rx_queue + 1, (unsigned) lcore);
			return -1;
		} else {
			lcore_conf[lcore].rx_queue_list[nb_rx_queue].port_id =
				lcore_params[i].port_id;
			lcore_conf[lcore].rx_queue_list[nb_rx_queue].queue_id =
				lcore_params[i].queue_id;
			lcore_conf[lcore].n_rx_queue++;
		}
	}
	return 0;
}

/* display usage */
static void print_usage(const char *prgname)
{
	printf("%s [EAL options]\n"
		   "  [--config (port,queue,lcore)[,(port,queue,lcore]]\n"
		   "  [--kniconfig (port,lcore_rx,lcore_tx,lcore_kthread...)]\n"
		   "  [--enable-jumbo [--max-pkt-len PKTLEN]]\n"
		   "  -p PORTMASK: hexadecimal bitmask of ports to configure\n"
		   "  -P : enable promiscuous mode\n"
		   "  --config (port,queue,lcore): rx queues configuration\n"
		   "  --callback-setup: script called when ifaces are set up\n"
		   "  --unixsock: specify the path for the cmdline unixsock (default: /tmp/rdpdk.sock)\n"
		   "  --no-numa: optional, disable numa awareness\n"
		   "  --enable-jumbo: enable jumbo frame"
		   " which max packet len is PKTLEN in decimal (64-9600)\n",
		   prgname);
}

static int parse_max_pkt_len(const char *pktlen)
{
	char *end = NULL;
	unsigned long len;

	/* parse decimal string */
	len = strtoul(pktlen, &end, 10);
	if ((pktlen[0] == '\0') || (end == NULL) || (*end != '\0'))
		return -1;

	if (len == 0)
		return -1;

	return len;
}

static int parse_portmask(const char *portmask)
{
	char *end = NULL;
	unsigned long pm;

	/* parse hexadecimal string */
	pm = strtoul(portmask, &end, 16);
	if ((portmask[0] == '\0') || (end == NULL) || (*end != '\0'))
		return -1;

	if (pm == 0)
		return -1;

	return pm;
}

static int parse_config(const char *q_arg)
{
	char s[256];
	const char *p, *p0 = q_arg;
	char *end;
	enum fieldnames {
		FLD_PORT = 0,
		FLD_QUEUE,
		FLD_LCORE,
		_NUM_FLD
	};
	unsigned long int_fld[_NUM_FLD];
	char *str_fld[_NUM_FLD];
	int i;
	unsigned size;

	nb_lcore_params = 0;

	while ((p = strchr(p0, '(')) != NULL) {
		++p;
		if ((p0 = strchr(p, ')')) == NULL)
			return -1;

		size = p0 - p;
		if (size >= sizeof(s))
			return -1;

		snprintf(s, sizeof(s), "%.*s", size, p);
		if (rte_strsplit(s, sizeof(s), str_fld, _NUM_FLD, ',') != _NUM_FLD)
			return -1;
		for (i = 0; i < _NUM_FLD; i++) {
			errno = 0;
			int_fld[i] = strtoul(str_fld[i], &end, 0);
			if (errno != 0 || end == str_fld[i] || int_fld[i] > 255)
				return -1;
		}
		if (nb_lcore_params >= MAX_LCORE_PARAMS) {
			printf("exceeded max number of lcore params: %hu\n",
				   nb_lcore_params);
			return -1;
		}
		lcore_params_array[nb_lcore_params].port_id =
			(uint8_t) int_fld[FLD_PORT];
		lcore_params_array[nb_lcore_params].queue_id =
			(uint8_t) int_fld[FLD_QUEUE];
		lcore_params_array[nb_lcore_params].lcore_id =
			(uint8_t) int_fld[FLD_LCORE];
		++nb_lcore_params;
	}
	lcore_params = lcore_params_array;
	return 0;
}

#define CMD_LINE_OPT_CONFIG "config"
#define CMD_LINE_OPT_KNICONFIG "kniconfig"
#define CMD_LINE_OPT_CALLBACK_SETUP "callback-setup"
#define CMD_LINE_OPT_NO_NUMA "no-numa"
#define CMD_LINE_OPT_ENABLE_JUMBO "enable-jumbo"
#define CMD_LINE_OPT_UNIXSOCK "unixsock"

/* Parse the argument given in the command line of the application */
static int parse_args(int argc, char **argv)
{
	int opt, ret;
	char **argvopt;
	int option_index;
	char *prgname = argv[0];
	static struct option lgopts[] = {
		{CMD_LINE_OPT_CONFIG, 1, 0, 0},
		{CMD_LINE_OPT_KNICONFIG, 1, 0, 0},
		{CMD_LINE_OPT_CALLBACK_SETUP, 1, 0, 0},
		{CMD_LINE_OPT_UNIXSOCK, 1, 0, 0},
		{CMD_LINE_OPT_NO_NUMA, 0, 0, 0},
		{CMD_LINE_OPT_ENABLE_JUMBO, 0, 0, 0},
		{NULL, 0, 0, 0}
	};

	argvopt = argv;

	while ((opt = getopt_long(argc, argvopt, "p:P",
							  lgopts, &option_index)) != EOF) {

		switch (opt) {
			/* portmask */
		case 'p':
			enabled_port_mask = parse_portmask(optarg);
			if (enabled_port_mask == 0) {
				printf("invalid portmask\n");
				print_usage(prgname);
				return -1;
			}
			break;
		case 'P':
			printf("Promiscuous mode selected\n");
			promiscuous_on = 1;
			break;

			/* long options */
		case 0:
			if (!strncmp(lgopts[option_index].name,
						 CMD_LINE_OPT_KNICONFIG,
						 sizeof(CMD_LINE_OPT_KNICONFIG))) {
				ret = kni_parse_config(optarg);
				if (ret) {
					printf("Invalid config\n");
					print_usage(prgname);
					return -1;
				}
			}

			if (!strncmp(lgopts[option_index].name, CMD_LINE_OPT_CONFIG,
						 sizeof(CMD_LINE_OPT_CONFIG))) {
				ret = parse_config(optarg);
				if (ret) {
					printf("invalid config\n");
					print_usage(prgname);
					return -1;
				}
			}

			if (!strncmp
				(lgopts[option_index].name, CMD_LINE_OPT_UNIXSOCK,
				 sizeof(CMD_LINE_OPT_UNIXSOCK))) {
				unixsock_path = optarg;
			}

			if (!strncmp
				(lgopts[option_index].name, CMD_LINE_OPT_CALLBACK_SETUP,
				 sizeof(CMD_LINE_OPT_CALLBACK_SETUP))) {
				callback_setup = optarg;
			}

			if (!strncmp(lgopts[option_index].name, CMD_LINE_OPT_NO_NUMA,
						 sizeof(CMD_LINE_OPT_NO_NUMA))) {
				printf("numa is disabled \n");
				numa_on = 0;
			}

			if (!strncmp
				(lgopts[option_index].name, CMD_LINE_OPT_ENABLE_JUMBO,
				 sizeof(CMD_LINE_OPT_ENABLE_JUMBO))) {
				struct option lenopts =
					{ "max-pkt-len", required_argument, 0, 0 };

				printf
					("jumbo frame is enabled - disabling simple TX path\n");
				port_conf.rxmode.jumbo_frame = 1;

				/* if no max-pkt-len set, use the default value ETHER_MAX_LEN */
				if (0 ==
					getopt_long(argc, argvopt, "", &lenopts,
								&option_index)) {
					ret = parse_max_pkt_len(optarg);
					if ((ret < 64) || (ret > MAX_JUMBO_PKT_LEN)) {
						printf("invalid packet length\n");
						print_usage(prgname);
						return -1;
					}
					port_conf.rxmode.max_rx_pkt_len = ret;
				}
				printf("set jumbo frame max packet length to %u\n",
					   (unsigned int) port_conf.rxmode.max_rx_pkt_len);
			}
			break;

		default:
			print_usage(prgname);
			return -1;
		}
	}

	if (optind >= 0)
		argv[optind - 1] = prgname;

	/* Check that options were parsed ok */
	if (kni_validate_parameters(enabled_port_mask) < 0) {
		print_usage(prgname);
		rte_exit(EXIT_FAILURE, "Invalid parameters\n");
	}
	ret = optind - 1;
	optind = 0;					/* reset getopt lib */
	return ret;
}

static void
print_ethaddr(const char *name, const struct ether_addr *eth_addr)
{
	char buf[ETHER_ADDR_FMT_SIZE];
	ether_format_addr(buf, ETHER_ADDR_FMT_SIZE, eth_addr);
	printf("%s%s\n", name, buf);
}

static void setup_lpm(int socketid)
{
	struct rte_lpm6_config config;
	char s[64];

	/* create the LPM table */
	snprintf(s, sizeof(s), "IPV4_L3FWD_LPM_%d", socketid);
	ipv4_l3fwd_lookup_struct[socketid] =
		rte_lpm_create(s, socketid, IPV4_L3FWD_LPM_MAX_RULES, 0);
	if (ipv4_l3fwd_lookup_struct[socketid] == NULL)
		rte_exit(EXIT_FAILURE, "Unable to create the l3fwd LPM table"
				 " on socket %d\n", socketid);

	/* create the LPM6 table */
	snprintf(s, sizeof(s), "IPV6_L3FWD_LPM_%d", socketid);

	config.max_rules = IPV6_L3FWD_LPM_MAX_RULES;
	config.number_tbl8s = IPV6_L3FWD_LPM_NUMBER_TBL8S;
	config.flags = 0;
	ipv6_l3fwd_lookup_struct[socketid] = rte_lpm6_create(s, socketid,
														 &config);
	if (ipv6_l3fwd_lookup_struct[socketid] == NULL)
		rte_exit(EXIT_FAILURE, "Unable to create the l3fwd LPM6 table"
				 " on socket %d\n", socketid);
}

static int init_mem(unsigned nb_mbuf)
{
	struct lcore_conf *qconf;
	int socketid;
	unsigned lcore_id;
	uint8_t port;
	char s[64];

	memset(&kni_neighbor, 0, sizeof(kni_neighbor));

	for (port = 0; port < RTE_MAX_ETHPORTS; port++) {
		kni_neighbor[port].in_use = 1;
		kni_neighbor[port].action = NEI_ACTION_KNI;
		kni_neighbor[port].port_id = port;
	}

	for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
		if (rte_lcore_is_enabled(lcore_id) == 0)
			continue;

		if (numa_on)
			socketid = rte_lcore_to_socket_id(lcore_id);
		else
			socketid = 0;

		if (socketid >= NB_SOCKETS) {
			rte_exit(EXIT_FAILURE,
					 "Socket %d of lcore %u is out of range %d\n",
					 socketid, lcore_id, NB_SOCKETS);
		}
		if (pktmbuf_pool[socketid] == NULL) {
			snprintf(s, sizeof(s), "mbuf_pool_%d", socketid);
			pktmbuf_pool[socketid] =
				rte_mempool_create(s, nb_mbuf, MBUF_SIZE,
								   MEMPOOL_CACHE_SIZE,
								   sizeof(struct rte_pktmbuf_pool_private),
								   rte_pktmbuf_pool_init, NULL,
								   rte_pktmbuf_init, NULL, socketid, 0);
			if (pktmbuf_pool[socketid] == NULL)
				rte_exit(EXIT_FAILURE,
						 "Cannot init mbuf pool on socket %d\n", socketid);
			else
				printf("Allocated mbuf pool on socket %d\n", socketid);

			setup_lpm(socketid);
		}
		if (knimbuf_pool[socketid] == NULL) {
			snprintf(s, sizeof(s), "knimbuf_pool_%d", socketid);
			knimbuf_pool[socketid] =
				rte_mempool_create(s, nb_mbuf, MBUF_SIZE,
								   MEMPOOL_CACHE_SIZE,
								   sizeof(struct rte_pktmbuf_pool_private),
								   rte_pktmbuf_pool_init, NULL,
								   rte_pktmbuf_init, NULL, socketid, 0);
			if (knimbuf_pool[socketid] == NULL)
				rte_exit(EXIT_FAILURE,
						 "Cannot init kni mbuf pool on socket %d\n",
						 socketid);
			else
				printf("Allocated kni mbuf pool on socket %d\n", socketid);
		}
		qconf = &lcore_conf[lcore_id];
		qconf->ipv4_lookup_struct = ipv4_l3fwd_lookup_struct[socketid];
		qconf->neighbor4_struct = neighbor4_struct[socketid];
		qconf->ipv6_lookup_struct = ipv6_l3fwd_lookup_struct[socketid];
		qconf->neighbor6_struct = neighbor6_struct[socketid];
	}
	return 0;
}

/* Check the link status of all ports in up to 9s, and print them finally */
static void
check_all_ports_link_status(uint8_t port_num, uint32_t port_mask)
{
#define CHECK_INTERVAL 100		/* 100ms */
#define MAX_CHECK_TIME 90		/* 9s (90 * 100ms) in total */
	uint8_t portid, count, all_ports_up, print_flag = 0;
	struct rte_eth_link link;

	printf("\nChecking link status\n");
	for (count = 0; count <= MAX_CHECK_TIME; count++) {
		all_ports_up = 1;
		for (portid = 0; portid < port_num; portid++) {
			if ((port_mask & (1 << portid)) == 0)
				continue;
			memset(&link, 0, sizeof(link));
			rte_eth_link_get_nowait(portid, &link);
			/* print link status if flag set */
			if (print_flag == 1) {
				if (link.link_status)
					printf("Port %d Link Up - speed %u "
						   "Mbps - %s\n", (uint8_t) portid,
						   (unsigned) link.link_speed,
						   (link.link_duplex == ETH_LINK_FULL_DUPLEX) ?
						   ("full-duplex") : ("half-duplex\n"));
				else
					printf("Port %d Link Down\n", (uint8_t) portid);
				continue;
			}
			/* clear all_ports_up flag if any link down */
			if (link.link_status == 0) {
				all_ports_up = 0;
				break;
			}
		}
		/* after finally printing all link status, get out */
		if (print_flag == 1)
			break;

		if (all_ports_up == 0) {
			printf(".");
			fflush(stdout);
			rte_delay_ms(CHECK_INTERVAL);
		}

		/* set the print_flag if all ports up or timeout */
		if (all_ports_up == 1 || count == (MAX_CHECK_TIME - 1)) {
			print_flag = 1;
			printf("done\n");
		}
	}
}

static void init_port(uint8_t portid, uint8_t nb_lcores, unsigned nb_ports,
					  struct rte_eth_dev_info *dev_info)
{
	struct rte_eth_txconf *txconf;
	struct lcore_conf *qconf;
	uint32_t n_tx_queue;
	uint8_t nb_rx_queue, socketid;
	int ret;
	uint16_t queueid;
	unsigned lcore_id;

	/* skip ports that are not enabled */
	if ((enabled_port_mask & (1 << portid)) == 0) {
		printf("\nSkipping disabled port %d\n", portid);
		return;
	}

	/* init port */
	printf("Initializing port %d ...\n", portid);

	nb_rx_queue = get_port_n_rx_queues(portid);
	n_tx_queue = nb_lcores;
	if (n_tx_queue > MAX_TX_QUEUE_PER_PORT)
		n_tx_queue = MAX_TX_QUEUE_PER_PORT;
	printf("Creating queues: nb_rxq=%d nb_txq=%u...\n",
		   nb_rx_queue, (unsigned) n_tx_queue);

	ret = rte_eth_dev_configure(portid, nb_rx_queue,
								(uint16_t) n_tx_queue, &port_conf);
	if (ret < 0)
		rte_exit(EXIT_FAILURE,
				 "Cannot configure device: err=%d, port=%d\n", ret,
				 portid);

	/*
	 * prepare dst and src MACs for each port.
	 */
	rte_eth_macaddr_get(portid, &ports_eth_addr[portid]);
	print_ethaddr(" Address:", &ports_eth_addr[portid]);

	/* init memory */
	ret = init_mem(NB_MBUF);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "init_mem failed\n");

	/* init one TX queue per couple (lcore,port) */
	queueid = 0;
	for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
		if (rte_lcore_is_enabled(lcore_id) == 0) {
			continue;
		}

		if (numa_on)
			socketid = (uint8_t) rte_lcore_to_socket_id(lcore_id);
		else
			socketid = 0;

		printf("txq=%u,%d,%d\n", lcore_id, queueid, socketid);

		rte_eth_dev_info_get(portid, dev_info);
		txconf = &dev_info->default_txconf;
		txconf->txq_flags = ETH_TXQ_FLAGS_NOOFFLOADS;
		if (port_conf.rxmode.jumbo_frame)
			txconf->txq_flags = 0;
		printf("coucou port=%d queueid=%d nb_txd=%d core=%d\n", portid,
			   queueid, nb_txd, lcore_id);
		ret =
			rte_eth_tx_queue_setup(portid, queueid, nb_txd, socketid,
								   txconf);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "rte_eth_tx_queue_setup: err=%d, "
					 "port=%d\n", ret, portid);

		qconf = &lcore_conf[lcore_id];
		qconf->tx_queue_id[portid] = queueid;
		queueid++;
	}
}

static int alloc_kni_ports(void)
{
	uint8_t nb_sys_ports, port;
	/* Get number of ports found in scan */
	nb_sys_ports = rte_eth_dev_count();
	if (nb_sys_ports == 0)
		rte_exit(EXIT_FAILURE, "No supported Ethernet device found\n");

	/* Check if the configured port ID is valid */
	for (port = 0; port < RTE_MAX_ETHPORTS; port++)
		if (kni_port_params_array[port] && port >= nb_sys_ports)
			rte_exit(EXIT_FAILURE, "Configured invalid "
					 "port ID %u\n", port);

	/* Initialise each port */
	for (port = 0; port < nb_sys_ports; port++) {
		/* Skip ports that are not enabled */
		if (!(enabled_port_mask & (1 << port)))
			continue;
		if (!kni_port_params_array[port])
			continue;

		int lcore_id = kni_port_params_array[port]->lcore_k[0];
		int socketid = (uint8_t) rte_lcore_to_socket_id(lcore_id);
		//XXX we use another mbuf_pool here, its for incoming packets
		if (kni_alloc(port, knimbuf_pool[socketid])) {
			rte_exit(EXIT_FAILURE, "failed to allocate kni");
		}
	}
	return 0;
}

static void
signal_handler(int signum, __rte_unused siginfo_t * si,
			   __rte_unused void *unused)
{
	/* When we receive a RTMIN or SIGINT signal, stop kni processing */
	if (signum == SIGRTMIN || signum == SIGINT) {
		printf("SIG is received, and the KNI processing is "
			   "going to stop\n");
		kni_stop_loop();
		rte_atomic32_inc(&main_loop_stop);
		rdpdk_cmdline_stop();
		//FIXME make a loop
		control_stop(control_handle[0]);
		return;
	}
}

int main(int argc, char **argv)
{
	struct lcore_conf *qconf;
	struct rte_eth_dev_info dev_info;
	int ret;
	unsigned nb_ports;
	uint16_t queueid;
	unsigned lcore_id;
	uint32_t nb_lcores;
	uint8_t portid, queue, socketid;
	pthread_t control_tid;
	char thread_name[16];
	struct sigaction sa;

	sa.sa_flags = 0;
	sigemptyset(&sa.sa_mask);
	sa.sa_sigaction = signal_handler;
	if (sigaction(SIGINT, &sa, NULL) == -1) {
		rte_exit(EXIT_FAILURE, "failed to set sigaction");
	}

	/* Sanitize lcore_conf */
	for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
		qconf = &lcore_conf[lcore_id];
		qconf->ipv4_lookup_struct = NULL;
		qconf->ipv6_lookup_struct = NULL;
		qconf->neighbor4_struct = NULL;
		qconf->neighbor6_struct = NULL;
	}

	/* init EAL */
	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid EAL parameters\n");
	argc -= ret;
	argv += ret;

	/* parse application arguments (after the EAL ones) */
	ret = parse_args(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid L3FWD parameters\n");

	if (check_lcore_params() < 0)
		rte_exit(EXIT_FAILURE, "check_lcore_params failed\n");

	ret = init_lcore_rx_queues();
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "init_lcore_rx_queues failed\n");

	nb_ports = rte_eth_dev_count();
	if (nb_ports > RTE_MAX_ETHPORTS)
		nb_ports = RTE_MAX_ETHPORTS;

	if (check_port_config(nb_ports) < 0)
		rte_exit(EXIT_FAILURE, "check_port_config failed\n");

	nb_lcores = rte_lcore_count();


	int ctrlsock = 0;
	if (numa_on)
		ctrlsock = 0;			//FIXME set the correct value

	//XXX ensure that control_main doesn't run on a core binded by dpdk lcores
	//TODO spawn one thread per socketid
	control_handle[0] = control_init(ctrlsock);

	/* Initialize KNI subsystem */
	init_kni();

	/* initialize all ports */
	for (portid = 0; portid < nb_ports; portid++) {
		init_port(portid, nb_lcores, nb_ports, &dev_info);
	}

	for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
		if (rte_lcore_is_enabled(lcore_id) == 0)
			continue;
		qconf = &lcore_conf[lcore_id];

		printf("\nInitializing rx queues on lcore %u ...\n", lcore_id);

		if (numa_on)
			socketid = (uint8_t) rte_lcore_to_socket_id(lcore_id);
		else
			socketid = 0;

		/* init RX queues */
		for (queue = 0; queue < qconf->n_rx_queue; ++queue) {
			portid = qconf->rx_queue_list[queue].port_id;
			queueid = qconf->rx_queue_list[queue].queue_id;

			printf("rxq=%d,%d,%d\n", portid, queueid, socketid);

			ret = rte_eth_rx_queue_setup(portid, queueid, nb_rxd,
										 socketid,
										 NULL, pktmbuf_pool[socketid]);
			if (ret < 0)
				rte_exit(EXIT_FAILURE, "rte_eth_rx_queue_setup: err=%d,"
						 "port=%d\n", ret, portid);
		}
	}

	alloc_kni_ports();
	printf("\n");

	/* start ports */
	for (portid = 0; portid < nb_ports; portid++) {
		if ((enabled_port_mask & (1 << portid)) == 0) {
			continue;
		}
		/* Start device */
		ret = rte_eth_dev_start(portid);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "rte_eth_dev_start: err=%d, port=%d\n",
					 ret, portid);

		/*
		 * If enabled, put device in promiscuous mode.
		 * This allows IO forwarding mode to forward packets
		 * to itself through 2 cross-connected  ports of the
		 * target machine.
		 */
		if (promiscuous_on)
			rte_eth_promiscuous_enable(portid);
	}

	check_all_ports_link_status((uint8_t) nb_ports, enabled_port_mask);

	pthread_create(&control_tid, NULL, (void *) control_main,
				   control_handle[0]);
	snprintf(thread_name, 16, "control-%d", 0);
	pthread_setname_np(control_tid, thread_name);

	int sock = rdpdk_cmdline_init(unixsock_path);
	rdpdk_cmdline_launch(sock);

	/* launch per-lcore init on every lcore */
	//rte_eal_mp_remote_launch(main_loop, NULL, SKIP_MASTER);
	rte_eal_remote_launch(main_loop, NULL, 1);
	rte_eal_remote_launch(main_loop, NULL, 2);

	if ((ret = control_callback_setup(callback_setup))) {
		perror("control_callback_setup failure with: ");
		rte_exit(EXIT_FAILURE,
				 "control callback setup returned error: err=%d,", ret);
	}

	printf("launching kni thread\n");
	rte_eal_remote_launch(kni_main_loop, NULL, 3);
	RTE_LCORE_FOREACH_SLAVE(lcore_id) {
		snprintf(thread_name, 16, "lcore-slave-%d", lcore_id);
		pthread_setname_np(lcore_config[lcore_id].thread_id, thread_name);
	}
	snprintf(thread_name, 16, "lcore-master");
	pthread_setname_np(pthread_self(), thread_name);
	pthread_join(control_tid, NULL);
	RTE_LCORE_FOREACH_SLAVE(lcore_id) {
		printf("waiting %d\n", lcore_id);
		if (rte_eal_wait_lcore(lcore_id) < 0)
			return -1;
	}
	printf("rte_eal_wait_lcore finished\n");
	/* start ports */
	for (portid = 0; portid < nb_ports; portid++) {
		if ((enabled_port_mask & (1 << portid)) == 0) {
			continue;
		}
		printf("freeing kniportid %d\n", portid);
		kni_free_kni(portid);
		rte_eth_dev_stop(portid);
	}
	rdpdk_cmdline_terminate(sock, unixsock_path);
	control_terminate(control_handle[0]);
	return 0;
}
