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
#include <arpa/inet.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <unistd.h>

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
#include <rte_kni.h>
#include <rte_atomic.h>
#include <rte_lpm.h>
#include <rte_lpm6.h>
#include <cmdline_parse.h>
#include <cmdline_parse_ipaddr.h>
#include <rte_acl.h>

#include <libneighbour.h>
#include <libnetlink.h>

#include "common.h"
#include "routing.h"
#include "control.h"
#include "kni.h"
#include "cmdline.h"
#include "acl.h"
#include "config.h"

/**
 * ICMPv6 Header
 */
struct icmpv6_hdr {
	uint8_t icmp_type;   /* ICMPv6 packet type. */
	uint8_t icmp_code;   /* ICMPv6 packet code. */
	uint16_t icmp_cksum; /* ICMPv6 packet checksum. */
	uint32_t icmp_body;  /* ICMPv6 packet body. */
} __attribute__((__packed__));

lookup_struct_t* ipv4_pktj_lookup_struct[NB_SOCKETS];
lookup6_struct_t* ipv6_pktj_lookup_struct[NB_SOCKETS];
neighbor_struct_t* neighbor4_struct[NB_SOCKETS];
neighbor_struct_t* neighbor6_struct[NB_SOCKETS];

#define RATE_LIMITED UINT8_MAX
uint8_t rlimit4_lookup_table[NB_SOCKETS]
			    [MAX_RLIMIT_RANGE_NET] __rte_cache_aligned;
struct rlimit6_data rlimit6_lookup_table[NB_SOCKETS][NEI_NUM_ENTRIES];
uint32_t rlimit4_max[NB_SOCKETS][MAX_RLIMIT_RANGE]
		    [MAX_RLIMIT_RANGE_HOST] __rte_cache_aligned;
uint32_t rlimit6_max[NB_SOCKETS][NEI_NUM_ENTRIES] __rte_cache_aligned;

struct control_params_t {
	void* addr;
	int lcore_id;
};
struct control_params_t control_handle4[NB_SOCKETS];
struct control_params_t control_handle6[NB_SOCKETS];

#ifdef RTE_NEXT_ABI
#define PKTJ_PKT_TYPE(m) (m)->packet_type
#define PKTJ_IP_MASK (RTE_PTYPE_L3_IPV4 | RTE_PTYPE_L3_IPV6)
#define PKTJ_IPV4_MASK RTE_PTYPE_L3_IPV4
#define PKTJ_IPV6_MASK RTE_PTYPE_L3_IPV6
#else
#define PKTJ_PKT_TYPE(m) (m)->ol_flags
#define PKTJ_IP_MASK (PKT_RX_IPV4_HDR | PKT_RX_IPV6_HDR)
#define PKTJ_IPV4_MASK PKT_RX_IPV4_HDR
#define PKTJ_IPV6_MASK PKT_RX_IPV6_HDR
#endif

#define ETHER_TYPE_BE_IPv4 0x0008
#define ETHER_TYPE_BE_IPv6 0xDD86
#define ETHER_TYPE_BE_VLAN 0x0081
#define ETHER_TYPE_BE_ARP 0x0608

#ifdef RTE_NEXT_ABI
#define PKTJ_TEST_IPV4_HDR(m) RTE_ETH_IS_IPV4_HDR((m)->packet_type)
#define PKTJ_TEST_IPV6_HDR(m) RTE_ETH_IS_IPV6_HDR((m)->packet_type)
#define PKTJ_TEST_ARP_HDR(m) ((m)->packet_type & RTE_PTYPE_L2_ETHER_ARP)
#else
#define PKTJ_TEST_IPV4_HDR(m) (m)->ol_flags& PKT_RX_IPV4_HDR
#define PKTJ_TEST_IPV6_HDR(m) (m)->ol_flags& PKT_RX_IPV6_HDR
#define PKTJ_TEST_ARP_HDR(m)                                      \
	((rte_pktmbuf_mtod((m), struct ether_hdr*)->ether_type) & \
	 ETHER_TYPE_BE_ARP)
#endif

#ifdef PKTJ_QEMU
#define pktj_mm_load_si128 _mm_loadu_si128
#define pktj_mm_store_si128 _mm_storeu_si128

uint16_t __real_virtio_recv_mergeable_pkts(void* rx_queue,
					   struct rte_mbuf** rx_pkts,
					   uint16_t nb_pkts);
uint16_t __wrap_virtio_recv_mergeable_pkts(void* rx_queue,
					   struct rte_mbuf** rx_pkts,
					   uint16_t nb_pkts);
uint16_t
__wrap_virtio_recv_mergeable_pkts(void* rx_queue,
				  struct rte_mbuf** rx_pkts,
				  uint16_t nb_pkts)
{
	uint16_t res =
	    __real_virtio_recv_mergeable_pkts(rx_queue, rx_pkts, nb_pkts);
	uint16_t i;

	for (i = 0; i < res; i++) {
		if ((rte_pktmbuf_mtod(rx_pkts[i], struct ether_hdr*)
			 ->ether_type) == ETHER_TYPE_BE_IPv4) {
#ifdef RTE_NEXT_ABI
			rx_pkts[i]->packet_type = PKTJ_IPV4_MASK;
#else
			rx_pkts[i]->ol_flags = PKT_RX_IPV4_HDR;
#endif
		} else if ((rte_pktmbuf_mtod(rx_pkts[i], struct ether_hdr*)
				->ether_type) == ETHER_TYPE_BE_IPv6) {
#ifdef RTE_NEXT_ABI
			rx_pkts[i]->packet_type = PKTJ_IPV6_MASK;
#else
			rx_pkts[i]->ol_flags = PKT_RX_IPV6_HDR;
#endif
		} else if ((rte_pktmbuf_mtod(rx_pkts[i], struct ether_hdr*)
				->ether_type) == ETHER_TYPE_BE_ARP) {
#ifdef RTE_NEXT_ABI
			rx_pkts[i]->packet_type = RTE_PTYPE_L2_ETHER_ARP;
#endif
		}
	}

	return res;
}

#else
#define pktj_mm_load_si128 _mm_load_si128
#define pktj_mm_store_si128 _mm_store_si128
#endif

#ifndef IPv6_BYTES
#define IPv6_BYTES_FMT                         \
	"%02x%02x:%02x%02x:%02x%02x:%02x%02x:" \
	"%02x%02x:%02x%02x:%02x%02x:%02x%02x"
#define IPv6_BYTES(addr)                                                       \
	addr[0], addr[1], addr[2], addr[3], addr[4], addr[5], addr[6],         \
	    addr[7], addr[8], addr[9], addr[10], addr[11], addr[12], addr[13], \
	    addr[14], addr[15]
#endif

#define MEMPOOL_CACHE_SIZE 256

/*
 * This expression is used to calculate the number of mbufs needed depending on
 * user input, taking
 *  into account memory for rx and tx hardware rings, cache per lcore and mtable
 * per port per lcore.
 *  RTE_MAX is used to ensure that NB_MBUF never goes below a minimum value of
 * 8192
 */

#define NB_MBUF                                                      \
	RTE_MAX((nb_ports * nb_rx_queue * RTE_TEST_RX_DESC_DEFAULT + \
		 nb_ports * nb_lcores * MAX_PKT_BURST +              \
		 nb_ports * nb_tx_queue * RTE_TEST_TX_DESC_DEFAULT + \
		 nb_lcores * MEMPOOL_CACHE_SIZE),                    \
		(unsigned)8192)

#define BURST_TX_DRAIN_US 100 /* TX drain every ~100us */

/*
 * Try to avoid TX buffering if we have at least MAX_TX_BURST packets to send.
 */
#define MAX_TX_BURST (MAX_PKT_BURST / 2)

/* Configure how many packets ahead to prefetch, when reading packets */
#define PREFETCH_OFFSET 3

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
#define MASK_ETH 0x3f

static struct rte_mempool* pktmbuf_pool[NB_SOCKETS];
static uint64_t glob_tsc[RTE_MAX_LCORE];
static struct rte_mempool* knimbuf_pool[RTE_MAX_ETHPORTS];
struct nei_entry kni_neighbor[RTE_MAX_ETHPORTS];
static rte_spinlock_t spinlock_kni[RTE_MAX_ETHPORTS] = {
    RTE_SPINLOCK_INITIALIZER};

#define IPV4_L3FWD_LPM_MAX_RULES (1 << 20)  // 1048576
#define IPV6_L3FWD_LPM_MAX_RULES (1 << 19)  // 524288
#define IPV6_L3FWD_LPM_NUMBER_TBL8S (1 << 16)

struct lcore_stats stats[RTE_MAX_LCORE];

struct lcore_conf lcore_conf[RTE_MAX_LCORE];
static rte_atomic32_t main_loop_stop = RTE_ATOMIC32_INIT(0);

static void
print_ethaddr(const char* name, const struct ether_addr* eth_addr)
{
	char buf[ETHER_ADDR_FMT_SIZE];
	ether_format_addr(buf, ETHER_ADDR_FMT_SIZE, eth_addr);
	printf("%s%s\n", name, buf);
}

/* Send burst of packets on an output interface */
static inline int
send_burst(struct lcore_conf* qconf, uint16_t n, uint8_t port)
{
	struct rte_mbuf** m_table;
	int ret;
	uint16_t queueid;

	queueid = qconf->tx_queue_id[port];
	m_table = (struct rte_mbuf**)qconf->tx_mbufs[port].m_table;

	ret = rte_eth_tx_burst(port, queueid, m_table, n);
	if (unlikely(ret < n)) {
		do {
			rte_pktmbuf_free(m_table[ret]);
		} while (++ret < n);
	}

	return 0;
}

static inline __attribute__((always_inline)) void
send_packetsx4(struct lcore_conf* qconf,
	       uint8_t port,
	       struct rte_mbuf* m[],
	       uint32_t num)
{
	uint32_t len, j, n;

	len = qconf->tx_mbufs[port].len;

	/*
	 * If TX buffer for that queue is empty, and we have enough packets,
	 * then send them straightway.
	 */
	if (num >= MAX_TX_BURST && len == 0) {
		n = rte_eth_tx_burst(port, qconf->tx_queue_id[port], m, num);
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

#define PUT_PACKET_IN_BUFFER(a, b)               \
	qconf->tx_mbufs[port].m_table[a] = m[b]; \
	j++;

	j = 0;
	switch (n % FWDSTEP) {
		while (j < n) {
		case 0:
			PUT_PACKET_IN_BUFFER(len + j, j);
		case 3:
			PUT_PACKET_IN_BUFFER(len + j, j);
		case 2:
			PUT_PACKET_IN_BUFFER(len + j, j);
		case 1:
			PUT_PACKET_IN_BUFFER(len + j, j);
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
				PUT_PACKET_IN_BUFFER(j, n + j);
			case 3:
				PUT_PACKET_IN_BUFFER(j, n + j);
			case 2:
				PUT_PACKET_IN_BUFFER(j, n + j);
			case 1:
				PUT_PACKET_IN_BUFFER(j, n + j);
			}
		}
	}

	qconf->tx_mbufs[port].len = len;
}

static inline uint8_t
get_ipv4_dst_port(void* ipv4_hdr,
		  uint8_t portid,
		  lookup_struct_t* ipv4_pktj_lookup_struct)
{
	uint8_t next_hop;

	return (uint8_t)(
	    (rte_lpm_lookup(
		 ipv4_pktj_lookup_struct,
		 rte_be_to_cpu_32(((struct ipv4_hdr*)ipv4_hdr)->dst_addr),
		 &next_hop) == 0)
		? next_hop
		: portid);
}

static inline uint8_t
get_ipv6_dst_port(void* ipv6_hdr,
		  uint8_t portid,
		  lookup6_struct_t* ipv6_pktj_lookup_struct)
{
	uint8_t next_hop;
	return (uint8_t)(
	    (rte_lpm6_lookup(ipv6_pktj_lookup_struct,
			     ((struct ipv6_hdr*)ipv6_hdr)->dst_addr,
			     &next_hop) == 0)
		? next_hop
		: portid);
}

#define IPV4_MIN_VER_IHL 0x45
#define IPV4_MAX_VER_IHL 0x4f
#define IPV4_MAX_VER_IHL_DIFF (IPV4_MAX_VER_IHL - IPV4_MIN_VER_IHL)

/* Minimum value of IPV4 total length (20B) in network byte order. */
#define IPV4_MIN_LEN_BE (sizeof(struct ipv4_hdr) << 8)

static inline __attribute__((always_inline)) uint8_t
ip_process(void* hdr, uint16_t* dp, uint32_t flags, struct lcore_conf* qconf)
{
	struct nei_entry* entries;

	if (likely((flags & PKTJ_IPV4_MASK) != 0)) {
		uint8_t ihl;
		struct ipv4_hdr* ipv4_hdr = (struct ipv4_hdr*)hdr;
		ihl = ipv4_hdr->version_ihl - IPV4_MIN_VER_IHL;

		ipv4_hdr->time_to_live--;
		ipv4_hdr->hdr_checksum++;

		if (ihl > IPV4_MAX_VER_IHL_DIFF ||
		    ipv4_hdr->total_length < IPV4_MIN_LEN_BE ||
		    ipv4_hdr->time_to_live <= 0) {
			dp[0] = BAD_PORT;
			return 1;
		}
		entries = &qconf->neighbor4_struct->entries.t4[*dp].neighbor;
		return entries->port_id == BAD_PORT;
	} else if (likely((flags & PKTJ_IPV6_MASK) != 0)) {
		struct ipv6_hdr* ipv6_hdr = (struct ipv6_hdr*)hdr;

		ipv6_hdr->hop_limits--;

		// TODO add more tests
		if (ipv6_hdr->hop_limits <= 0) {
			dp[0] = BAD_PORT;
			return 1;
		}
		entries = &qconf->neighbor6_struct->entries.t6[*dp].neighbor;
		return entries->port_id == BAD_PORT;
	}
	return 0;
}

static inline __attribute__((always_inline)) uint16_t
get_dst_port(const struct lcore_conf* qconf,
	     struct rte_mbuf* pkt,
	     uint32_t dst_ipv4,
	     struct nei_entry* kni_neighbor)
{
	uint8_t next_hop;
	struct ipv6_hdr* ipv6_hdr;
	struct ether_hdr* eth_hdr;

	if (PKTJ_TEST_IPV4_HDR(pkt)) {
		if (rte_lpm_lookup(qconf->ipv4_lookup_struct, dst_ipv4,
				   &next_hop) != 0)
			next_hop = 0;
	} else if (PKTJ_TEST_IPV6_HDR(pkt)) {
		eth_hdr = rte_pktmbuf_mtod(pkt, struct ether_hdr*);
		ipv6_hdr = (struct ipv6_hdr*)(eth_hdr + 1);
		if (rte_lpm6_lookup(qconf->ipv6_lookup_struct,
				    ipv6_hdr->dst_addr, &next_hop) != 0)
			next_hop = 0;
	} else {
		next_hop = kni_neighbor->port_id;
	}

	return next_hop;
}

static inline int
process_step2(struct lcore_conf* qconf,
	      struct rte_mbuf* pkt,
	      uint16_t* dst_port)
{
	struct ether_hdr* eth_hdr;
	uint16_t dp;
	struct ipv4_hdr* ipv4_hdr;
	struct ipv6_hdr* ipv6_hdr;

	eth_hdr = rte_pktmbuf_mtod(pkt, struct ether_hdr*);

	if (likely(PKTJ_TEST_IPV4_HDR(pkt))) {
		ipv4_hdr = (struct ipv4_hdr*)(eth_hdr + 1);
		dp = get_ipv4_dst_port(ipv4_hdr, 0, qconf->ipv4_lookup_struct);
		RTE_LOG(DEBUG, PKTJ1, "process_packet4 res %d\n", dp);
		dst_port[0] = dp;
	} else if (PKTJ_TEST_IPV6_HDR(pkt)) {
		ipv6_hdr = (struct ipv6_hdr*)(eth_hdr + 1);

		dp = get_ipv6_dst_port(ipv6_hdr, 0, qconf->ipv6_lookup_struct);
		dst_port[0] = dp;
		RTE_LOG(DEBUG, PKTJ1, "process_packet6 res %d\n", dp);
	}
	return 0;
}

static __m128i mask_tcp_179;

static inline int
kni_rate_limit_step(struct lcore_conf* qconf, struct rte_mbuf* pkt)
{
	__m128i data;

	if (PKTJ_TEST_IPV4_HDR(pkt)) {
		// not limit tcp 179 (bgp)
		uint8_t* hdr = rte_pktmbuf_mtod_offset(
		    pkt, uint8_t*, sizeof(struct ether_hdr) +
				       offsetof(struct ipv4_hdr, time_to_live));
		data = _mm_loadu_si128((__m128i*)(hdr));
		data = _mm_andnot_si128(data, mask_tcp_179);
		if (_mm_testz_si128(data, data)) {
			// don't rate-limit bgp
			return 0;
		}
	} else if (PKTJ_TEST_IPV6_HDR(pkt)) {
		struct ipv6_hdr* ip6_hdr = rte_pktmbuf_mtod_offset(
		    pkt, struct ipv6_hdr*, sizeof(struct ether_hdr));

		if (ip6_hdr->proto == 0x3a) {
			struct icmpv6_hdr* icmp6_hdr =
			    (struct icmpv6_hdr*)(ip6_hdr + 1);
			if (icmp6_hdr->icmp_type == 0x85 ||
			    icmp6_hdr->icmp_type == 0x86 ||
			    icmp6_hdr->icmp_type == 0x87 ||
			    icmp6_hdr->icmp_type == 0x88 ||
			    icmp6_hdr->icmp_type == 0x89) {
				return 0;
			}
		} else if (ip6_hdr->proto == 6) {
			struct tcp_hdr* ip6_tcp_hdr =
			    (struct tcp_hdr*)(ip6_hdr + 1);
			if (ip6_tcp_hdr->dst_port == 0xb300) {
				return 0;
			}
		}
	} else {
		// dont't limit arp
		if (PKTJ_TEST_ARP_HDR(pkt)) {
			return 0;
		}
	}
	return ++qconf->kni_rate_limit_cur > kni_rate_limit;
}

static inline int
rate_limit_step_ipv4(struct lcore_conf* qconf,
		     struct rte_mbuf* pkt,
		     unsigned lcore_id)
{
	struct ipv4_hdr* ipv4_hdr;
	uint8_t range_id;
	union rlimit_addr* dst_addr;
	uint32_t naddr;

	ipv4_hdr = rte_pktmbuf_mtod_offset(pkt, struct ipv4_hdr*,
					   sizeof(struct ether_hdr));
	naddr = rte_be_to_cpu_32(ipv4_hdr->dst_addr);
	dst_addr = (union rlimit_addr*)&naddr;
	range_id = rlimit4_lookup_table[rte_lcore_to_socket_id(lcore_id)]
				       [dst_addr->network];
	// check if the dest cidr range is in the lookup table
	if (range_id != INVALID_RLIMIT_RANGE) {
		// increase the counter for this dest
		// and check against the max value
		if (qconf->rlimit4_cur[range_id][dst_addr->host]++ >=
		    rlimit4_max[rte_lcore_to_socket_id(lcore_id)][range_id]
			       [dst_addr->host]) {
			return RATE_LIMITED;
		}
	}

	return 0;
}

static inline int
rate_limit_step_ipv6(struct lcore_conf* qconf,
		     uint16_t dst_port,
		     unsigned lcore_id)
{
	// increase the packet counter for this neighbor
	// and check against the max value
	if (qconf->rlimit6_cur[dst_port]++ >=
	    rlimit6_max[rte_lcore_to_socket_id(lcore_id)][dst_port]) {
		return RATE_LIMITED;
	}

	return 0;
}

/*
 * Read packet_type and destination IPV4 addresses from 4 mbufs.
 */
static inline void
processx4_step1(struct rte_mbuf* pkt[FWDSTEP],
		__m128i* dip,
		uint32_t* ipv4_flag)
{
	struct ipv4_hdr* ipv4_hdr;
	struct ether_hdr* eth_hdr;
	uint32_t x0, x1, x2, x3;

	eth_hdr = rte_pktmbuf_mtod(pkt[0], struct ether_hdr*);
	ipv4_hdr = (struct ipv4_hdr*)(eth_hdr + 1);
	x0 = ipv4_hdr->dst_addr;
	ipv4_flag[0] = PKTJ_PKT_TYPE(pkt[0]) & PKTJ_IPV4_MASK;

	eth_hdr = rte_pktmbuf_mtod(pkt[1], struct ether_hdr*);
	ipv4_hdr = (struct ipv4_hdr*)(eth_hdr + 1);
	x1 = ipv4_hdr->dst_addr;
	ipv4_flag[0] &= PKTJ_PKT_TYPE(pkt[1]);

	eth_hdr = rte_pktmbuf_mtod(pkt[2], struct ether_hdr*);
	ipv4_hdr = (struct ipv4_hdr*)(eth_hdr + 1);
	x2 = ipv4_hdr->dst_addr;
	ipv4_flag[0] &= PKTJ_PKT_TYPE(pkt[2]);

	eth_hdr = rte_pktmbuf_mtod(pkt[3], struct ether_hdr*);
	ipv4_hdr = (struct ipv4_hdr*)(eth_hdr + 1);
	x3 = ipv4_hdr->dst_addr;
	ipv4_flag[0] &= PKTJ_PKT_TYPE(pkt[3]);

	dip[0] = _mm_set_epi32(x3, x2, x1, x0);
}

/*
 * Lookup into LPM for neighbor id.
 * If lookup fails, drop.
 */
static inline void
processx4_step2(const struct lcore_conf* qconf,
		__m128i dip,
		uint32_t flag,
		struct rte_mbuf* pkt[FWDSTEP],
		uint16_t port_id,
		uint16_t neighbor[FWDSTEP])
{
	rte_xmm_t dst;
	const __m128i bswap_mask =
	    _mm_set_epi8(12, 13, 14, 15, 8, 9, 10, 11, 4, 5, 6, 7, 0, 1, 2, 3);
	struct nei_entry* neighbor_entry;

	/* Byte swap 4 IPV4 addresses, if it's not an ipv4 packet, swap anyway.
	 */
	dip = _mm_shuffle_epi8(dip, bswap_mask);

	/* if all 4 packets are IPV4. */
	if (likely(flag != 0)) {
		rte_lpm_lookupx4(qconf->ipv4_lookup_struct, dip, neighbor, 0);
		RTE_LOG(DEBUG, PKTJ1, "lookpx4 res %d:%d:%d:%d\n", neighbor[0],
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
		RTE_LOG(DEBUG, PKTJ1, "get_dst_portx4 res %d:%d:%d:%d\n",
			neighbor[0], neighbor[1], neighbor[2], neighbor[3]);
	}
}

static inline int
processx4_step_checkneighbor(struct lcore_conf* qconf,
			     struct rte_mbuf** pkt,
			     uint16_t* dst_port,
			     int nb_rx,
			     uint8_t portid,
			     unsigned lcore_id)
{
	int i, j, num;
	uint32_t nb_kni, k;
	struct rte_mbuf* knimbuf[FWDSTEP];
	struct kni_port_params* p;
	uint8_t process, action, is_ipv4;
	uint16_t vlan_tci;

	p = kni_port_params_array[portid];
	nb_kni = p->nb_kni;

#define PROCESSX4_STEP(step)                                                   \
	if (likely(PKTJ_TEST_IPV4_HDR(pkt[j]))) {                              \
		is_ipv4 = 1;                                                   \
		action = qconf->neighbor4_struct->entries.t4[dst_port[j]]      \
			     .neighbor.action;                                 \
		process = !qconf->neighbor4_struct->entries.t4[dst_port[j]]    \
			       .neighbor.valid ||                              \
			  action == NEI_ACTION_KNI;                            \
		RTE_LOG(DEBUG, PKTJ1,                                          \
			#step ": j %d process %d dst_port %d ipv4\n", j,       \
			process, dst_port[j]);                                 \
	} else if (PKTJ_TEST_IPV6_HDR(pkt[j])) {                               \
		is_ipv4 = 0;                                                   \
		action = qconf->neighbor6_struct->entries.t6[dst_port[j]]      \
			     .neighbor.action;                                 \
		process = !qconf->neighbor6_struct->entries.t6[dst_port[j]]    \
			       .neighbor.valid ||                              \
			  action == NEI_ACTION_KNI;                            \
		RTE_LOG(DEBUG, PKTJ1, #step ": j %d process %d ipv6\n", j,     \
			process);                                              \
	} else {                                                               \
		is_ipv4 = 0;                                                   \
		process = 1;                                                   \
		action = NEI_ACTION_KNI;                                       \
		RTE_LOG(                                                       \
		    DEBUG, PKTJ1,                                              \
		    #step ": j %d process %d olflags%lx eth_type %x\n", j,     \
		    process, pkt[j]->ol_flags,                                 \
		    rte_pktmbuf_mtod(pkt[j], struct ether_hdr*)->ether_type);  \
	}                                                                      \
	process +=                                                             \
	    process == 0                                                       \
		? ip_process(                                                  \
		      rte_pktmbuf_mtod_offset(pkt[j], struct ether_hdr*,       \
					      sizeof(struct ether_hdr)),       \
		      &dst_port[j], PKTJ_PKT_TYPE(pkt[j]), qconf)              \
		: 0;                                                           \
	if (process) {                                                         \
		/* test if we need to rate-limit that packet before sending it \
		 * to kni */                                                   \
		if (action != NEI_ACTION_DROP &&                               \
		    !kni_rate_limit_step(qconf, pkt[j]))                       \
			knimbuf[i++] = pkt[j];                                 \
		else {                                                         \
			rte_pktmbuf_free(pkt[j]);                              \
			stats[lcore_id].nb_ratel_dropped++;                    \
		}                                                              \
		/* no dest neighbor addr available, send it through the kni */ \
		if (j != --nb_rx) {                                            \
			/* we have more packets, deplace last one and its info \
			 */                                                    \
			pkt[j] = pkt[nb_rx];                                   \
			dst_port[j] = dst_port[nb_rx];                         \
		}                                                              \
		RTE_LOG(DEBUG, PKTJ1, #step                                    \
			": j %d nb_rx %d i %d dst_port %d lcore_id %d\n",      \
			j, nb_rx, i, dst_port[j], lcore_id);                   \
	} else {                                                               \
		/* we have only ipv4 or ipv6 packets here, other protos are    \
		 * sent to the kni */                                          \
		if (is_ipv4) {                                                 \
			process =                                              \
			    rate_limit_step_ipv4(qconf, pkt[j], lcore_id);     \
			vlan_tci =                                             \
			    qconf->neighbor4_struct->entries.t4[dst_port[j]]   \
				.neighbor.vlan_id;                             \
		} else {                                                       \
			process = rate_limit_step_ipv6(qconf, dst_port[j],     \
						       lcore_id);              \
			vlan_tci =                                             \
			    qconf->neighbor6_struct->entries.t6[dst_port[j]]   \
				.neighbor.vlan_id;                             \
		}                                                              \
		if (unlikely(process == RATE_LIMITED)) {                       \
			rte_pktmbuf_free(pkt[j]);                              \
			stats[lcore_id].nb_ratel_dropped++;                    \
			if (j != --nb_rx) {                                    \
				/* we have more packets, deplace last one and  \
				 * its info                                    \
				 */                                            \
				pkt[j] = pkt[nb_rx];                           \
				dst_port[j] = dst_port[nb_rx];                 \
			}                                                      \
		} else {                                                       \
			pkt[j]->vlan_tci = vlan_tci;                           \
			pkt[j]->ol_flags |= PKT_TX_VLAN_PKT;                   \
			RTE_LOG(DEBUG, PKTJ1, #step ": olflags%lx vlan%d\n",   \
				pkt[j]->ol_flags, vlan_tci);                   \
			j++;                                                   \
		}                                                              \
	}

	i = 0;
	j = 0;
	// duck device, first iteration use the switch dans go to nb_rx %
	// FWDSTEP case
	switch (nb_rx % FWDSTEP) {
		while (j < nb_rx) {
			i = 0;  // reinit i here after the first duck device
		case 0:
			PROCESSX4_STEP(0);
		case 3:
			PROCESSX4_STEP(3);
		case 2:
			PROCESSX4_STEP(2);
		case 1:
			PROCESSX4_STEP(1);

			if (likely(i == 0))
				continue;

			for (k = 0; k < nb_kni; k++) {
				int l = 0;
				for (; l < i; ++l)
					rte_vlan_insert(knimbuf + l);
				rte_spinlock_lock(&spinlock_kni[portid]);
				num = rte_kni_tx_burst(p->kni[k], knimbuf, i);
				rte_spinlock_unlock(&spinlock_kni[portid]);
				stats[lcore_id].nb_kni_tx += num;
				if (unlikely(num < i)) {
					/* Free mbufs not tx to kni interface */
					if (num > 0)
						kni_burst_free_mbufs(
						    &knimbuf[num], i - num);
					else
						kni_burst_free_mbufs(
						    &knimbuf[0], i);
				}
				RTE_LOG(
				    DEBUG, PKTJ1,
				    "k %d nb_rx %d i %d num %d lcore_id %d\n",
				    k, nb_rx, i, num, lcore_id);
			}
		}  // while loop end
	}
	return nb_rx;
}

static inline void
process_step3(struct lcore_conf* qconf,
	      struct rte_mbuf* pkt,
	      uint16_t* dst_port)
{
	struct ether_hdr* eth_hdr;
	__m128i te;
	__m128i ve;
	struct nei_entry* entries;

	eth_hdr = (rte_pktmbuf_mtod(pkt, struct ether_hdr*));
	if (likely(PKTJ_TEST_IPV4_HDR(pkt)))
		entries =
		    &qconf->neighbor4_struct->entries.t4[*dst_port].neighbor;
	else
		entries =
		    &qconf->neighbor6_struct->entries.t6[*dst_port].neighbor;

	ve = _mm_load_si128((__m128i*)&entries->nexthop_hwaddr);

	// requires unaligned load to prevent segfaults
	// happens on any packet when using virtio because of soft vlan
	// stripping,
	// eth_hdr is always at (headroom + sizeof(struct vlan_hdr))
	// also happens when not using virtio but packet type is still
	// unknown...
	te = _mm_loadu_si128((__m128i*)eth_hdr);

	te = _mm_blend_epi16(te, ve, MASK_ETH);
	_mm_storeu_si128((__m128i*)&eth_hdr->d_addr, te);
	*dst_port = entries->port_id;
}

/*
 * Update source and destination MAC addresses in the ethernet header.
 * Perform checks and updates for IP packets.
 */
static inline void
processx4_step3(struct lcore_conf* qconf,
		struct rte_mbuf* pkt[FWDSTEP],
		uint16_t dst_port[FWDSTEP])
{
	__m128i te[FWDSTEP];
	__m128i ve[FWDSTEP];
	__m128i* p[FWDSTEP];
	struct nei_entry* entries[FWDSTEP];

	if (likely(PKTJ_TEST_IPV4_HDR(pkt[0])))
		entries[0] =
		    &qconf->neighbor4_struct->entries.t4[dst_port[0]].neighbor;
	else
		entries[0] =
		    &qconf->neighbor6_struct->entries.t6[dst_port[0]].neighbor;

	if (likely(PKTJ_TEST_IPV4_HDR(pkt[1])))
		entries[1] =
		    &qconf->neighbor4_struct->entries.t4[dst_port[1]].neighbor;
	else
		entries[1] =
		    &qconf->neighbor6_struct->entries.t6[dst_port[1]].neighbor;

	if (likely(PKTJ_TEST_IPV4_HDR(pkt[2])))
		entries[2] =
		    &qconf->neighbor4_struct->entries.t4[dst_port[2]].neighbor;
	else
		entries[2] =
		    &qconf->neighbor6_struct->entries.t6[dst_port[2]].neighbor;

	if (likely(PKTJ_TEST_IPV4_HDR(pkt[3])))
		entries[3] =
		    &qconf->neighbor4_struct->entries.t4[dst_port[3]].neighbor;
	else
		entries[3] =
		    &qconf->neighbor6_struct->entries.t6[dst_port[3]].neighbor;

	/* Pivot dst_port */
	dst_port[0] = entries[0]->port_id;
	dst_port[1] = entries[1]->port_id;
	dst_port[2] = entries[2]->port_id;
	dst_port[3] = entries[3]->port_id;

	p[0] = (rte_pktmbuf_mtod(pkt[0], __m128i*));
	p[1] = (rte_pktmbuf_mtod(pkt[1], __m128i*));
	p[2] = (rte_pktmbuf_mtod(pkt[2], __m128i*));
	p[3] = (rte_pktmbuf_mtod(pkt[3], __m128i*));

	ve[0] = _mm_load_si128((__m128i*)&entries[0]->nexthop_hwaddr);
	ve[1] = _mm_load_si128((__m128i*)&entries[1]->nexthop_hwaddr);
	ve[2] = _mm_load_si128((__m128i*)&entries[2]->nexthop_hwaddr);
	ve[3] = _mm_load_si128((__m128i*)&entries[3]->nexthop_hwaddr);

	te[0] = pktj_mm_load_si128(p[0]);
	te[1] = pktj_mm_load_si128(p[1]);
	te[2] = pktj_mm_load_si128(p[2]);
	te[3] = pktj_mm_load_si128(p[3]);

	/* Update first 12 bytes, keep rest bytes intact. */
	te[0] = _mm_blend_epi16(te[0], ve[0], MASK_ETH);
	te[1] = _mm_blend_epi16(te[1], ve[1], MASK_ETH);
	te[2] = _mm_blend_epi16(te[2], ve[2], MASK_ETH);
	te[3] = _mm_blend_epi16(te[3], ve[3], MASK_ETH);

	pktj_mm_store_si128(p[0], te[0]);
	pktj_mm_store_si128(p[1], te[1]);
	pktj_mm_store_si128(p[2], te[2]);
	pktj_mm_store_si128(p[3], te[3]);
}

#define GRPSZ (1 << FWDSTEP)
#define GRPMSK (GRPSZ - 1)

/*
 * Group consecutive packets with the same destination port in bursts of 4.
 * Suppose we have array of destionation ports:
 * dst_port[] = {a, b, c, d,, e, ... }
 * dp1 should contain: <a, b, c, d>, dp2: <b, c, d, e>.
 * We doing 4 comparisions at once and the result is 4 bit mask.
 * This mask is used as an index into prebuild array of pnum values.
 */
static inline uint16_t*
port_groupx4(uint16_t pn[FWDSTEP + 1], uint16_t* lp, __m128i dp1, __m128i dp2)
{
	static const struct {
		uint64_t pnum; /* prebuild 4 values for pnum[]. */
		int32_t idx;   /* index for new last updated elemnet. */
		uint16_t lpv;  /* add value to the last updated element. */
	} gptbl[GRPSZ] = {
	    {
		/* 0: a != b, b != c, c != d, d != e */
		.pnum = UINT64_C(0x0001000100010001),
		.idx = 4,
		.lpv = 0,
	    },
	    {
		/* 1: a == b, b != c, c != d, d != e */
		.pnum = UINT64_C(0x0001000100010002),
		.idx = 4,
		.lpv = 1,
	    },
	    {
		/* 2: a != b, b == c, c != d, d != e */
		.pnum = UINT64_C(0x0001000100020001),
		.idx = 4,
		.lpv = 0,
	    },
	    {
		/* 3: a == b, b == c, c != d, d != e */
		.pnum = UINT64_C(0x0001000100020003),
		.idx = 4,
		.lpv = 2,
	    },
	    {
		/* 4: a != b, b != c, c == d, d != e */
		.pnum = UINT64_C(0x0001000200010001),
		.idx = 4,
		.lpv = 0,
	    },
	    {
		/* 5: a == b, b != c, c == d, d != e */
		.pnum = UINT64_C(0x0001000200010002),
		.idx = 4,
		.lpv = 1,
	    },
	    {
		/* 6: a != b, b == c, c == d, d != e */
		.pnum = UINT64_C(0x0001000200030001),
		.idx = 4,
		.lpv = 0,
	    },
	    {
		/* 7: a == b, b == c, c == d, d != e */
		.pnum = UINT64_C(0x0001000200030004),
		.idx = 4,
		.lpv = 3,
	    },
	    {
		/* 8: a != b, b != c, c != d, d == e */
		.pnum = UINT64_C(0x0002000100010001),
		.idx = 3,
		.lpv = 0,
	    },
	    {
		/* 9: a == b, b != c, c != d, d == e */
		.pnum = UINT64_C(0x0002000100010002),
		.idx = 3,
		.lpv = 1,
	    },
	    {
		/* 0xa: a != b, b == c, c != d, d == e */
		.pnum = UINT64_C(0x0002000100020001),
		.idx = 3,
		.lpv = 0,
	    },
	    {
		/* 0xb: a == b, b == c, c != d, d == e */
		.pnum = UINT64_C(0x0002000100020003),
		.idx = 3,
		.lpv = 2,
	    },
	    {
		/* 0xc: a != b, b != c, c == d, d == e */
		.pnum = UINT64_C(0x0002000300010001),
		.idx = 2,
		.lpv = 0,
	    },
	    {
		/* 0xd: a == b, b != c, c == d, d == e */
		.pnum = UINT64_C(0x0002000300010002),
		.idx = 2,
		.lpv = 1,
	    },
	    {
		/* 0xe: a != b, b == c, c == d, d == e */
		.pnum = UINT64_C(0x0002000300040001),
		.idx = 1,
		.lpv = 0,
	    },
	    {
		/* 0xf: a == b, b == c, c == d, d == e */
		.pnum = UINT64_C(0x0002000300040005),
		.idx = 0,
		.lpv = 4,
	    },
	};

	union {
		uint16_t u16[FWDSTEP + 1];
		uint64_t u64;
	}* pnum = (void*)pn;

	int32_t v;

	dp1 = _mm_cmpeq_epi16(dp1, dp2);
	dp1 = _mm_unpacklo_epi16(dp1, dp1);
	v = _mm_movemask_ps((__m128)dp1);

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

/*
 * Put one packet in acl_search struct according to the packet ol_flags
 */
static inline void
prepare_one_packet(struct rte_mbuf** pkts_in,
		   struct acl_search_t* acl,
		   int index)
{
	struct rte_mbuf* pkt = pkts_in[index];

	// XXX we cannot filter non IP packet yet
	if (PKTJ_TEST_IPV4_HDR(pkt)) {
		/* Fill acl structure */
		acl->data_ipv4[acl->num_ipv4] = MBUF_IPV4_2PROTO(pkt);
		acl->m_ipv4[(acl->num_ipv4)++] = pkt;
	} else if (PKTJ_TEST_IPV6_HDR(pkt)) {
		/* Fill acl structure */
		acl->data_ipv6[acl->num_ipv6] = MBUF_IPV6_2PROTO(pkt);
		acl->m_ipv6[(acl->num_ipv6)++] = pkt;
	}
}

/*
 * Loop through all packets and classify them if acl_search if possible.
 */
static inline void
prepare_acl_parameter(struct rte_mbuf** pkts_in,
		      struct acl_search_t* acl,
		      int nb_rx)
{
	int i = 0, j = 0;

	acl->num_ipv4 = 0;
	acl->num_ipv6 = 0;

#define PREFETCH()                                          \
	rte_prefetch0(rte_pktmbuf_mtod(pkts_in[i], void*)); \
	i++;                                                \
	j++;

	// we prefetch0 packets 3 per 3
	switch (nb_rx % PREFETCH_OFFSET) {
		while (nb_rx != i) {
		case 0:
			PREFETCH();
		case 2:
			PREFETCH();
		case 1:
			PREFETCH();

			while (j > 0) {
				prepare_one_packet(pkts_in, acl, i - j);
				--j;
			}
		}
	}
}

/*
 * Take both acl from acl_search and filters packets related to those acl.
 * Put back unfiltered packets in pkt_burst without overwriting non IP packets.
 */
static inline int
filter_packets(uint32_t lcore_id,
	       struct rte_mbuf** pkts,
	       struct acl_search_t* acl_search,
	       int nb_rx,
	       struct rte_acl_ctx* acl4,
	       struct rte_acl_ctx* acl6)
{
	uint32_t* res;
	struct rte_mbuf** acl_pkts;
	int nb_res;
	int i;
	int nb_pkts = 0;  // number of packet in the newly crafted pkts

	nb_res = acl_search->num_ipv4;
	res = acl_search->res_ipv4;
	acl_pkts = acl_search->m_ipv4;

	// TODO maybe we want to manually unroll those loops
	// TODO maye we could replace those loops by an inlined fonction

	// if num_ipv4 is equal to zero we skip it
	for (i = 0; i < nb_res; ++i) {
		// if the packet must be filtered, free it and don't add it back
		// in pkts
		if (unlikely(acl4 != NULL &&
			     (res[i] & ACL_DENY_SIGNATURE) != 0)) {
/* in the ACL list, drop it */
#ifdef L3FWDACL_DEBUG
			dump_acl4_rule(acl_pkts[i], res[i]);
#endif
			stats[lcore_id].nb_acl_dropped++;
			rte_pktmbuf_free(acl_pkts[i]);
		} else {
			// add back the unfiltered packet in pkts but don't
			// discard non IP packet
			while (nb_pkts < nb_rx &&
			       !(PKTJ_PKT_TYPE(pkts[nb_pkts]) & PKTJ_IP_MASK)) {
				nb_pkts++;
			}
			pkts[nb_pkts++] = acl_pkts[i];
		}
	}

	nb_res = acl_search->num_ipv6;
	res = acl_search->res_ipv6;
	acl_pkts = acl_search->m_ipv6;

	// if num_ipv6 is equal to zero we skip it
	for (i = 0; i < nb_res; ++i) {
		// if the packet must be filtered, free it and don't add it back
		// in pkts
		if (unlikely(acl6 != NULL &&
			     (res[i] & ACL_DENY_SIGNATURE) != 0)) {
/* in the ACL list, drop it */
#ifdef L3FWDACL_DEBUG
			dump_acl6_rule(acl_pkts[i], res[i]);
#endif
			stats[lcore_id].nb_acl_dropped++;
			rte_pktmbuf_free(acl_pkts[i]);
		} else {
			// add back the unfiltered packet in pkts but don't
			// discard non IP packet
			while (nb_pkts < nb_rx &&
			       !(PKTJ_PKT_TYPE(pkts[nb_pkts]) & PKTJ_IP_MASK)) {
				nb_pkts++;
			}
			pkts[nb_pkts++] = acl_pkts[i];
		}
	}

	// add back non IP packet that are after nb_pkts packets
	for (i = nb_pkts; i < nb_rx; i++) {
		if (!(PKTJ_PKT_TYPE(pkts[i]) & PKTJ_IP_MASK)) {
			pkts[nb_pkts++] = pkts[i];
		}
	}

	return nb_pkts;
}

static inline int
rte_atomic64_cmpswap(volatile uintptr_t* dst, uintptr_t* exp, uintptr_t src)
{
	uint8_t res;

	asm volatile(MPLOCKED
		     "cmpxchgq %[src], %[dst];"
		     "movq %%rax, %[exp];"
		     "sete %[res];"
		     : [res] "=a"(res), /* output */
		       [dst] "=m"(*dst), [exp] "=m"(*exp)
		     : [src] "r"(src), /* input */
		       "a"(*exp), "m"(*dst)
		     : "memory", "cc"); /* no-clobber list */
	return res;
}

/* main processing loop */
static int
main_loop(__rte_unused void* dummy)
{
	struct rte_mbuf* pkts_burst[MAX_PKT_BURST];
	uint32_t lcore_id;
	uint64_t prev_tsc, diff_tsc, cur_tsc, rate_tsc = 0;
	int i, j, nb_rx;
	uint8_t portid = 0, queueid;
	struct lcore_conf* qconf;
	const uint64_t drain_tsc =
	    (rte_get_tsc_hz() + US_PER_S - 1) / US_PER_S * BURST_TX_DRAIN_US;
	const uint64_t ticks_per_s = rte_get_tsc_hz();
	int32_t k;
	int32_t f_stop;
	uint16_t dlp;
	uint16_t* lp;
	uint16_t dst_port[MAX_PKT_BURST];
	__m128i dip[MAX_PKT_BURST / FWDSTEP];
	uint32_t flag[MAX_PKT_BURST / FWDSTEP];
	uint16_t pnum[MAX_PKT_BURST + 1];
#ifdef ATOMIC_ACL
	struct rte_acl_ctx* acx;
#endif

	prev_tsc = 0;

	lcore_id = rte_lcore_id();
	qconf = &lcore_conf[lcore_id];

	if (qconf->n_rx_queue == 0) {
		RTE_LOG(INFO, PKTJ1, "lcore %u has nothing to do\n", lcore_id);
		return 0;
	}

	RTE_LOG(INFO, PKTJ1, "entering main loop on lcore %u\n", lcore_id);

	for (i = 0; i < qconf->n_rx_queue; i++) {
		portid = qconf->rx_queue_list[i].port_id;
		stats[lcore_id].port_id = portid;
		queueid = qconf->rx_queue_list[i].queue_id;
		RTE_LOG(INFO, PKTJ1,
			" -- lcoreid=%u portid=%hhu rxqueueid=%hhu\n", lcore_id,
			portid, queueid);
	}

	while (1) {
		f_stop = rte_atomic32_read(&main_loop_stop);
		if (unlikely(f_stop))
			break;
		stats[lcore_id].nb_iteration_looped++;
		cur_tsc = glob_tsc[lcore_id];

#ifdef ATOMIC_ACL
#define SWAP_ACX(cur_acx, new_acx)                                            \
	acx = cur_acx;                                                        \
	if (!rte_atomic64_cmpswap((uintptr_t*)&new_acx, (uintptr_t*)&cur_acx, \
				  (uintptr_t)new_acx)) {                      \
		rte_acl_free(acx);                                            \
	}
#else
#define SWAP_ACX(cur_acx, new_acx)          \
	if (unlikely(cur_acx != new_acx)) { \
		rte_acl_free(cur_acx);      \
		cur_acx = new_acx;          \
	}
#endif

		SWAP_ACX(qconf->cur_acx_ipv4, qconf->new_acx_ipv4);
		SWAP_ACX(qconf->cur_acx_ipv6, qconf->new_acx_ipv6);
#undef SWAP_ACX

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
				send_burst(qconf, qconf->tx_mbufs[portid].len,
					   portid);
				qconf->tx_mbufs[portid].len = 0;
			}

			uint64_t sec = cur_tsc / ticks_per_s;
			if (sec > rate_tsc) {
				rate_tsc = sec;

				// reset rate limit counters
				qconf->kni_rate_limit_cur = 0;

				memset(qconf->rlimit6_cur, 0,
				       sizeof(qconf->rlimit6_cur));
				memset(qconf->rlimit4_cur, 0,
				       sizeof(qconf->rlimit4_cur));
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
			if (unlikely(nb_rx == 0))
				continue;

			RTE_LOG(DEBUG, PKTJ1,
				"main_loop nb_rx %d  queue_id %d\n", nb_rx,
				queueid);
			stats[lcore_id].nb_rx += nb_rx;
			{
				struct acl_search_t acl_search;

				prepare_acl_parameter(pkts_burst, &acl_search,
						      nb_rx);

				if (likely(qconf->cur_acx_ipv4 &&
					   acl_search.num_ipv4)) {
					rte_acl_classify(
					    qconf->cur_acx_ipv4,
					    acl_search.data_ipv4,
					    acl_search.res_ipv4,
					    acl_search.num_ipv4,
					    DEFAULT_MAX_CATEGORIES);
				}

				if (likely(qconf->cur_acx_ipv6 &&
					   acl_search.num_ipv6)) {
					rte_acl_classify(
					    qconf->cur_acx_ipv6,
					    acl_search.data_ipv6,
					    acl_search.res_ipv6,
					    acl_search.num_ipv6,
					    DEFAULT_MAX_CATEGORIES);
				}
				nb_rx = filter_packets(
				    lcore_id, pkts_burst, &acl_search, nb_rx,
				    qconf->cur_acx_ipv4, qconf->cur_acx_ipv6);
			}
			if (unlikely(nb_rx == 0))
				continue;

			/* Process up to last 3 packets one by one. */
			RTE_LOG(DEBUG, PKTJ1,
				"main_loop acl nb_rx %d  queue_id %d\n", nb_rx,
				queueid);
#define PROCESS_STEP2(offset)                            \
	process_step2(qconf, pkts_burst[nb_rx - offset], \
		      dst_port + nb_rx - offset)

			switch (nb_rx % FWDSTEP) {
			case 3:
				PROCESS_STEP2(3);
			case 2:
				PROCESS_STEP2(2);
			case 1:
				PROCESS_STEP2(1);
			}

			k = RTE_ALIGN_FLOOR(nb_rx, FWDSTEP);
			for (j = 0; j != k; j += FWDSTEP) {
				processx4_step1(&pkts_burst[j],
						&dip[j / FWDSTEP],
						&flag[j / FWDSTEP]);
			}

			k = RTE_ALIGN_FLOOR(nb_rx, FWDSTEP);
			for (j = 0; j != k; j += FWDSTEP) {
				processx4_step2(
				    qconf, dip[j / FWDSTEP], flag[j / FWDSTEP],
				    &pkts_burst[j], portid, &dst_port[j]);
			}

			// send through the kni packets which don't have an
			// available neighbor
			nb_rx = processx4_step_checkneighbor(qconf, pkts_burst,
							     dst_port, nb_rx,
							     portid, lcore_id);

			/*
			 * Finish packet processing and group consecutive
			 * packets with the same destination port.
			 */
			k = RTE_ALIGN_FLOOR(nb_rx, FWDSTEP);
			if (unlikely(k != 0)) {
				__m128i dp1, dp2;

				lp = pnum;
				lp[0] = 1;

				processx4_step3(qconf, pkts_burst, dst_port);

				/* dp1: <d[0], d[1], d[2], d[3], ... > */
				dp1 = _mm_loadu_si128((__m128i*)dst_port);

				for (j = FWDSTEP; j != k; j += FWDSTEP) {
					processx4_step3(qconf, &pkts_burst[j],
							&dst_port[j]);

					/*
					 * dp2:
					 * <d[j-3], d[j-2], d[j-1], d[j], ... >
					 */
					dp2 = _mm_loadu_si128(
					    (__m128i*)&dst_port[j - FWDSTEP +
								1]);
					lp = port_groupx4(&pnum[j - FWDSTEP],
							  lp, dp1, dp2);

					/*
					 * dp1:
					 * <d[j], d[j+1], d[j+2], d[j+3], ... >
					 */
					dp1 = _mm_srli_si128(
					    dp2, (FWDSTEP - 1) *
						     sizeof(dst_port[0]));
				}

				/*
				 * dp2: <d[j-3], d[j-2], d[j-1], d[j-1], ... >
				 */
				dp2 = _mm_shufflelo_epi16(dp1, 0xf9);
				lp = port_groupx4(&pnum[j - FWDSTEP], lp, dp1,
						  dp2);

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
				j = 0;
			}

#define PROCESS_STEP3_1()                                  \
	process_step3(qconf, pkts_burst[j], &dst_port[j]); \
	if (likely((dlp) == dst_port[j])) {                \
		lp[0]++;                                   \
	} else {                                           \
		dlp = dst_port[j];                         \
		lp = &pnum[j];                             \
		lp[0] = 1;                                 \
	}                                                  \
	j++;
#define PROCESS_STEP3_2()                                  \
	process_step3(qconf, pkts_burst[j], &dst_port[j]); \
	if (likely((dlp) == dst_port[j])) {                \
		lp[0]++;                                   \
	} else {                                           \
		pnum[j] = 1;                               \
	}

			/* Process up to last 3 packets one by one. */
			switch (nb_rx % FWDSTEP) {
			case 3:
				PROCESS_STEP3_1();
			case 2:
				PROCESS_STEP3_1();
			case 1:
				PROCESS_STEP3_2();
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
					send_packetsx4(qconf, pn,
						       pkts_burst + j, k);
				} else {
					stats[lcore_id].nb_dropped += k;
					for (m = j; m != j + k; m++)
						rte_pktmbuf_free(pkts_burst[m]);
				}
			}
		}
	}
	return 0;
}

static int
check_lcore_params(void)
{
	uint8_t queue, lcore;
	uint16_t i;
	int socketid;

	for (i = 0; i < nb_lcore_params; ++i) {
		queue = lcore_params[i].queue_id;
		if (queue >= MAX_RX_QUEUE_PER_PORT) {
			RTE_LOG(ERR, PKTJ1, "invalid queue number: %hhu\n",
				queue);
			return -1;
		}
		lcore = lcore_params[i].lcore_id;
		if (!rte_lcore_is_enabled(lcore)) {
			RTE_LOG(
			    ERR, PKTJ1,
			    "error: lcore %hhu is not enabled in lcore mask\n",
			    lcore);
			return -1;
		}
		if ((socketid = rte_lcore_to_socket_id(lcore) != 0) &&
		    (numa_on == 0)) {
			RTE_LOG(WARNING, PKTJ1,
				"warning: lcore %hhu is on "
				"socket %d with numa off \n",
				lcore, socketid);
		}
	}
	return 0;
}

static int
check_port_config(const unsigned nb_ports)
{
	unsigned portid;
	uint16_t i;

	for (i = 0; i < nb_lcore_params; ++i) {
		portid = lcore_params[i].port_id;
		if ((enabled_port_mask & (1 << portid)) == 0) {
			RTE_LOG(ERR, PKTJ1,
				"port %u is not enabled in port mask\n",
				portid);
			return -1;
		}
		if (portid >= nb_ports) {
			RTE_LOG(ERR, PKTJ1,
				"port %u is not present on the board\n",
				portid);
			return -1;
		}
	}
	return 0;
}

static uint8_t
get_ports_n_rx_queues(void)
{
	uint8_t nb_queue = 0;
	uint16_t i;

	for (i = 0; i < nb_lcore_params; ++i) {
		if (enabled_port_mask & 1 << lcore_params[i].port_id)
			nb_queue++;
	}
	return nb_queue;
}

uint8_t
get_port_n_rx_queues(uint8_t port)
{
	int nb_queue = 0;
	uint16_t i;

	for (i = 0; i < nb_lcore_params; ++i) {
		if (lcore_params[i].port_id == port)
			nb_queue++;
	}
	return nb_queue;
}

static int
init_lcore_rx_queues(void)
{
	uint16_t i, nb_rx_queue;
	uint8_t lcore;

	for (i = 0; i < nb_lcore_params; ++i) {
		lcore = lcore_params[i].lcore_id;
		nb_rx_queue = lcore_conf[lcore].n_rx_queue;
		if (nb_rx_queue >= MAX_RX_QUEUE_PER_LCORE) {
			RTE_LOG(ERR, PKTJ1,
				"error: too many queues (%u) for lcore: %u\n",
				(unsigned)nb_rx_queue + 1, (unsigned)lcore);
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

static void
setup_lpm(int socketid)
{
	struct rte_lpm6_config config;
	char s[64];

	/* create the LPM table */
	snprintf(s, sizeof(s), "IPV4_L3FWD_LPM_%d", socketid);
	ipv4_pktj_lookup_struct[socketid] =
	    rte_lpm_create(s, socketid, IPV4_L3FWD_LPM_MAX_RULES, 0);
	if (ipv4_pktj_lookup_struct[socketid] == NULL)
		rte_exit(EXIT_FAILURE,
			 "Unable to create the pktj LPM table"
			 " on socket %d\n",
			 socketid);

	/* create the LPM6 table */
	snprintf(s, sizeof(s), "IPV6_L3FWD_LPM_%d", socketid);

	config.max_rules = IPV6_L3FWD_LPM_MAX_RULES;
	config.number_tbl8s = IPV6_L3FWD_LPM_NUMBER_TBL8S;
	config.flags = 0;
	ipv6_pktj_lookup_struct[socketid] =
	    rte_lpm6_create(s, socketid, &config);
	if (ipv6_pktj_lookup_struct[socketid] == NULL)
		rte_exit(EXIT_FAILURE,
			 "Unable to create the pktj LPM6 table"
			 " on socket %d\n",
			 socketid);
}

static int
init_mem(uint8_t nb_ports)
{
	struct lcore_conf* qconf;
	int socketid;
	unsigned lcore_id;
	uint8_t port;
	char s[64];
	size_t nb_mbuf;
	uint32_t nb_lcores;
	uint8_t nb_tx_queue;
	uint8_t nb_rx_queue;

	nb_lcores = rte_lcore_count();
	nb_rx_queue = get_ports_n_rx_queues();
	nb_tx_queue = nb_rx_queue;
	nb_mbuf = NB_MBUF;

	memset(&kni_neighbor, 0, sizeof(kni_neighbor));

	for (port = 0; port < RTE_MAX_ETHPORTS; port++) {
		kni_neighbor[port].in_use = 1;
		kni_neighbor[port].action = NEI_ACTION_KNI;
		kni_neighbor[port].port_id = port;
	}

	memset(rlimit4_max, UINT32_MAX, sizeof(rlimit4_max));
	memset(rlimit6_max, UINT32_MAX, sizeof(rlimit6_max));
	memset(rlimit4_lookup_table, INVALID_RLIMIT_RANGE,
	       sizeof(rlimit4_lookup_table));

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
			pktmbuf_pool[socketid] = rte_pktmbuf_pool_create(
			    s, nb_mbuf, MEMPOOL_CACHE_SIZE, 0,
			    RTE_MBUF_DEFAULT_BUF_SIZE, socketid);
			if (pktmbuf_pool[socketid] == NULL)
				rte_exit(EXIT_FAILURE,
					 "Cannot init mbuf pool on socket %d\n",
					 socketid);
			else
				RTE_LOG(INFO, PKTJ1,
					"Allocated mbuf pool on socket %d\n",
					socketid);

			setup_lpm(socketid);
		}
		if (knimbuf_pool[socketid] == NULL) {
			snprintf(s, sizeof(s), "knimbuf_pool_%d", socketid);
			knimbuf_pool[socketid] = rte_pktmbuf_pool_create(
			    s, nb_mbuf, MEMPOOL_CACHE_SIZE, 0,
			    RTE_MBUF_DEFAULT_BUF_SIZE, socketid);
			if (knimbuf_pool[socketid] == NULL)
				rte_exit(
				    EXIT_FAILURE,
				    "Cannot init kni mbuf pool on socket %d\n",
				    socketid);
			else
				RTE_LOG(
				    INFO, PKTJ1,
				    "Allocated kni mbuf pool on socket %d\n",
				    socketid);
		}
		qconf = &lcore_conf[lcore_id];
		qconf->ipv4_lookup_struct = ipv4_pktj_lookup_struct[socketid];
		qconf->neighbor4_struct = neighbor4_struct[socketid];
		qconf->ipv6_lookup_struct = ipv6_pktj_lookup_struct[socketid];
		qconf->neighbor6_struct = neighbor6_struct[socketid];
		qconf->cur_acx_ipv4 = ipv4_acx[socketid];
		qconf->cur_acx_ipv6 = ipv6_acx[socketid];

		memset(qconf->rlimit6_cur, 0, sizeof(qconf->rlimit6_cur));
		memset(qconf->rlimit4_cur, 0, sizeof(qconf->rlimit4_cur));
	}
	return 0;
}

/* Check the link status of all ports in up to 9s, and print them finally */
static void
check_all_ports_link_status(uint8_t port_num, uint32_t port_mask)
{
#define CHECK_INTERVAL 100 /* 100ms */
#define MAX_CHECK_TIME 90  /* 9s (90 * 100ms) in total */
	uint8_t portid, count, all_ports_up, print_flag = 0;
	struct rte_eth_link link;

	RTE_LOG(INFO, PKTJ1, "\nChecking link status\n");
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
					RTE_LOG(INFO, PKTJ1,
						"Port %d Link Up - speed %u "
						"Mbps - %s\n",
						(uint8_t)portid,
						(unsigned)link.link_speed,
						(link.link_duplex ==
						 ETH_LINK_FULL_DUPLEX)
						    ? ("full-duplex")
						    : ("half-duplex\n"));
				else
					RTE_LOG(INFO, PKTJ1,
						"Port %d Link Down\n",
						(uint8_t)portid);
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
			RTE_LOG(INFO, PKTJ1, ".");
			fflush(stdout);
			rte_delay_ms(CHECK_INTERVAL);
		}

		/* set the print_flag if all ports up or timeout */
		if (all_ports_up == 1 || count == (MAX_CHECK_TIME - 1)) {
			print_flag = 1;
			RTE_LOG(INFO, PKTJ1, "done\n");
		}
	}
}

static void
init_port(uint8_t portid)
{
	struct rte_eth_txconf* txconf;
	struct rte_eth_dev_info dev_info;
	struct lcore_conf* qconf;
	uint8_t nb_tx_queue, queue;
	uint8_t nb_rx_queue, socketid;
	int ret;
	int16_t queueid;
	unsigned lcore_id;

	/* skip ports that are not enabled */
	if ((enabled_port_mask & (1 << portid)) == 0) {
		RTE_LOG(INFO, PKTJ1, "\nSkipping disabled port %d\n", portid);
		return;
	}

	/* init port */
	RTE_LOG(INFO, PKTJ1, "Initializing port %d ...\n", portid);

	nb_rx_queue = get_port_n_rx_queues(portid);
	// XXX the +1 is for the kni
	nb_tx_queue = nb_rx_queue + 1;
	RTE_LOG(INFO, PKTJ1, "Creating queues: nb_rxq=%d nb_txq=%u...\n",
		nb_rx_queue, nb_tx_queue);

	ret =
	    rte_eth_dev_configure(portid, nb_rx_queue, nb_tx_queue, &port_conf);
	if (ret < 0)
		rte_exit(EXIT_FAILURE,
			 "Cannot configure device: err=%d, port=%u\n", ret,
			 portid);

	/*
	 * prepare dst and src MACs for each port.
	 */
	rte_eth_macaddr_get(portid, &ports_eth_addr[portid]);
	print_ethaddr(" Address:", &ports_eth_addr[portid]);

	rte_eth_dev_info_get(portid, &dev_info);
	txconf = &dev_info.default_txconf;

#ifdef PKTJ_QEMU
	txconf->txq_flags = ETH_TXQ_FLAGS_NOOFFLOADS;
#else
	txconf->txq_flags &= ~ETH_TXQ_FLAGS_NOOFFLOADS;
#endif

	// XXX is it correct ?
	if (port_conf.rxmode.jumbo_frame)
		txconf->txq_flags = 0;

	printf("port=%u tx_queueid=%d nb_txd=%d kni\n", portid, nb_tx_queue,
	       nb_txd);

	// XXX kni tx queue
	if (numa_on)
		socketid = (uint8_t)rte_lcore_to_socket_id(
		    kni_port_params_array[portid]->lcore_tx);
	else
		socketid = 0;

	ret = rte_eth_tx_queue_setup(portid, nb_tx_queue - 1, nb_txd, socketid,
				     txconf);
	if (ret < 0)
		rte_exit(EXIT_FAILURE,
			 "rte_eth_tx_queue_setup: err=%d, "
			 "port=%u\n",
			 ret, portid);

	nb_tx_queue = 0;
	/* init one TX queue per couple (lcore,port) */
	for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
		if (rte_lcore_is_enabled(lcore_id) == 0) {
			continue;
		}

		if (numa_on)
			socketid = (uint8_t)rte_lcore_to_socket_id(lcore_id);
		else
			socketid = 0;

		qconf = &lcore_conf[lcore_id];
		queueid = -1;

		/* init RX queues */
		for (queue = 0; queue < qconf->n_rx_queue; ++queue) {
			if (portid != qconf->rx_queue_list[queue].port_id) {
				// we skip that queue
				continue;
			}
			queueid = qconf->rx_queue_list[queue].queue_id;

			RTE_LOG(DEBUG, PKTJ1,
				"port=%u rx_queueid=%d nb_rxd=%d core=%u\n",
				portid, queueid, nb_rxd, lcore_id);
			ret = rte_eth_rx_queue_setup(portid, queueid, nb_rxd,
						     socketid, NULL,
						     pktmbuf_pool[socketid]);
			if (ret < 0)
				rte_exit(EXIT_FAILURE,
					 "rte_eth_rx_queue_setup: err=%d,"
					 "port=%u\n",
					 ret, portid);
		}
		if (queueid == -1) {
			// no rx_queue set, don't need to setup tx_queue for
			// that clore
			continue;
		}

		RTE_LOG(
		    INFO, PKTJ1,
		    "\nInitializing rx/tx queues on lcore %u for port %u ...\n",
		    lcore_id, portid);

		rte_eth_dev_info_get(portid, &dev_info);
		txconf = &dev_info.default_txconf;

#ifdef PKTJ_QEMU
		txconf->txq_flags = ETH_TXQ_FLAGS_NOOFFLOADS;
#else
		txconf->txq_flags &= ~ETH_TXQ_FLAGS_NOOFFLOADS;
#endif

		// XXX is it correct ?
		if (port_conf.rxmode.jumbo_frame)
			txconf->txq_flags = 0;

		RTE_LOG(DEBUG, PKTJ1,
			"port=%u tx_queueid=%d nb_txd=%d core=%u\n", portid,
			nb_tx_queue, nb_txd, lcore_id);
		ret = rte_eth_tx_queue_setup(portid, nb_tx_queue, nb_txd,
					     socketid, txconf);
		if (ret < 0)
			rte_exit(EXIT_FAILURE,
				 "rte_eth_tx_queue_setup: err=%d, "
				 "port=%u\n",
				 ret, portid);

		qconf->tx_queue_id[portid] = nb_tx_queue++;
	}
}

static int
alloc_kni_ports(uint8_t nb_sys_ports)
{
	uint8_t port;

	/* Check if the configured port ID is valid */
	for (port = 0; port < RTE_MAX_ETHPORTS; port++)
		if (kni_port_params_array[port] && port >= nb_sys_ports)
			rte_exit(EXIT_FAILURE,
				 "Configured invalid "
				 "port ID %u\n",
				 port);

	/* Initialise each port */
	for (port = 0; port < nb_sys_ports; port++) {
		/* Skip ports that are not enabled */
		if (!(enabled_port_mask & (1 << port)))
			continue;
		if (!kni_port_params_array[port])
			continue;

		uint8_t lcore_id = kni_port_params_array[port]->lcore_k[0];
		uint8_t socketid = rte_lcore_to_socket_id(lcore_id);
		// XXX we use another mbuf_pool here, its for kni incoming
		// packets
		if (kni_alloc(port, knimbuf_pool[socketid])) {
			rte_exit(EXIT_FAILURE, "failed to allocate kni");
		}
	}
	return 0;
}

static void
signal_handler(int signum,
	       __rte_unused siginfo_t* si,
	       __rte_unused void* unused)
{
	int sock;

	/* When we receive a RTMIN or SIGINT signal, stop kni processing */
	if (signum == SIGRTMIN || signum == SIGINT || signum == SIGQUIT ||
	    signum == SIGTERM) {
		RTE_LOG(INFO, PKTJ1,
			"SIG %d is received, and the KNI processing is "
			"going to stop\n",
			signum);
		kni_stop_loop();
		rte_atomic32_inc(&main_loop_stop);

		for (sock = 0; sock < NB_SOCKETS; sock++) {
			if (control_handle4[sock].addr) {
				pktj_cmdline_stop(sock);
				control_stop(control_handle4[sock].addr);
				control_stop(control_handle6[sock].addr);
			}
		}
	} else if (signum == SIGCHLD) {
		int pid, status;
		if ((pid = wait(&status)) > 0) {
			RTE_LOG(INFO, PKTJ1,
				"SIGCHLD received, reaped child "
				"pid: %d status %d\n",
				pid, WEXITSTATUS(status));
		}
	}
}

static int
rdtsc_thread(__rte_unused void* args)
{
	int32_t f_stop;
	uint32_t i;
	uint64_t cur_tsc;

	while (1) {
		f_stop = rte_atomic32_read(&main_loop_stop);
		if (unlikely(f_stop))
			break;
		cur_tsc = rte_rdtsc();

		for (i = 0; i < RTE_MAX_LCORE; i++) {
			glob_tsc[i] = cur_tsc;
		}
		usleep(1000);
	}

	return 0;
}

static void
spawn_management_threads(uint32_t ctrlsock,
			 pthread_t* control_tid,
			 pthread_t* rdtsc_tid)
{
	unsigned lcore_id;
	int ret;
	char thread_name[16];

	lcore_id = control_handle4[ctrlsock].lcore_id;

	RTE_LOG(INFO, PKTJ1,
		"launching control thread for socketid "
		"%d on lcore %u\n",
		ctrlsock, lcore_id);
	pthread_create(&control_tid[0], NULL, (void*)control_main,
		       control_handle4[ctrlsock].addr);
	snprintf(thread_name, sizeof(thread_name), "control4-%d", ctrlsock);
	pthread_setname_np(control_tid[0], thread_name);
	ret = pthread_setaffinity_np(control_tid[0], sizeof(cpu_set_t),
				     &lcore_config[lcore_id].cpuset);
	if (ret != 0) {
		perror("control4 pthread_setaffinity_np: ");
		rte_exit(EXIT_FAILURE,
			 "control4 pthread_setaffinity_np "
			 "returned error: err=%d,",
			 ret);
	}
	pthread_create(&control_tid[1], NULL, (void*)control_main,
		       control_handle6[ctrlsock].addr);
	snprintf(thread_name, sizeof(thread_name), "control6-%d", ctrlsock);
	pthread_setname_np(control_tid[1], thread_name);
	ret = pthread_setaffinity_np(control_tid[1], sizeof(cpu_set_t),
				     &lcore_config[lcore_id].cpuset);
	if (ret != 0) {
		perror("control6 pthread_setaffinity_np: ");
		rte_exit(EXIT_FAILURE,
			 "control6 pthread_setaffinity_np "
			 "returned error: err=%d,",
			 ret);
	}
	pthread_create(rdtsc_tid, NULL, (void*)rdtsc_thread, NULL);
	snprintf(thread_name, sizeof(thread_name), "rdtsc-%d", ctrlsock);
	pthread_setname_np(*rdtsc_tid, thread_name);
	ret = pthread_setaffinity_np(*rdtsc_tid, sizeof(cpu_set_t),
				     &lcore_config[lcore_id].cpuset);

	if (ret != 0) {
		perror("rdtsc pthread_setaffinity_np: ");
		rte_exit(EXIT_FAILURE,
			 "rdtsc pthread_setaffinity_np "
			 "returned error: err=%d,",
			 ret);
	}

	ret = pktj_cmdline_init(unixsock_path, ctrlsock);
	if (ret != 0) {
		rte_exit(EXIT_FAILURE, "pktj_cmdline_init failed");
	}
	ret = pktj_cmdline_launch(ctrlsock, &lcore_config[lcore_id].cpuset);
	if (ret != 0) {
		rte_exit(EXIT_FAILURE, "pktj_cmdline_launch failed");
	}
}

int
main(int argc, char** argv)
{
	struct lcore_conf* qconf;
	int ret;
	unsigned nb_ports;
	unsigned lcore_id;
	uint8_t portid;
	pthread_t control_tid[2] = {0};  // ipv4 and ipv6 thread
	pthread_t rdtsc_tid;
	char thread_name[16];
	struct sigaction sa;
	uint32_t ctrlsock;
	uint16_t maxsock;
	int ipv4_sock_found = 0;

	sa.sa_flags = 0;
	sigemptyset(&sa.sa_mask);
	sa.sa_sigaction = signal_handler;
	if (sigaction(SIGINT, &sa, NULL) == -1) {
		rte_exit(EXIT_FAILURE, "failed to set sigaction");
	}
	if (sigaction(SIGTERM, &sa, NULL) == -1) {
		rte_exit(EXIT_FAILURE, "failed to set sigaction");
	}
	if (sigaction(SIGQUIT, &sa, NULL) == -1) {
		rte_exit(EXIT_FAILURE, "failed to set sigaction");
	}
	if (sigaction(SIGCHLD, &sa, NULL) == -1) {
		rte_exit(EXIT_FAILURE, "failed to set sigaction");
	}

	if (prctl(PR_SET_CHILD_SUBREAPER, 1) < 0) {
		rte_exit(EXIT_FAILURE, "failed to prctl");
	}

	/* Sanitize lcore_conf */
	for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
		qconf = &lcore_conf[lcore_id];
		qconf->ipv4_lookup_struct = NULL;
		qconf->ipv6_lookup_struct = NULL;
		qconf->neighbor4_struct = NULL;
		qconf->neighbor6_struct = NULL;
	}

	/* parse application arguments (after the EAL ones) */
	ret = parse_args(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid L3FWD parameters\n");

	RTE_LCORE_FOREACH_SLAVE(lcore_id)
	{
		snprintf(thread_name, 16, "lcore-slave-%u", lcore_id);
		pthread_setname_np(lcore_config[lcore_id].thread_id,
				   thread_name);
	}
	snprintf(thread_name, 16, "lcore-master");
	pthread_setname_np(pthread_self(), thread_name);

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

	/* Add ACL rules and route entries, build trie */
	if (acl_init(0) < 0)
		rte_exit(EXIT_FAILURE, "acl_init ipv4 failed\n");
	if (acl_init(1) < 0)
		rte_exit(EXIT_FAILURE, "acl_init ipv6 failed\n");

	// look for any lcore not bound by dpdk (kni and eal) on each socket,
	// use it when found
	if (numa_on) {
		maxsock = NB_SOCKETS;
	} else {
		maxsock = 1;
	}

	for (ctrlsock = 0; ctrlsock < maxsock; ctrlsock++) {
		control_handle4[ctrlsock].addr = NULL;
		control_handle6[ctrlsock].addr = NULL;
		qconf = NULL;

		// TODO: look for all available vcpus (not only eal
		// enabled lcores)
		RTE_LCORE_FOREACH(lcore_id)
		{
			if (rte_lcore_to_socket_id(lcore_id) == ctrlsock) {
				qconf = &lcore_conf[lcore_id];
				if (qconf->n_rx_queue == 0) {
					if (!ipv4_sock_found) {
						control_handle4[ctrlsock].addr =
						    control_init(
							ctrlsock,
							NETLINK4_EVENTS);
						control_handle4[ctrlsock]
						    .lcore_id = lcore_id;
						ipv4_sock_found = 1;
						continue;
					} else {
						control_handle6[ctrlsock].addr =
						    control_init(
							ctrlsock,
							NETLINK6_EVENTS);
						control_handle6[ctrlsock]
						    .lcore_id = lcore_id;
						break;
					}
				}
			}
		}

		if (qconf) {  // check if any lcore is enabled on this
			// socket
			if (control_handle4[ctrlsock].addr == NULL ||
			    control_handle6[ctrlsock].addr == NULL) {
				// if no lcore is available on this socket
				rte_exit(EXIT_FAILURE,
					 "no free lcore found on "
					 "socket %d for control 4 or 6, "
					 "exiting ...\n",
					 ctrlsock);
			}
		}
	}

	/* init memory */
	ret = init_mem(nb_ports);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "init_mem failed\n");

	/* Initialize KNI subsystem */
	init_kni();

	if (ratelimit_file) {
		rate_limit_config_from_file(ratelimit_file);
	}

	/* initialize all ports */
	for (portid = 0; portid < nb_ports; portid++) {
		init_port(portid);
	}

	alloc_kni_ports(nb_ports);

	/* start ports */
	for (portid = 0; portid < nb_ports; portid++) {
		if ((enabled_port_mask & (1 << portid)) == 0) {
			continue;
		}
		/* Start device */
		ret = rte_eth_dev_start(portid);
		if (ret < 0)
			rte_exit(EXIT_FAILURE,
				 "rte_eth_dev_start: err=%d, port=%d\n", ret,
				 portid);

		/*
		 * If enabled, put device in promiscuous mode.
		 * This allows IO forwarding mode to forward packets
		 * to itself through 2 cross-connected  ports of the
		 * target machine.
		 */
		if (promiscuous_on)
			rte_eth_promiscuous_enable(portid);
	}

	check_all_ports_link_status((uint8_t)nb_ports, enabled_port_mask);

	if (numa_on) {
		for (ctrlsock = 0; ctrlsock < NB_SOCKETS; ctrlsock++) {
			if (control_handle4[ctrlsock].addr) {
				spawn_management_threads(ctrlsock, control_tid,
							 &rdtsc_tid);
			}
		}
	} else {
		spawn_management_threads(0, control_tid, &rdtsc_tid);
	}

	/* set a mask for tcp dst_port 179, the mask is applied to body starting
	 * at ttl field */
	mask_tcp_179 = _mm_setr_epi32(0x00000600, 0, 0, 0xb3000000);

	/* launch per-lcore init on every lcore */
	RTE_LCORE_FOREACH(lcore_id)
	{
		qconf = &lcore_conf[lcore_id];
		if (qconf->n_rx_queue != 0) {
			rte_eal_remote_launch(main_loop, NULL, lcore_id);
			snprintf(thread_name, 16, "forward-%u", lcore_id);
			pthread_setname_np(lcore_config[lcore_id].thread_id,
					   thread_name);
		}

		for (portid = 0; portid < nb_ports; portid++) {
			if (kni_port_params_array[portid]->lcore_tx ==
			    lcore_id) {
				pthread_t kni_tid;
				cpu_set_t cpuset;

				RTE_LOG(INFO, PKTJ1,
					"launching kni thread on lcore %u\n",
					lcore_id);
				pthread_create(&kni_tid, NULL,
					       (void*)kni_main_loop,
					       (void*)(uintptr_t)lcore_id);

				CPU_ZERO(&cpuset);
				CPU_SET(lcore_id, &cpuset);
				ret = pthread_setaffinity_np(
				    kni_tid, sizeof(cpu_set_t), &cpuset);
				if (ret != 0) {
					perror("kni pthread_setaffinity_np: ");
					rte_exit(EXIT_FAILURE,
						 "kni pthread_setaffinity_np "
						 "returned error: err=%d,",
						 ret);
				}
				snprintf(thread_name, 16, "kni-%u-%u", portid,
					 lcore_id);
				pthread_setname_np(kni_tid, thread_name);
			}
		}
	}

	if ((ret = control_callback_setup(callback_setup, nb_ports))) {
		perror("control_callback_setup failure with: ");
		rte_exit(EXIT_FAILURE,
			 "control callback setup returned error: err=%d,", ret);
	}

	if (control_tid[0]) {
		pthread_join(control_tid[0], NULL);
	}
	if (control_tid[1]) {
		pthread_join(control_tid[1], NULL);
	}

	RTE_LCORE_FOREACH_SLAVE(lcore_id)
	{
		RTE_LOG(INFO, PKTJ1, "waiting %u\n", lcore_id);
		if (rte_eal_wait_lcore(lcore_id) < 0)
			return -1;
	}
	RTE_LOG(INFO, PKTJ1, "rte_eal_wait_lcore finished\n");

	// childs will be handled here
	if (signal(SIGCHLD, SIG_DFL) == SIG_ERR) {
		rte_exit(EXIT_FAILURE, "failed to set sigaction");
	}
	ret = system("pkill -SIGTERM -P $PPID");
	RTE_LOG(INFO, PKTJ1, "killing remaining child processes: %d\n", ret);

	{
		int pid, status;
		while ((pid = wait(&status)) > 0) {
			RTE_LOG(DEBUG, PKTJ1,
				"Reaped child pid: %d status %d\n", pid,
				WEXITSTATUS(status));
		}
	}

	/* start ports */
	for (portid = 0; portid < nb_ports; portid++) {
		if ((enabled_port_mask & (1 << portid)) == 0) {
			continue;
		}
		RTE_LOG(INFO, PKTJ1, "freeing kniportid %d\n", portid);
		kni_free_kni(portid);
		rte_eth_dev_stop(portid);
	}

	for (ctrlsock = 0; ctrlsock < NB_SOCKETS; ctrlsock++) {
		if (control_handle4[ctrlsock].addr) {
			pktj_cmdline_terminate(ctrlsock, unixsock_path);
			control_terminate(control_handle4[ctrlsock].addr);
			control_terminate(control_handle6[ctrlsock].addr);
		}
	}

	return 0;
}
