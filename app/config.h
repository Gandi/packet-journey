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

#ifndef __PKTJ_CONFIG_H
#define __PKTJ_CONFIG_H

void print_usage(const char *prgname);
int parse_args(int argc, char **argv);
uint8_t get_port_n_rx_queues(uint8_t port);

extern uint16_t nb_lcore_params;
extern struct lcore_params *lcore_params;
extern uint32_t enabled_port_mask;
extern int promiscuous_on;
extern int numa_on;
extern uint32_t kni_rate_limit;
extern const char *callback_setup;
extern const char *unixsock_path;
extern struct rte_eth_conf port_conf;

struct lcore_params {
	uint8_t port_id;
	uint8_t queue_id;
	uint8_t lcore_id;
} __rte_cache_aligned;

#define MAX_RX_QUEUE_PER_LCORE 16
#define MAX_TX_QUEUE_PER_PORT RTE_MAX_ETHPORTS
#define MAX_RX_QUEUE_PER_PORT 128

struct lcore_rx_queue {
	uint8_t port_id;
	uint8_t queue_id;
} __rte_cache_aligned;

struct mbuf_table {
	uint16_t len;
	struct rte_mbuf *m_table[MAX_PKT_BURST];
};

#define MAX_RLIMIT_RANGE                                                       \
	(10 + 1) // maximum number of /16 ranges limited (+ 1 will be removed
		 // asap, have to define some invalid range value)

struct lcore_conf {
	uint16_t n_rx_queue;
	struct lcore_rx_queue rx_queue_list[MAX_RX_QUEUE_PER_LCORE];
	uint16_t tx_queue_id[RTE_MAX_ETHPORTS];
	struct mbuf_table tx_mbufs[RTE_MAX_ETHPORTS];
	lookup_struct_t *ipv4_lookup_struct;
	lookup6_struct_t *ipv6_lookup_struct;
	neighbor_struct_t *neighbor4_struct;
	neighbor_struct_t *neighbor6_struct;
	struct rte_acl_ctx *cur_acx_ipv4, *new_acx_ipv4;
	struct rte_acl_ctx *cur_acx_ipv6, *new_acx_ipv6;
	uint32_t kni_rate_limit_cur;
	uint32_t rlimit4_cur[MAX_RLIMIT_RANGE][UINT16_MAX + 1];
	uint32_t rlimit6_cur[NEI_NUM_ENTRIES];
} __rte_cache_aligned;

extern struct lcore_conf lcore_conf[RTE_MAX_LCORE];

extern uint8_t rlimit4_lookup_table[UINT16_MAX + 1];
extern uint32_t rlimit4_max[MAX_RLIMIT_RANGE][UINT16_MAX + 1];
extern uint32_t rlimit6_max[NEI_NUM_ENTRIES];

#define CMD_LINE_OPT_CONFIG "config"
#define CMD_LINE_OPT_KNICONFIG "kniconfig"
#define CMD_LINE_OPT_CALLBACK_SETUP "callback-setup"
#define CMD_LINE_OPT_UNIXSOCK "unixsock"
#define CMD_LINE_OPT_RULE_IPV4 "rule_ipv4"
#define CMD_LINE_OPT_RULE_IPV6 "rule_ipv6"
#define CMD_LINE_OPT_ACLAVX2 "aclavx2"
#define CMD_LINE_OPT_PROMISC "promiscuous"
#define CMD_LINE_OPT_NO_NUMA "no-numa"
#define CMD_LINE_OPT_ENABLE_JUMBO "enable-jumbo"
#define CMD_LINE_OPT_MAXPKT_LEN "max-pkt-len"
#define CMD_LINE_OPT_PORTMASK "portmask"
#define CMD_LINE_OPT_CONFIGFILE "configfile"
#define CMD_LINE_OPT_KNI_RATE_LIMIT "kni_rate_limit"

#define FILE_MAIN_CONFIG "pktj"

#define MAX_LCORE_PARAMS 1024
#define MAX_JUMBO_PKT_LEN 9600

#endif
