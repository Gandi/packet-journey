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

void print_usage(const char* prgname);
int parse_args(int argc, char** argv);
uint8_t get_port_n_rx_queues(uint8_t port);
void rate_limit_config_from_file(const char* file_name);
int rate_limit_address(cmdline_ipaddr_t* ip, uint32_t num, int socket_id);

extern uint16_t nb_lcore_params;
extern struct lcore_params* lcore_params;
extern uint32_t enabled_port_mask;
extern int promiscuous_on;
extern int numa_on;
extern uint32_t kni_rate_limit;
extern const char* callback_setup;
extern const char* unixsock_path;
extern const char* ratelimit_file;
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
	struct rte_mbuf* m_table[MAX_PKT_BURST];
};

#define INVALID_RLIMIT_RANGE UINT8_MAX
#define MAX_RLIMIT_RANGE 10  // max number of cidr ranges that can be limited

#define RLIMIT_RANGE 16  // group addresses by /16
#define MAX_RLIMIT_RANGE_NET \
	(1 << RLIMIT_RANGE)  // max number of subnets for that prefix
#define MAX_RLIMIT_RANGE_HOST \
	(1 << (32 - RLIMIT_RANGE))  // max number of hosts in a range

struct lcore_conf {
	uint16_t n_rx_queue;
	struct lcore_rx_queue rx_queue_list[MAX_RX_QUEUE_PER_LCORE];
	uint16_t tx_queue_id[RTE_MAX_ETHPORTS];
	struct mbuf_table tx_mbufs[RTE_MAX_ETHPORTS];
	lookup_struct_t* ipv4_lookup_struct;
	lookup6_struct_t* ipv6_lookup_struct;
	neighbor_struct_t* neighbor4_struct;
	neighbor_struct_t* neighbor6_struct;
	struct rte_acl_ctx *cur_acx_ipv4, *new_acx_ipv4;
	struct rte_acl_ctx *cur_acx_ipv6, *new_acx_ipv6;
	uint32_t kni_rate_limit_cur;

	// counter for each lower part of
	// dest ipv4 addrs in ratelimited cidr ranges
	uint32_t rlimit4_cur[MAX_RLIMIT_RANGE][MAX_RLIMIT_RANGE_HOST];
	uint32_t
	    rlimit6_cur[NEI_NUM_ENTRIES];  // counter for each ipv6 neighbor
} __rte_cache_aligned;

extern struct lcore_conf lcore_conf[RTE_MAX_LCORE];

struct rlimit6_data {
	struct in6_addr addr;
	uint32_t num;
};

union rlimit_addr {
	struct {
		uint32_t host : (32 - RLIMIT_RANGE);
		uint32_t network : RLIMIT_RANGE;
	};
	uint32_t addr;
};
extern uint8_t rlimit4_lookup_table[NB_SOCKETS][MAX_RLIMIT_RANGE_NET];
extern struct rlimit6_data rlimit6_lookup_table[NB_SOCKETS][NEI_NUM_ENTRIES];
extern uint32_t rlimit4_max[NB_SOCKETS][MAX_RLIMIT_RANGE]
			   [MAX_RLIMIT_RANGE_HOST];
extern uint32_t rlimit6_max[NB_SOCKETS][NEI_NUM_ENTRIES];

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
#define CMD_LINE_OPT_RATE_LIMIT "rate_limit"

#define FILE_MAIN_CONFIG "pktj"

#define MAX_LCORE_PARAMS 1024
#define MAX_JUMBO_PKT_LEN 9600

#endif
