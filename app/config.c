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
#include <sys/types.h>
#include <string.h>
#include <getopt.h>

#include <rte_string_fns.h>
#include <rte_mempool.h>
#include <rte_ethdev.h>
#include <rte_cfgfile.h>
#include <rte_malloc.h>
#include <rte_lpm6.h>
#include <cmdline_parse.h>
#include <cmdline_parse_ipaddr.h>

#include <libneighbour.h>

#include "common.h"
#include "routing.h"
#include "config.h"
#include "acl.h"
#include "kni.h"

static struct lcore_params lcore_params_array[MAX_LCORE_PARAMS];

struct lcore_params* lcore_params;
uint16_t nb_lcore_params;

/* mask of enabled ports */
uint32_t enabled_port_mask = 0;
int promiscuous_on = 0; /**< Ports set in promiscuous mode off by default. */
int numa_on = 1;	/**< NUMA is enabled by default. */
uint32_t kni_rate_limit = UINT32_MAX;
const char* callback_setup = NULL;
const char* unixsock_path = "/tmp/pktj.sock";
const char* ratelimit_file = NULL;

struct rte_eth_conf port_conf = {
    .rxmode =
	{
	    .mq_mode = ETH_MQ_RX_RSS,
	    .max_rx_pkt_len = ETHER_MAX_LEN,
	    .split_hdr_size = 0,
	    .header_split = 0,
/**< Header Split disabled */
#ifdef PKTJ_QEMU
	    .hw_ip_checksum = 0,
/**< IP checksum offload enabled */
#else
	    .hw_ip_checksum = 1,
/**< IP checksum offload enabled */
#endif
	    .hw_vlan_strip = 1,
	    .hw_vlan_filter = 0,
	    /**< VLAN filtering disabled */
	    .jumbo_frame = 0,
	    /**< Jumbo Frame Support disabled */
	    .hw_strip_crc = 0,
	    /**< CRC stripped by hardware */
	},
    .rx_adv_conf =
	{
	    .rss_conf =
		{
		    .rss_key = NULL,
		    .rss_hf = ETH_RSS_PROTO_MASK,
		},
	},
    .txmode =
	{
	    .mq_mode = ETH_MQ_TX_NONE,
	},
};

/* display usage */
void
print_usage(const char* prgname)
{
	RTE_LOG(
	    ERR, PKTJ1,
	    "%s [EAL options]\n"
	    "  [--config (port,queue,lcore)[,(port,queue,lcore]]\n"
	    "  [--kniconfig (port,lcore_tx,lcore_kthread)]\n"
	    "  [--enable-jumbo [--max-pkt-len PKTLEN (64-9000)]]\n"
	    "  [--promiscuous : enable promiscuous mode]\n"
	    "  [--unixsock PATH: override cmdline unixsock path (default: "
	    "/tmp/pktj.sock)]\n"
	    "  [--configfile PATH: use a configfile for params]\n"
	    "  [--aclavx2: Use AVX2 instructions to do lookupi n acl tables]\n"
	    "  [--no-numa: disable numa awareness]\n"
	    "  [--kni_rate_limit RATELIMIT: rate limit the packets sent to the "
	    "kni]\n"
	    "  --portmask PORTMASK: hexadecimal bitmask of ports to configure\n"
	    "  --callback-setup: script called when ifaces are set up\n"
	    "  --rule_ipv4=FILE \n"
	    "  --rule_ipv6=FILE \n",
	    prgname);
}

static int
parse_max_pkt_len(const char* pktlen)
{
	char* end = NULL;
	unsigned long len;

	/* parse decimal string */
	len = strtoul(pktlen, &end, 10);
	if ((pktlen[0] == '\0') || (end == NULL) || (*end != '\0'))
		return -1;

	if (len == 0)
		return -1;

	return len;
}

static int
parse_portmask(const char* portmask)
{
	char* end = NULL;
	unsigned long pm;

	/* parse hexadecimal string */
	pm = strtoul(portmask, &end, 16);
	if ((portmask[0] == '\0') || (end == NULL) || (*end != '\0'))
		return -1;

	if (pm == 0)
		return -1;

	return pm;
}

static void
print_kni_config(void)
{
	uint32_t i, j;
	struct kni_port_params** p = kni_port_params_array;

	for (i = 0; i < RTE_MAX_ETHPORTS; i++) {
		if (!p[i])
			continue;
		RTE_LOG(DEBUG, KNI, "Port ID: %d\n", p[i]->port_id);
		RTE_LOG(DEBUG, KNI, "Tx lcore ID: %u\n", p[i]->lcore_tx);
		for (j = 0; j < p[i]->nb_lcore_k; j++)
			RTE_LOG(DEBUG, KNI, "Kernel thread lcore ID: %u\n",
				p[i]->lcore_k[j]);
	}
}

static int
kni_parse_config(const char* arg)
{
	const char *p, *p0 = arg;
	char s[256], *end;
	unsigned size;
	enum fieldnames {
		FLD_PORT = 0,
		FLD_LCORE_TX,
		_NUM_FLD = KNI_MAX_KTHREAD + 3,
	};
	int i, j, nb_token;
	char* str_fld[_NUM_FLD];
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
			RTE_LOG(ERR, KNI, "Invalid config parameters\n");
			goto fail;
		}
		snprintf(s, sizeof(s), "%.*s", size, p);
		nb_token = rte_strsplit(s, sizeof(s), str_fld, _NUM_FLD, ',');
		if (nb_token <= FLD_LCORE_TX) {
			RTE_LOG(ERR, KNI, "Invalid config parameters\n");
			goto fail;
		}
		for (i = 0; i < nb_token; i++) {
			errno = 0;
			int_fld[i] = strtoul(str_fld[i], &end, 0);
			if (errno != 0 || end == str_fld[i]) {
				RTE_LOG(ERR, KNI,
					"Invalid config parameters\n");
				goto fail;
			}
		}

		port_id = (uint8_t)int_fld[FLD_PORT];
		if (port_id >= RTE_MAX_ETHPORTS) {
			RTE_LOG(ERR, KNI,
				"Port ID %d could not exceed the maximum %d\n",
				port_id, RTE_MAX_ETHPORTS);
			goto fail;
		}
		if (kni_port_params_array[port_id]) {
			RTE_LOG(ERR, KNI, "Port %d has been configured\n",
				port_id);
			goto fail;
		}
		kni_port_params_array[port_id] =
		    (struct kni_port_params*)rte_zmalloc(
			"KNI_port_params", sizeof(struct kni_port_params),
			RTE_CACHE_LINE_SIZE);
		kni_port_params_array[port_id]->port_id = port_id;

		kni_port_params_array[port_id]->tx_queue_id =
		    get_port_n_rx_queues(port_id);

		kni_port_params_array[port_id]->lcore_tx =
		    (uint8_t)int_fld[FLD_LCORE_TX];
		if (kni_port_params_array[port_id]->lcore_tx >= RTE_MAX_LCORE) {
			RTE_LOG(ERR, KNI,
				"lcore_tx %u ID could not "
				"exceed the maximum %u\n",
				kni_port_params_array[port_id]->lcore_tx,
				(unsigned)RTE_MAX_LCORE);
			goto fail;
		}
		i = FLD_LCORE_TX + 1;
		for (j = 0; i < nb_token && j < KNI_MAX_KTHREAD; i++, j++)
			kni_port_params_array[port_id]->lcore_k[j] =
			    (uint8_t)int_fld[i];
		kni_port_params_array[port_id]->nb_lcore_k = j;
	}
	print_kni_config();

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

static int
kni_parse_config_from_file(uint8_t port_id, char* q_arg)
{
	char* end;
	enum fieldnames {
		FLD_LCORE = 0,
		_NUM_FLD = KNI_MAX_KTHREAD + 3,
	};
	int i, j, nb_token;
	char* str_fld[_NUM_FLD];
	unsigned long int_fld[_NUM_FLD];

	nb_token = rte_strsplit(q_arg, strlen(q_arg), str_fld, _NUM_FLD, ',');

	if (nb_token <= FLD_LCORE) {
		RTE_LOG(ERR, KNI, "Invalid config parameters\n");
		goto fail;
	}
	for (i = 0; i < nb_token; i++) {
		errno = 0;
		int_fld[i] = strtoul(str_fld[i], &end, 0);
		if (errno != 0 || end == str_fld[i]) {
			RTE_LOG(ERR, KNI, "Invalid config parameters\n");
			goto fail;
		}
	}

	if (port_id >= RTE_MAX_ETHPORTS) {
		RTE_LOG(ERR, KNI,
			"Port ID %d could not exceed the maximum %d\n", port_id,
			RTE_MAX_ETHPORTS);
		goto fail;
	}
	if (kni_port_params_array[port_id]) {
		RTE_LOG(ERR, KNI, "Port %d has already been configured\n",
			port_id);
		goto fail;
	}
	kni_port_params_array[port_id] = (struct kni_port_params*)rte_zmalloc(
	    "KNI_port_params", sizeof(struct kni_port_params),
	    RTE_CACHE_LINE_SIZE);
	kni_port_params_array[port_id]->port_id = port_id;

	kni_port_params_array[port_id]->tx_queue_id =
	    get_port_n_rx_queues(port_id);

	kni_port_params_array[port_id]->lcore_tx = (uint8_t)int_fld[FLD_LCORE];
	if (kni_port_params_array[port_id]->lcore_tx >= RTE_MAX_LCORE) {
		RTE_LOG(ERR, KNI,
			"lcore_tx %u ID could not "
			"exceed the maximum %u\n",
			kni_port_params_array[port_id]->lcore_tx,
			(unsigned)RTE_MAX_LCORE);
		goto kni_fail;
	}
	i = FLD_LCORE + 1;
	for (j = 0; i < nb_token && j < KNI_MAX_KTHREAD; i++, j++)
		kni_port_params_array[port_id]->lcore_k[j] =
		    (uint8_t)int_fld[i];
	kni_port_params_array[port_id]->nb_lcore_k = j;

	return 0;

kni_fail:
	if (kni_port_params_array[port_id]) {
		rte_free(kni_port_params_array[port_id]);
		kni_port_params_array[port_id] = NULL;
	}
fail:

	return -1;
}

static int
kni_validate_parameters(uint32_t portmask)
{
	uint32_t i;

	if (!portmask) {
		RTE_LOG(ERR, KNI, "No port configured in port mask\n");
		return -1;
	}

	for (i = 0; i < RTE_MAX_ETHPORTS; i++) {
		if (((portmask & (1 << i)) && !kni_port_params_array[i]) ||
		    (!(portmask & (1 << i)) && kni_port_params_array[i]))
			rte_exit(EXIT_FAILURE,
				 "portmask is not consistent "
				 "to port ids specified in --config\n");
		if (kni_port_params_array[i] &&
		    !rte_lcore_is_enabled(
			(unsigned)(kni_port_params_array[i]->lcore_tx)))
			rte_exit(EXIT_FAILURE,
				 "lcore id %u for "
				 "port %d transmitting not enabled\n",
				 kni_port_params_array[i]->lcore_tx,
				 kni_port_params_array[i]->port_id);
	}

	return 0;
}

static int
parse_config(const char* q_arg)
{
	char s[256];
	const char *p, *p0 = q_arg;
	char* end;
	enum fieldnames { FLD_PORT = 0, FLD_QUEUE, FLD_LCORE, _NUM_FLD };
	unsigned long int_fld[_NUM_FLD];
	char* str_fld[_NUM_FLD];
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
		if (rte_strsplit(s, sizeof(s), str_fld, _NUM_FLD, ',') !=
		    _NUM_FLD)
			return -1;
		for (i = 0; i < _NUM_FLD; i++) {
			errno = 0;
			int_fld[i] = strtoul(str_fld[i], &end, 0);
			if (errno != 0 || end == str_fld[i] || int_fld[i] > 255)
				return -1;
		}
		if (nb_lcore_params >= MAX_LCORE_PARAMS) {
			RTE_LOG(ERR, PKTJ1,
				"exceeded max number of lcore params: %hu\n",
				nb_lcore_params);
			return -1;
		}
		lcore_params_array[nb_lcore_params].port_id =
		    (uint8_t)int_fld[FLD_PORT];
		lcore_params_array[nb_lcore_params].queue_id =
		    (uint8_t)int_fld[FLD_QUEUE];
		lcore_params_array[nb_lcore_params].lcore_id =
		    (uint8_t)int_fld[FLD_LCORE];
		++nb_lcore_params;
	}
	lcore_params = lcore_params_array;
	return 0;
}

static int
parse_config_from_file(uint8_t port_id, char* q_arg)
{
	char* end;
	enum fieldnames { FLD_QUEUE = 0, FLD_LCORE, _NUM_FLD };
	unsigned long int_fld[_NUM_FLD];
	char* str_fld[_NUM_FLD];
	char* str_tuples[MAX_LCORE_PARAMS];
	int i, j, nb_tuples;

	nb_tuples = rte_strsplit(q_arg, strlen(q_arg), str_tuples,
				 MAX_LCORE_PARAMS, ' ');

	for (j = 0; j < nb_tuples; j++) {
		if (rte_strsplit(str_tuples[j], strlen(str_tuples[j]), str_fld,
				 _NUM_FLD, ',') != _NUM_FLD) {
			return -1;
		}

		for (i = 0; i < _NUM_FLD; i++) {
			errno = 0;
			int_fld[i] = strtoul(str_fld[i], &end, 0);
			if (errno != 0 || end == str_fld[i] ||
			    int_fld[i] > 255) {
				return -1;
			}
		}

		if (nb_lcore_params >= MAX_LCORE_PARAMS) {
			RTE_LOG(ERR, PKTJ1,
				"exceeded max number of lcore params: %hu\n",
				nb_lcore_params);
			return -1;
		}
		lcore_params_array[nb_lcore_params].port_id = port_id;
		lcore_params_array[nb_lcore_params].queue_id =
		    (uint8_t)int_fld[FLD_QUEUE];
		lcore_params_array[nb_lcore_params].lcore_id =
		    (uint8_t)int_fld[FLD_LCORE];
		++nb_lcore_params;
	}

	lcore_params = lcore_params_array;
	return 0;
}

static int
rate_limit_ipv4(union rlimit_addr* addr, uint32_t num, int socket_id)
{
	uint8_t range_id;
	static uint8_t next_range_id[NB_SOCKETS] = {0};

	range_id = rlimit4_lookup_table[socket_id][addr->network];
	// check if this cidr range is the lookup table
	if (range_id == INVALID_RLIMIT_RANGE) {
		range_id = next_range_id[socket_id]++;

		if (range_id >= MAX_RLIMIT_RANGE) {  // if not found
			return -1;
		}
	}

	// set slot for this cidr range in the lookup table
	// and set the max packet rate for this dest addr
	rlimit4_lookup_table[socket_id][addr->network] = range_id;
	rlimit4_max[socket_id][range_id][addr->host] = num;

	return 0;
}

static int
rate_limit_ipv6(cmdline_ipaddr_t* ip, uint32_t num, int socket_id)
{
	static uint8_t next_hop_count[NB_SOCKETS] = {0};
	uint16_t next_hop = 0;

	// store the rule so it can applied once
	// it is added if it is not already

	// check if this address is already stored
	for (next_hop = 0; next_hop < NEI_NUM_ENTRIES; next_hop++) {
		// if addresses match
		if (!memcmp(&rlimit6_lookup_table[socket_id][next_hop].addr,
			    &ip->addr.ipv6, sizeof(struct in6_addr))) {
			break;
		}
	}

	// otherwise try to allocate new slot for storage
	if (next_hop == NEI_NUM_ENTRIES) {
		// no more slot available
		if (next_hop_count[socket_id] == NEI_NUM_ENTRIES - 1) {
			return -1;
		}

		next_hop = next_hop_count[socket_id]++;
	}

	rte_memcpy(&rlimit6_lookup_table[socket_id][next_hop].addr,
		   &ip->addr.ipv6, sizeof(struct in6_addr));
	rlimit6_lookup_table[socket_id][next_hop].num = num;

	if (rte_lpm6_lookup(ipv6_pktj_lookup_struct[socket_id],
			    ip->addr.ipv6.s6_addr, (uint8_t*)&next_hop) == 0) {
		// set the max packet rate for this neighbor
		rlimit6_max[socket_id][next_hop] = num;
	}

	return 0;
}

int
rate_limit_address(cmdline_ipaddr_t* ip, uint32_t num, int socket_id)
{
	int i, res;
	uint32_t netmask, netaddr, maxhost, j;

	res = 0;
	if (ip->family == AF_INET) {
		if (ip->prefixlen > 0) {
			// rate limit range
			netmask = ~(UINT32_MAX >> ip->prefixlen);
			netaddr =
			    rte_be_to_cpu_32(ip->addr.ipv4.s_addr) & netmask;
			maxhost = netaddr + (1 << (32 - ip->prefixlen));
			if (socket_id == SOCKET_ID_ANY) {
				for (i = 0; i < NB_SOCKETS; i++) {
					for (j = netaddr; j < maxhost; j++) {
						rate_limit_ipv4(
						    (union rlimit_addr*)&j, num,
						    i);
					}
				}
			} else {
				for (j = netaddr; j < maxhost; j++) {
					rate_limit_ipv4((union rlimit_addr*)&j,
							num, socket_id);
				}
			}
		} else {
			netaddr = rte_be_to_cpu_32(ip->addr.ipv4.s_addr);
			if (socket_id == SOCKET_ID_ANY) {
				for (i = 0; i < NB_SOCKETS; i++) {
					res += rate_limit_ipv4(
					    (union rlimit_addr*)&netaddr, num,
					    i);
				}
			} else {
				res = rate_limit_ipv4(
				    (union rlimit_addr*)&netaddr, num,
				    socket_id);
			}
		}
	} else if (ip->family == AF_INET6) {
		if (socket_id == SOCKET_ID_ANY) {  // rate limit for all sockets
			for (i = 0; i < NB_SOCKETS; i++) {
				res += rate_limit_ipv6(ip, num, i);
			}
		} else {
			res = rate_limit_ipv6(ip, num, socket_id);
		}
	}

	return res;
}

void
rate_limit_config_from_file(const char* file_name)
{
	char buff[LINE_MAX];
	enum fieldnames { FLD_ADDRESS = 0, FLD_RATE, _NUM_FLD };
	char* str_fld[_NUM_FLD];
	cmdline_parse_token_ipaddr_t tk, tk_net;
	cmdline_ipaddr_t ip_addr;
	uint32_t num;

	FILE* fh = fopen(file_name, "rb");

	if (fh == NULL) {
		RTE_LOG(ERR, PKTJ1,
			"Could not open rate limit config file: %s\n",
			file_name);
		return;
	}

	tk.ipaddr_data.flags = CMDLINE_IPADDR_V4 | CMDLINE_IPADDR_V6;
	tk_net.ipaddr_data.flags =
	    CMDLINE_IPADDR_V4 | CMDLINE_IPADDR_V6 | CMDLINE_IPADDR_NETWORK;

	while ((fgets(buff, LINE_MAX, fh) != NULL)) {
		if (rte_strsplit(buff, strlen(buff), str_fld, _NUM_FLD, ' ') !=
		    _NUM_FLD) {
			continue;
		}

		sscanf(str_fld[FLD_RATE], "%u", &num);
		if (cmdline_parse_ipaddr((cmdline_parse_token_hdr_t*)&tk_net,
					 str_fld[FLD_ADDRESS], &ip_addr,
					 sizeof(ip_addr)) > 0 ||
		    cmdline_parse_ipaddr((cmdline_parse_token_hdr_t*)&tk,
					 str_fld[FLD_ADDRESS], &ip_addr,
					 sizeof(ip_addr)) > 0) {
			if (rate_limit_address(&ip_addr, num, SOCKET_ID_ANY) ==
			    0) {
				RTE_LOG(INFO, PKTJ1, "rate limited %s to %d\n",
					str_fld[FLD_ADDRESS], num);
			}
		} else {  // invalid address
			RTE_LOG(ERR, PKTJ1, "could not rate limit %s to %d\n",
				str_fld[FLD_ADDRESS], num);
		}
	}

	fclose(fh);
}

static int
install_cfgfile(const char* file_name, char* prgname)
{
	struct rte_cfgfile* file;
	uint32_t n_ports, i, ret;
	const char* entry;
	char section_name[16], *ptr;

	if (file_name[0] == '\0')
		return -1;

	file = rte_cfgfile_load(file_name, 0);
	if (file == NULL) {
		rte_exit(EXIT_FAILURE, "Config file %s not found\n", file_name);
		return -1;
	}

	n_ports = (uint32_t)rte_cfgfile_num_sections(file, "port",
						     sizeof("port") - 1);

	if (n_ports >= RTE_MAX_ETHPORTS) {
		rte_exit(EXIT_FAILURE,
			 "Ports %d could not exceed the maximum %d\n", n_ports,
			 RTE_MAX_ETHPORTS);
		return -1;
	}

	nb_lcore_params = 0;
	memset(&kni_port_params_array, 0, sizeof(kni_port_params_array));

	for (i = 0; i < n_ports; i++) {
		snprintf(section_name, sizeof(section_name), "port %u", i);
		if (!rte_cfgfile_has_section(file, section_name)) {
			rte_exit(EXIT_FAILURE,
				 "Config file parse error: port IDs are not "
				 "sequential (port %u missing)\n",
				 i);
			return -1;
		}

		enabled_port_mask |= (1 << i);

		entry = rte_cfgfile_get_entry(file, section_name, "eal queues");
		if (!entry) {
			rte_exit(
			    EXIT_FAILURE,
			    "Config file parse error: EAL queues for port %u "
			    "not defined\n",
			    i);
			return -1;
		}

		ptr = strdup(entry);
		if (!ptr) {
			rte_exit(EXIT_FAILURE,
				 "Config file parse error: Could "
				 "not allocate memory for "
				 "strdup\n");
			return -1;
		}
		ret = parse_config_from_file(i, ptr);
		free(ptr);

		if (ret) {
			RTE_LOG(ERR, PKTJ1, "invalid config\n");
			print_usage(prgname);
			return -1;
		}

		entry = rte_cfgfile_get_entry(file, section_name, "kni");
		if (!entry) {
			rte_exit(EXIT_FAILURE,
				 "Config file parse error: KNI "
				 "core queues for port %u "
				 "not defined\n",
				 i);
			return -1;
		}

		ptr = strdup(entry);
		if (!ptr) {
			rte_exit(EXIT_FAILURE,
				 "Config file parse error: Could "
				 "not allocate memory for "
				 "strdup\n");
			return -1;
		}
		ret = kni_parse_config_from_file(i, ptr);
		free(ptr);

		if (ret) {
			RTE_LOG(ERR, PKTJ1, "Invalid config\n");
			print_usage(prgname);
			return -1;
		}
	}

	entry = rte_cfgfile_get_entry(file, FILE_MAIN_CONFIG,
				      CMD_LINE_OPT_UNIXSOCK);
	if (entry) {
		unixsock_path = strdup(entry);
	}

	entry = rte_cfgfile_get_entry(file, FILE_MAIN_CONFIG,
				      CMD_LINE_OPT_CALLBACK_SETUP);
	if (entry) {
		callback_setup = strdup(entry);
	}

	entry = rte_cfgfile_get_entry(file, FILE_MAIN_CONFIG,
				      CMD_LINE_OPT_KNI_RATE_LIMIT);
	if (entry) {
		if ((ret = strtoul(entry, NULL, 0)) > 0) {
			kni_rate_limit = ret;
		}
	}

	entry = rte_cfgfile_get_entry(file, FILE_MAIN_CONFIG,
				      CMD_LINE_OPT_RULE_IPV4);
	if (entry) {
		acl_parm_config.rule_ipv4_name = strdup(entry);
	}

	entry = rte_cfgfile_get_entry(file, FILE_MAIN_CONFIG,
				      CMD_LINE_OPT_RULE_IPV6);
	if (entry) {
		acl_parm_config.rule_ipv6_name = strdup(entry);
	}

	entry = rte_cfgfile_get_entry(file, FILE_MAIN_CONFIG,
				      CMD_LINE_OPT_RATE_LIMIT);
	if (entry) {
		ratelimit_file = strdup(entry);
	}

	/*      optional    */
	entry =
	    rte_cfgfile_get_entry(file, FILE_MAIN_CONFIG, CMD_LINE_OPT_PROMISC);
	if (entry) {
		if (strtoul(entry, NULL, 0)) {
			RTE_LOG(INFO, PKTJ1, "Promiscuous mode selected\n");
			promiscuous_on = 1;
		}
	}

	entry =
	    rte_cfgfile_get_entry(file, FILE_MAIN_CONFIG, CMD_LINE_OPT_NO_NUMA);
	if (entry) {
		if (strtoul(entry, NULL, 0)) {
			RTE_LOG(INFO, PKTJ1, "numa is disabled \n");
			numa_on = 0;
		}
	}

	entry =
	    rte_cfgfile_get_entry(file, FILE_MAIN_CONFIG, CMD_LINE_OPT_ACLAVX2);
	if (entry) {
		if (strtoul(entry, NULL, 0)) {
			acl_parm_config.aclavx2 = 1;
		}
	}

	entry = rte_cfgfile_get_entry(file, FILE_MAIN_CONFIG,
				      CMD_LINE_OPT_ENABLE_JUMBO);
	if (entry) {
		if (strtoul(entry, NULL, 0)) {
			RTE_LOG(INFO, PKTJ1,
				"jumbo frame is enabled - "
				"disabling simple TX path\n");
			port_conf.rxmode.jumbo_frame = 1;

			entry = rte_cfgfile_get_entry(file, FILE_MAIN_CONFIG,
						      CMD_LINE_OPT_MAXPKT_LEN);
			if (entry) {
				ret = parse_max_pkt_len(entry);
				if ((ret < 64) || (ret > MAX_JUMBO_PKT_LEN)) {
					RTE_LOG(ERR, PKTJ1,
						"invalid packet length\n");
					print_usage(prgname);
					return -1;
				}
				port_conf.rxmode.max_rx_pkt_len = ret;
			}

			RTE_LOG(INFO, PKTJ1,
				"set jumbo frame max packet length to %u\n",
				(unsigned int)port_conf.rxmode.max_rx_pkt_len);
		}
	}

	print_kni_config();

	rte_cfgfile_close(file);

	return 0;
}

/* Parse the argument given in the command line of the application */
int
parse_args(int argc, char** argv)
{
	int opt, ret;
	char** argvopt;
	int option_index;
	char* prgname = argv[0];
	char* end;
	static struct option lgopts[] = {{CMD_LINE_OPT_CONFIG, 1, 0, 0},
					 {CMD_LINE_OPT_KNICONFIG, 1, 0, 0},
					 {CMD_LINE_OPT_CALLBACK_SETUP, 1, 0, 0},
					 {CMD_LINE_OPT_UNIXSOCK, 1, 0, 0},
					 {CMD_LINE_OPT_RULE_IPV4, 1, 0, 0},
					 {CMD_LINE_OPT_RULE_IPV6, 1, 0, 0},
					 {CMD_LINE_OPT_ACLAVX2, 0, 0, 0},
					 {CMD_LINE_OPT_PROMISC, 0, 0, 0},
					 {CMD_LINE_OPT_NO_NUMA, 0, 0, 0},
					 {CMD_LINE_OPT_ENABLE_JUMBO, 0, 0, 0},
					 {CMD_LINE_OPT_PORTMASK, 1, 0, 0},
					 {CMD_LINE_OPT_CONFIGFILE, 1, 0, 0},
					 {NULL, 0, 0, 0}};

	/* init EAL */
	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid EAL parameters\n");
	argc -= ret;
	argv += ret;

	for (opt = 1; opt < argc; opt++) {
		if (strcmp(argv[opt], "--configfile") == 0 &&
		    argv[opt + 1] != NULL) {
			return install_cfgfile(argv[opt + 1], prgname);
		}
	}

	argvopt = argv;

	while ((opt = getopt_long(argc, argvopt, "", lgopts, &option_index)) !=
	       EOF) {
		switch (opt) {
		/* long options */
		case 0:
			if (!strncmp(lgopts[option_index].name,
				     CMD_LINE_OPT_KNICONFIG,
				     sizeof(CMD_LINE_OPT_KNICONFIG))) {
				ret = kni_parse_config(optarg);
				if (ret) {
					RTE_LOG(ERR, PKTJ1, "Invalid config\n");
					print_usage(prgname);
					return -1;
				}
			}

			if (!strncmp(lgopts[option_index].name,
				     CMD_LINE_OPT_CONFIG,
				     sizeof(CMD_LINE_OPT_CONFIG))) {
				ret = parse_config(optarg);
				if (ret) {
					RTE_LOG(ERR, PKTJ1, "invalid config\n");
					print_usage(prgname);
					return -1;
				}
			}

			if (!strncmp(lgopts[option_index].name,
				     CMD_LINE_OPT_PORTMASK,
				     sizeof(CMD_LINE_OPT_PORTMASK))) {
				enabled_port_mask = parse_portmask(optarg);
				if (enabled_port_mask == 0) {
					RTE_LOG(ERR, PKTJ1,
						"invalid portmask\n");
					print_usage(prgname);
					return -1;
				}
			}

			if (!strncmp(lgopts[option_index].name,
				     CMD_LINE_OPT_UNIXSOCK,
				     sizeof(CMD_LINE_OPT_UNIXSOCK))) {
				unixsock_path = optarg;
			}

			if (!strncmp(lgopts[option_index].name,
				     CMD_LINE_OPT_CALLBACK_SETUP,
				     sizeof(CMD_LINE_OPT_CALLBACK_SETUP))) {
				callback_setup = optarg;
			}

			if (!strncmp(lgopts[option_index].name,
				     CMD_LINE_OPT_PROMISC,
				     sizeof(CMD_LINE_OPT_NO_NUMA))) {
				promiscuous_on = 1;
			}

			if (!strncmp(lgopts[option_index].name,
				     CMD_LINE_OPT_NO_NUMA,
				     sizeof(CMD_LINE_OPT_NO_NUMA))) {
				RTE_LOG(INFO, PKTJ1, "numa is disabled \n");
				numa_on = 0;
			}

			if (!strncmp(lgopts[option_index].name,
				     CMD_LINE_OPT_KNI_RATE_LIMIT,
				     sizeof(CMD_LINE_OPT_KNI_RATE_LIMIT))) {
				kni_rate_limit = strtoul(optarg, &end, 10);
			}

			if (!strncmp(lgopts[option_index].name,
				     CMD_LINE_OPT_RULE_IPV4,
				     sizeof(CMD_LINE_OPT_RULE_IPV4))) {
				acl_parm_config.rule_ipv4_name = optarg;
			}

			if (!strncmp(lgopts[option_index].name,
				     CMD_LINE_OPT_RULE_IPV6,
				     sizeof(CMD_LINE_OPT_RULE_IPV6))) {
				acl_parm_config.rule_ipv6_name = optarg;
			}

			if (!strncmp(lgopts[option_index].name,
				     CMD_LINE_OPT_ACLAVX2,
				     sizeof(CMD_LINE_OPT_ACLAVX2))) {
				acl_parm_config.aclavx2 = 1;
			}

			if (!strncmp(lgopts[option_index].name,
				     CMD_LINE_OPT_ENABLE_JUMBO,
				     sizeof(CMD_LINE_OPT_ENABLE_JUMBO))) {
				struct option lenopts = {
				    CMD_LINE_OPT_MAXPKT_LEN, required_argument,
				    0, 0};

				RTE_LOG(INFO, PKTJ1,
					"jumbo frame is enabled "
					"- disabling simple TX "
					"path\n");
				port_conf.rxmode.jumbo_frame = 1;

				/* if no max-pkt-len set, use the default value
				 * ETHER_MAX_LEN */
				if (0 == getopt_long(argc, argvopt, "",
						     &lenopts, &option_index)) {
					ret = parse_max_pkt_len(optarg);
					if ((ret < 64) ||
					    (ret > MAX_JUMBO_PKT_LEN)) {
						RTE_LOG(
						    ERR, PKTJ1,
						    "invalid packet length\n");
						print_usage(prgname);
						return -1;
					}
					port_conf.rxmode.max_rx_pkt_len = ret;
				}
				RTE_LOG(
				    INFO, PKTJ1,
				    "set jumbo frame max packet length to %u\n",
				    (unsigned int)
					port_conf.rxmode.max_rx_pkt_len);
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
	optind = 0; /* reset getopt lib */
	return ret;
}
