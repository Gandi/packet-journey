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

#include <rte_common.h>
#include <rte_byteorder.h>
#include <rte_debug.h>
#include <rte_log.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_pci.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_string_fns.h>
#include <termios.h>

#include <cmdline_rdline.h>
#include <cmdline_parse.h>
#include <cmdline.h>

#include "common.h"
#include "stats.h"
#include "cmdline.h"

#define STATS_JSON_PRE "{\"lcores\": ["
#define STATS_JSON_LCORE                                             \
	"{\"time\": %lu, \"lcore\": %u, \"portid\": %lu, \"loop\": " \
	"%lu, \"tx\": %lu, \"rx\": %lu, \"kni_tx\": "                \
	"%lu, \"kni_rx\": %lu, \"drop\": %lu, "                      \
	"\"kni_drop\": %lu, \"acl_drop\": %lu, \"rate_drop\": %lu}, "
#define STATS_JSON_MID "{}"
#define STATS_JSON_TOTAL                            \
	"], \"total\": {\"tx\": %lu, \"rx\": %lu, " \
	"\"kni_tx\": %lu, \"kni_rx\": %lu, "        \
	"\"drop\": %lu, \"kni_drop\": %lu, "        \
	"\"acl_drop\": %lu, \"rate_drop\": %lu}}\n"

#define STATS_CSV_PRE ""
#define STATS_CSV_LCORE "%lu,%u,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu\n"
#define STATS_CSV_MID ""
#define STATS_CSV_TOTAL ""

#define STATS_HUM_PRE "Lcore statistics ===================================="
#define STATS_HUM_LCORE                    \
	"\nTime %lu: lcore %u portid %lu " \
	"---------------"                  \
	"\nLoop iteration: %lu"            \
	"\nPackets sent: %lu"              \
	"\nPackets received: %lu"          \
	"\nPackets kni sent: %lu"          \
	"\nPackets kni received: %lu"      \
	"\nPackets dropped: %lu"           \
	"\nPackets kni dropped: %lu"       \
	"\nPackets acl dropped: %lu"       \
	"\nPackets ratel dropped: %lu"
#define STATS_HUM_MID ""
#define STATS_HUM_TOTAL                                          \
	"\nAggregate statistics ===============================" \
	"\nTotal packets sent: %lu"                              \
	"\nTotal packets received: %lu"                          \
	"\nTotal packets kni sent: %lu"                          \
	"\nTotal packets kni received: %lu"                      \
	"\nTotal packets dropped: %lu"                           \
	"\nTotal packets kni dropped: %lu"                       \
	"\nTotal packets acl dropped: %lu"                       \
	"\nTotal packets ratel dropped: %lu"                     \
	"\n====================================================\n"

static void
print_ethaddr(struct cmdline* cl,
	      const char* name,
	      const struct ether_addr* eth_addr)
{
	char buf[ETHER_ADDR_FMT_SIZE];
	ether_format_addr(buf, ETHER_ADDR_FMT_SIZE, eth_addr);
	cmdline_printf(cl, "%s%s\n", name, buf);
}

// TODO check that port_id is valid

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-nonliteral"

void
pktj_stats_display(struct cmdline* cl, int option, int delay)
{
	uint64_t total_packets_dropped, total_packets_tx, total_packets_rx;
	uint64_t total_packets_kni_tx, total_packets_kni_rx,
	    total_packets_kni_dropped;
	uint64_t total_packets_ratel_dropped, total_packets_acl_dropped;
	unsigned lcoreid;
	time_t _time;
	const char *fmt_pre, *fmt_lcore, *fmt_mid, *fmt_total;

	total_packets_dropped = 0;
	total_packets_tx = 0;
	total_packets_rx = 0;
	total_packets_kni_tx = 0;
	total_packets_kni_rx = 0;
	total_packets_kni_dropped = 0;
	total_packets_acl_dropped = 0;
	total_packets_ratel_dropped = 0;

	if (option == CMD_STATS_JSON) {  // json
		fmt_pre = STATS_JSON_PRE;
		fmt_lcore = STATS_JSON_LCORE;
		fmt_mid = STATS_JSON_MID;
		fmt_total = STATS_JSON_TOTAL;
	} else if (option == CMD_STATS_CSV) {  // csv
		fmt_pre = STATS_CSV_PRE;
		fmt_lcore = STATS_CSV_LCORE;
		fmt_mid = STATS_CSV_MID;
		fmt_total = STATS_CSV_TOTAL;
	} else {
		fmt_pre = STATS_HUM_PRE;
		fmt_lcore = STATS_HUM_LCORE;
		fmt_mid = STATS_HUM_MID;
		fmt_total = STATS_HUM_TOTAL;
	}

	_time = time(NULL);

	for (lcoreid = 0; lcoreid < CMDLINE_MAX_CLIENTS; lcoreid++) {
		if (cmdline_clients[RTE_PER_LCORE(g_socket_id)][lcoreid].cl ==
		    cl) {
			cmdline_clients[RTE_PER_LCORE(g_socket_id)][lcoreid]
			    .csv_delay = delay;
			cmdline_clients[RTE_PER_LCORE(g_socket_id)][lcoreid]
			    .delay_timer = _time;
			break;
		}
	}

	cmdline_printf(cl, "%s", fmt_pre);

	for (lcoreid = 0; lcoreid < RTE_MAX_LCORE; lcoreid++) {
		if (!rte_lcore_is_enabled(lcoreid))
			continue;

		cmdline_printf(
		    cl, fmt_lcore, _time, lcoreid, stats[lcoreid].port_id,
		    stats[lcoreid].nb_iteration_looped, stats[lcoreid].nb_tx,
		    stats[lcoreid].nb_rx, stats[lcoreid].nb_kni_tx,
		    stats[lcoreid].nb_kni_rx, stats[lcoreid].nb_dropped,
		    stats[lcoreid].nb_kni_dropped,
		    stats[lcoreid].nb_acl_dropped,
		    stats[lcoreid].nb_ratel_dropped);

		total_packets_dropped += stats[lcoreid].nb_dropped;
		total_packets_tx += stats[lcoreid].nb_tx;
		total_packets_rx += stats[lcoreid].nb_rx;
		total_packets_kni_tx += stats[lcoreid].nb_kni_tx;
		total_packets_kni_rx += stats[lcoreid].nb_kni_rx;
		total_packets_kni_dropped += stats[lcoreid].nb_kni_dropped;
		total_packets_acl_dropped += stats[lcoreid].nb_acl_dropped;
		total_packets_ratel_dropped += stats[lcoreid].nb_ratel_dropped;
	}

	// add a null object to end the array
	cmdline_printf(cl, "%s", fmt_mid);

	cmdline_printf(cl, fmt_total, total_packets_tx, total_packets_rx,
		       total_packets_kni_tx, total_packets_kni_rx,
		       total_packets_dropped, total_packets_kni_dropped,
		       total_packets_acl_dropped, total_packets_ratel_dropped);
}

#pragma GCC diagnostic pop

void
pktj_lpm_stats_display(struct cmdline* cl, int is_ipv4, int option)
{
	struct lpm_stats_t* stats;

	stats = is_ipv4 ? &lpm4_stats[RTE_PER_LCORE(g_socket_id)]
			: &lpm6_stats[RTE_PER_LCORE(g_socket_id)];

	if (option == CMD_LPM_STATS_JSON) {
		cmdline_printf(cl,
			       "{\"current\": %lu, \"add\": {\"success\": "
			       "%lu, \"failure\": %lu}, \"del\": "
			       "{\"success\": %lu, \"failure\": %lu}}\n",
			       (stats->nb_add_ok - stats->nb_del_ok),
			       stats->nb_add_ok, stats->nb_add_ko,
			       stats->nb_del_ok, stats->nb_del_ko);
	} else {
		cmdline_printf(
		    cl,
		    "\nLPM statistics ====================================="
		    "\nCurrent routes: %lu"
		    "\nTotal routes added successfully: %lu"
		    "\nTotal route add failures: %lu"
		    "\nTotal routes deleted successfully: %lu"
		    "\nTotal route delete failures: %lu",
		    (stats->nb_add_ok - stats->nb_del_ok), stats->nb_add_ok,
		    stats->nb_add_ko, stats->nb_del_ok, stats->nb_del_ko);
		cmdline_printf(
		    cl,
		    "\n====================================================\n");
	}
}

void
port_infos_display(struct cmdline* cl, portid_t port_id)
{
	struct ether_addr mac_addr;
	struct rte_eth_link link;
	int vlan_offload;
	static const char* info_border = "=====================";

	rte_eth_link_get_nowait(port_id, &link);
	cmdline_printf(cl, "\n%s Infos for port %-2d %s\n", info_border,
		       port_id, info_border);
	rte_eth_macaddr_get(port_id, &mac_addr);
	print_ethaddr(cl, "MAC address: ", &mac_addr);

	cmdline_printf(cl, "\nLink status: %s\n",
		       (link.link_status) ? ("up") : ("down"));
	cmdline_printf(cl, "Link speed: %u Mbps\n", (unsigned)link.link_speed);
	cmdline_printf(cl, "Link duplex: %s\n",
		       (link.link_duplex == ETH_LINK_FULL_DUPLEX)
			   ? ("full-duplex")
			   : ("half-duplex"));
	cmdline_printf(
	    cl, "Promiscuous mode: %s\n",
	    rte_eth_promiscuous_get(port_id) ? "enabled" : "disabled");
	cmdline_printf(
	    cl, "Allmulticast mode: %s\n",
	    rte_eth_allmulticast_get(port_id) ? "enabled" : "disabled");

	vlan_offload = rte_eth_dev_get_vlan_offload(port_id);
	if (vlan_offload >= 0) {
		cmdline_printf(cl, "VLAN offload: \n");
		if (vlan_offload & ETH_VLAN_STRIP_OFFLOAD)
			cmdline_printf(cl, "  strip on \n");
		else
			cmdline_printf(cl, "  strip off \n");

		if (vlan_offload & ETH_VLAN_FILTER_OFFLOAD)
			cmdline_printf(cl, "  filter on \n");
		else
			cmdline_printf(cl, "  filter off \n");

		if (vlan_offload & ETH_VLAN_EXTEND_OFFLOAD)
			cmdline_printf(cl, "  qinq(extend) on \n");
		else
			cmdline_printf(cl, "  qinq(extend) off \n");
	}
}

void
nic_stats_display(struct cmdline* cl, portid_t port_id, int option)
{
	struct rte_eth_stats stats;
	uint8_t i;

	static const char* nic_stats_border = "=======================";

	rte_eth_stats_get(port_id, &stats);

	if (option) {
		cmdline_printf(cl,
			       "{\"portid\": %d, "
			       "\"rx\": {\"packets\": %" PRIu64
			       ", \"errors\": %" PRIu64 ", \"bytes\": %" PRIu64
			       ", "
			       ", \"nombuf\": %" PRIu64
			       ", "
			       "\"tx\": {\"packets\": %" PRIu64
			       ", \"errors\": %" PRIu64 ", \"bytes\": %" PRIu64
			       ", ",
			       port_id, stats.ipackets, stats.ierrors,
			       stats.ibytes, stats.rx_nombuf, stats.opackets,
			       stats.oerrors, stats.obytes);

		cmdline_printf(cl, "\"queues\": [");

		for (i = 0; i < RTE_ETHDEV_QUEUE_STAT_CNTRS; i++) {
			cmdline_printf(cl,
				       "{\"queueid\": %d, "
				       "\"rx\": {\"packets\": %" PRIu64
				       ", \"errors\": %" PRIu64
				       ", \"bytes\": %" PRIu64
				       "}, "
				       "\"tx\": {\"packets\": %" PRIu64
				       ", \"bytes\": %" PRIu64 "}}, ",
				       i, stats.q_ipackets[i],
				       stats.q_errors[i], stats.q_ibytes[i],
				       stats.q_opackets[i], stats.q_obytes[i]);
		}

		// add a null object to end the array
		cmdline_printf(cl, "{}");

		cmdline_printf(cl, "]}\n");

	} else {
		cmdline_printf(cl, "\n  %s NIC statistics for port %-2d %s\n",
			       nic_stats_border, port_id, nic_stats_border);

		cmdline_printf(cl, "  RX-packets:              %10" PRIu64
				   "    RX-errors: %10" PRIu64
				   "    RX-bytes: %10" PRIu64 "\n",
			       stats.ipackets, stats.ierrors, stats.ibytes);
		cmdline_printf(cl, "  RX-nombuf:               %10" PRIu64 "\n",
			       stats.rx_nombuf);
		cmdline_printf(cl, "  TX-packets:              %10" PRIu64
				   "    TX-errors: %10" PRIu64
				   "    TX-bytes: %10" PRIu64 "\n",
			       stats.opackets, stats.oerrors, stats.obytes);

		cmdline_printf(cl, "\n");
		for (i = 0; i < RTE_ETHDEV_QUEUE_STAT_CNTRS; i++) {
			cmdline_printf(cl,
				       "  Stats reg %2d RX-packets: %10" PRIu64
				       "    RX-errors: %10" PRIu64
				       "    RX-bytes: %10" PRIu64 "\n",
				       i, stats.q_ipackets[i],
				       stats.q_errors[i], stats.q_ibytes[i]);
		}
		cmdline_printf(cl, "\n");
		for (i = 0; i < RTE_ETHDEV_QUEUE_STAT_CNTRS; i++) {
			cmdline_printf(
			    cl,
			    "  Stats reg %2d TX-packets: %10" PRIu64
			    "                             TX-bytes: %10" PRIu64
			    "\n",
			    i, stats.q_opackets[i], stats.q_obytes[i]);
		}

		cmdline_printf(cl, "  %s=======================%s\n",
			       nic_stats_border, nic_stats_border);
	}
}

void
nic_stats_clear(struct cmdline* cl, portid_t port_id)
{
	rte_eth_stats_reset(port_id);
	cmdline_printf(cl, "\n  NIC statistics for port %d cleared\n", port_id);
}

void
nic_xstats_display(struct cmdline* cl, portid_t port_id, int option)
{
	struct rte_eth_xstats* xstats;
	int len, ret, i;

	len = rte_eth_xstats_get(port_id, NULL, 0);
	if (len < 0) {
		cmdline_printf(cl, "Cannot get xstats count\n");
		return;
	}
	xstats = malloc(sizeof(xstats[0]) * len);
	if (xstats == NULL) {
		cmdline_printf(cl, "Cannot allocate memory for xstats\n");
		return;
	}
	ret = rte_eth_xstats_get(port_id, xstats, len);
	if (ret < 0 || ret > len) {
		cmdline_printf(cl, "Cannot get xstats\n");
		free(xstats);
		return;
	}

	if (option) {
		cmdline_printf(cl, "{\"portid\": %d, ", port_id);

		for (i = 0; i < len; i++)
			cmdline_printf(cl, "%s\"%s\": %" PRIu64,
				       (i != 0) ? ", " : "", xstats[i].name,
				       xstats[i].value);

		cmdline_printf(cl, "}\n");

	} else {
		cmdline_printf(cl,
			       "===== NIC extended statistics for port %-2d\n",
			       port_id);

		for (i = 0; i < len; i++)
			cmdline_printf(cl, "%s: %" PRIu64 "\n", xstats[i].name,
				       xstats[i].value);
	}

	free(xstats);
}

void
nic_xstats_clear(struct cmdline* cl, portid_t port_id)
{
	rte_eth_xstats_reset(port_id);
	cmdline_printf(cl, "\n  NIC extra statistics for port %d cleared\n",
		       port_id);
}

void
port_rss_hash_conf_show(struct cmdline* cl, portid_t port_id, int show_rss_key)
{
	struct rss_type_info {
		char str[32];
		uint64_t rss_type;
	};
	static const struct rss_type_info rss_type_table[] = {
	    {"ipv4", ETH_RSS_IPV4},
	    {"ipv4-frag", ETH_RSS_FRAG_IPV4},
	    {"ipv4-tcp", ETH_RSS_NONFRAG_IPV4_TCP},
	    {"ipv4-udp", ETH_RSS_NONFRAG_IPV4_UDP},
	    {"ipv4-sctp", ETH_RSS_NONFRAG_IPV4_SCTP},
	    {"ipv4-other", ETH_RSS_NONFRAG_IPV4_OTHER},
	    {"ipv6", ETH_RSS_IPV6},
	    {"ipv6-frag", ETH_RSS_FRAG_IPV6},
	    {"ipv6-tcp", ETH_RSS_NONFRAG_IPV6_TCP},
	    {"ipv6-udp", ETH_RSS_NONFRAG_IPV6_UDP},
	    {"ipv6-sctp", ETH_RSS_NONFRAG_IPV6_SCTP},
	    {"ipv6-other", ETH_RSS_NONFRAG_IPV6_OTHER},
	    {"l2-payload", ETH_RSS_L2_PAYLOAD},
	    {"ipv6-ex", ETH_RSS_IPV6_EX},
	    {"ipv6-tcp-ex", ETH_RSS_IPV6_TCP_EX},
	    {"ipv6-udp-ex", ETH_RSS_IPV6_UDP_EX},
	};

	struct rte_eth_rss_conf rss_conf;
	uint8_t rss_key[10 * 8];
	uint64_t rss_hf;
	uint8_t i;
	int diag;

	/* Get RSS hash key if asked to display it */
	rss_conf.rss_key = (show_rss_key) ? rss_key : NULL;
	diag = rte_eth_dev_rss_hash_conf_get(port_id, &rss_conf);
	if (diag != 0) {
		switch (diag) {
		case -ENODEV:
			cmdline_printf(cl, "port index %d invalid\n", port_id);
			break;
		case -ENOTSUP:
			cmdline_printf(cl,
				       "operation not supported by device\n");
			break;
		default:
			cmdline_printf(cl, "operation failed - diag=%d\n",
				       diag);
			break;
		}
		return;
	}
	rss_hf = rss_conf.rss_hf;
	if (rss_hf == 0) {
		cmdline_printf(cl, "RSS disabled\n");
		return;
	}
	cmdline_printf(cl, "RSS functions:\n ");
	for (i = 0; i < RTE_DIM(rss_type_table); i++) {
		if (rss_hf & rss_type_table[i].rss_type)
			cmdline_printf(cl, "%s ", rss_type_table[i].str);
	}
	cmdline_printf(cl, "\n");
	if (!show_rss_key)
		return;
	cmdline_printf(cl, "RSS key:\n");
	for (i = 0; i < rss_conf.rss_key_len; i++)
		cmdline_printf(cl, "%02X", rss_key[i]);
	cmdline_printf(cl, "\n");
}

void
port_rss_hash_key_update(struct cmdline* cl,
			 portid_t port_id,
			 uint8_t* hash_key)
{
	struct rte_eth_rss_conf rss_conf;
	int diag;

	rss_conf.rss_key = NULL;
	diag = rte_eth_dev_rss_hash_conf_get(port_id, &rss_conf);
	if (diag == 0) {
		rss_conf.rss_key = hash_key;
		rss_conf.rss_key_len = RSS_HASH_KEY_LENGTH;
		diag = rte_eth_dev_rss_hash_update(port_id, &rss_conf);
	}
	if (diag == 0)
		return;

	switch (diag) {
	case -ENODEV:
		cmdline_printf(cl, "port index %d invalid\n", port_id);
		break;
	case -ENOTSUP:
		cmdline_printf(cl, "operation not supported by device\n");
		break;
	default:
		cmdline_printf(cl, "operation failed - diag=%d\n", diag);
		break;
	}
}
