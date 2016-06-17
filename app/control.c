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
#include <unistd.h>
#include <assert.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <spawn.h>

#include <rte_common.h>
#include <rte_malloc.h>
#include <rte_log.h>
#include <rte_ip.h>
#include <rte_lpm.h>
#include <rte_lpm6.h>
#include <rte_ethdev.h>
#include <cmdline_parse.h>
#include <cmdline_parse_ipaddr.h>

#include <libnetlink.h>
#include <libneighbour.h>

#include "common.h"
#include "control.h"
#include "routing.h"
#include "config.h"

#define CTRL_CBK_MAX_SIZE 256
#ifndef __DECONST
#define __DECONST(type, var) ((type)(uintptr_t)(const void*)(var))
#endif

extern char** environ;

struct control_handle {
	int32_t socket_id;
};

struct handle_res {
	struct netl_handle* netl_h;
	int32_t socket_id;
};

struct lpm_stats_t lpm4_stats[NB_SOCKETS];
struct lpm_stats_t lpm6_stats[NB_SOCKETS];

static const char* oper_states[] = {
    "UNKNOWN", "NOTPRESENT", "DOWN", "LOWERLAYERDOWN",
    "TESTING", "DORMANT",    "UP"};

static void
print_operstate(FILE* f, __u8 state)
{
	if (state >= sizeof(oper_states) / sizeof(oper_states[0]))
		fprintf(f, "state %#x ", state);
	else
		fprintf(f, "state %s ", oper_states[state]);
}

static void
apply_rate_limit_ipv6(struct in6_addr* nexthop,
		      uint8_t nexthop_id,
		      int socket_id)
{
	uint32_t i;

	// apply rate limit rule if next hop neighbor is in the table
	for (i = 0; i < NEI_NUM_ENTRIES; i++) {
		// if addresses match
		if (!memcmp(&rlimit6_lookup_table[socket_id][i].addr, nexthop,
			    sizeof(struct in6_addr))) {
			rlimit6_max[socket_id][nexthop_id] =
			    rlimit6_lookup_table[socket_id][i].num;
			break;
		}
	}
}

int control_add_ipv4_local_entry(struct in_addr* nexthop,
				 struct in_addr* saddr,
				 uint8_t depth,
				 uint32_t port_id,
				 int32_t socket_id);

int control_add_ipv6_local_entry(struct in6_addr* nexthop,
				 struct in6_addr* saddr,
				 uint8_t depth,
				 uint32_t port_id,
				 int32_t socket_id);
static int
route4(__rte_unused struct rtmsg* route,
       route_action_t action,
       struct in_addr* addr,
       uint8_t depth,
       struct in_addr* nexthop,
       uint8_t type,
       void* args)
{
	// If route add
	//   lookup next hop in neighbor table ipv4
	//   if not lookup
	//     create next hop, with flag invalid and addr = nexthop
	//   nexthopid = last id
	//
	//   register new route in lpm, with nexthop id
	//   increment refcount in neighbor
	// If route delete
	//   lookup next hop in neighbor table ipv4
	//   if not lookup
	//     then WTF TABLE CORRUPTED
	//   remove route from lpm
	//   decrement refcount in neighbor
	//   if refcount reached 0
	//     then flag entry empty

	struct control_handle* handle = args;
	assert(handle != NULL);
	uint16_t nexthop_id;
	int s;
	int32_t socket_id = handle->socket_id;
	struct in_addr blackhole_addr4 = {rte_be_to_cpu_32(INADDR_ANY)};

	if (type == RTN_BLACKHOLE) {
		nexthop = &blackhole_addr4;
	}

	if (action == ROUTE_ADD) {
		RTE_LOG(DEBUG, PKTJ_CTRL1, "adding an ipv4 route...\n");
		// lookup nexthop
		s = neighbor4_lookup_nexthop(neighbor4_struct[socket_id],
					     nexthop, &nexthop_id);
		if (s < 0) {
			s = neighbor4_add_nexthop(neighbor4_struct[socket_id],
						  nexthop, &nexthop_id,
						  NEI_ACTION_FWD);
			if (s < 0) {
				RTE_LOG(ERR, PKTJ_CTRL1,
					"failed to add a "
					"nexthop during "
					"route adding...\n");
				return -1;
			}
		}
		s = rte_lpm_add(ipv4_pktj_lookup_struct[socket_id],
				rte_be_to_cpu_32(addr->s_addr), depth,
				nexthop_id);
		if (s < 0) {
			lpm4_stats[socket_id].nb_add_ko++;
			RTE_LOG(ERR, PKTJ_CTRL1,
				"failed to add a route in "
				"lpm during route "
				"adding...\n");
			return -1;
		}
		neighbor4_refcount_incr(neighbor4_struct[socket_id],
					nexthop_id);
		lpm4_stats[socket_id].nb_add_ok++;
	}

	if (action == ROUTE_DELETE) {
		RTE_LOG(DEBUG, PKTJ_CTRL1, "deleting an ipv4 route...\n");
		// lookup nexthop
		s = neighbor4_lookup_nexthop(neighbor4_struct[socket_id],
					     nexthop, &nexthop_id);
		if (s < 0) {
			RTE_LOG(INFO, PKTJ_CTRL1,
				"failed to find nexthop "
				"during route deletion...\n");
			return -1;
		}

		s = rte_lpm_delete(ipv4_pktj_lookup_struct[socket_id],
				   rte_be_to_cpu_32(addr->s_addr), depth);
		if (s < 0) {
			lpm4_stats[socket_id].nb_del_ko++;
			RTE_LOG(INFO, PKTJ_CTRL1, "failed to delete route...\n");
			return -1;
		}
		neighbor4_refcount_decr(neighbor4_struct[socket_id],
					nexthop_id);
		lpm4_stats[socket_id].nb_del_ok++;
	}
	RTE_LOG(DEBUG, PKTJ_CTRL1, "route ope success\n");
	return 0;
}

static int
route6(__rte_unused struct rtmsg* route,
       route_action_t action,
       struct in6_addr* addr,
       uint8_t depth,
       struct in6_addr* nexthop,
       uint8_t type,
       void* args)
{
	// If route add
	//   lookup next hop in neighbor table ipv4
	//   if not lookup
	//     create next hop, with flag invalid and addr = nexthop
	//   nexthopid = last id
	//
	//   register new route in lpm, with nexthop id
	//   increment refcount in neighbor
	// If route delete
	//   lookup next hop in neighbor table ipv4
	//   if not lookup
	//     then WTF TABLE CORRUPTED
	//   remove route from lpm
	//   decrement refcount in neighbor
	//   if refcount reached 0
	//     then flag entry empty

	struct control_handle* handle = args;
	assert(handle != NULL);
	uint16_t nexthop_id;
	int s;
	int32_t socket_id = handle->socket_id;
	static struct in6_addr blackhole_addr6 = IN6ADDR_ANY_INIT;

	if (type == RTN_BLACKHOLE) {
		nexthop = &blackhole_addr6;
	}

	if (action == ROUTE_ADD) {
		RTE_LOG(DEBUG, PKTJ_CTRL1, "adding an ipv6 route...\n");
		// lookup nexthop
		s = neighbor6_lookup_nexthop(neighbor6_struct[socket_id],
					     nexthop, &nexthop_id);
		if (s < 0) {
			s = neighbor6_add_nexthop(neighbor6_struct[socket_id],
						  nexthop, &nexthop_id,
						  NEI_ACTION_FWD);
			if (s < 0) {
				RTE_LOG(ERR, PKTJ_CTRL1,
					"failed to add a "
					"nexthop during "
					"route adding...\n");
				return -1;
			}

			// apply rate limit rule if next hop neighbor is in the
			// table
			apply_rate_limit_ipv6(nexthop, nexthop_id, socket_id);
		}
		s = rte_lpm6_add(ipv6_pktj_lookup_struct[socket_id],
				 addr->s6_addr, depth, nexthop_id);
		if (s < 0) {
			lpm6_stats[socket_id].nb_add_ko++;
			RTE_LOG(ERR, PKTJ_CTRL1,
				"failed to add a route in "
				"lpm during route "
				"adding...\n");
			return -1;
		}
		neighbor6_refcount_incr(neighbor6_struct[socket_id],
					nexthop_id);
		lpm6_stats[socket_id].nb_add_ok++;
	}

	if (action == ROUTE_DELETE) {
		RTE_LOG(DEBUG, PKTJ_CTRL1, "deleting an ipv6 route...\n");
		// lookup nexthop
		s = neighbor6_lookup_nexthop(neighbor6_struct[socket_id],
					     nexthop, &nexthop_id);
		if (s < 0) {
			RTE_LOG(INFO, PKTJ_CTRL1,
				"failed to find nexthop "
				"during route deletion...\n");
			return -1;
		}

		s = rte_lpm6_delete(ipv6_pktj_lookup_struct[socket_id],
				    addr->s6_addr, depth);
		if (s < 0) {
			lpm6_stats[socket_id].nb_del_ko++;
			RTE_LOG(INFO, PKTJ_CTRL1, "failed to delete route...\n");
			return -1;
		}
		neighbor6_refcount_decr(neighbor6_struct[socket_id],
					nexthop_id);
		lpm6_stats[socket_id].nb_del_ok++;
	}
	RTE_LOG(DEBUG, PKTJ_CTRL1, "route ope success\n");
	return 0;
}

static int
neighbor4(neighbor_action_t action,
	  __s32 port_id,
	  struct in_addr* addr,
	  struct ether_addr* lladdr,
	  __u8 flags,
	  __rte_unused __u16 vlan_id,
	  void* args)
{
	// if port_id is not handled
	//   ignore, return immediatly
	// if neighbor add
	//   lookup neighbor
	//   if exists
	//     update lladdr, set flag as REACHABLE/STALE/DELAY
	//   else
	//     // This should not happen
	//     insert new nexthop
	//     set insert date=now, refcount = 0, flag=REACHABLE/STALE/DELAY
	// if neighbor delete
	//   lookup neighbor
	//   if exists
	//     if refcount != 0
	//       set nexthop as invalid
	//     else
	//       set flag empty
	//   else
	//     do nothing
	//     // this should not happen

	struct control_handle* handle = args;
	assert(handle != NULL);
	int s;
	uint16_t nexthop_id;
    uint32_t find_id;
	int32_t socket_id = handle->socket_id;
	char ipbuf[INET_ADDRSTRLEN];

	assert(neighbor4_struct != NULL);

	if (addr == NULL)
		return -1;
	inet_ntop(AF_INET, addr, ipbuf, INET_ADDRSTRLEN);

	if (action == NEIGHBOR_ADD) {
		if (lladdr == NULL)
			return -1;
		char ibuf[IFNAMSIZ];
		unsigned kni_vlan;

		if_indextoname(port_id, ibuf);
		s = sscanf(ibuf, "dpdk%10u.%10u", &port_id, &kni_vlan);
		if (s <= 0) {
			RTE_LOG(ERR, PKTJ_CTRL1,
				"received a neighbor "
				"announce for an unmanaged "
				"iface %s\n",
				ibuf);
			return -1;
		}

		s = neighbor4_lookup_nexthop(neighbor4_struct[socket_id], addr,
					     &nexthop_id);
		if (s < 0) {
			if (flags != NUD_NONE && flags != NUD_NOARP &&
			    flags != NUD_STALE) {
				RTE_LOG(ERR, PKTJ_CTRL1,
					"failed to change state in neighbor4 "
					"table (state %d, %s)...\n",
					flags, ipbuf);
				return -1;
			}

			{
				RTE_LOG(DEBUG, PKTJ_CTRL1,
					"adding ipv4 neighbor %s with port %s "
					"vlan_id %d...\n",
					ipbuf, ibuf, kni_vlan);
			}

			s = neighbor4_add_nexthop(neighbor4_struct[socket_id],
						  addr, &nexthop_id,
						  NEI_ACTION_FWD);
			if (s < 0) {
				RTE_LOG(ERR, PKTJ_CTRL1,
					"failed to add a "
					"nexthop in neighbor "
					"table...\n");
				return -1;
			}

			if (rte_lpm_lookup(ipv4_pktj_lookup_struct[socket_id],
					   rte_be_to_cpu_32(addr->s_addr),
					   &find_id) == 0) {
				s = rte_lpm_add(
				    ipv4_pktj_lookup_struct[socket_id],
				    rte_be_to_cpu_32(addr->s_addr), 32,
				    nexthop_id);
				if (s < 0) {
					lpm4_stats[socket_id].nb_add_ko++;
					RTE_LOG(ERR, PKTJ_CTRL1,
						"failed to add a route in "
						"lpm during neighbor "
						"adding...\n");
					return -1;
				}
				lpm4_stats[socket_id].nb_add_ok++;
			}
		}

		if (flags == NUD_FAILED) {
			neighbor4_set_action(neighbor4_struct[socket_id],
					     nexthop_id, NEI_ACTION_KNI);
		} else {
			neighbor4_set_action(neighbor4_struct[socket_id],
					     nexthop_id, NEI_ACTION_FWD);
		}
		RTE_LOG(DEBUG, PKTJ_CTRL1,
			"set neighbor4 with port_id %d state %d\n", port_id,
			flags);
		neighbor4_set_lladdr_port(neighbor4_struct[socket_id],
					  nexthop_id, &ports_eth_addr[port_id],
					  lladdr, port_id, kni_vlan);
		neighbor4_set_state(neighbor4_struct[socket_id], nexthop_id,
				    flags);
	}
	if (action == NEIGHBOR_DELETE) {
		if (flags != NUD_FAILED && flags != NUD_STALE) {
			RTE_LOG(
			    DEBUG, PKTJ_CTRL1,
			    "neighbor4 delete ope failed, bad NUD state: %d \n",
			    flags);
			return -1;
		}

		RTE_LOG(DEBUG, PKTJ_CTRL1, "deleting ipv4 neighbor...\n");
		s = neighbor4_lookup_nexthop(neighbor4_struct[socket_id], addr,
					     &nexthop_id);
		if (s < 0) {
			RTE_LOG(INFO, PKTJ_CTRL1,
				"failed to find a nexthop to "
				"delete in neighbor "
				"table...\n");
			return 0;
		}
		neighbor4_delete(neighbor4_struct[socket_id], nexthop_id);
		// FIXME not thread safe
		if (neighbor4_struct[socket_id]
			->entries.t4[nexthop_id]
			.neighbor.refcnt == 0) {
			s = rte_lpm_delete(ipv4_pktj_lookup_struct[socket_id],
					   rte_be_to_cpu_32(addr->s_addr), 32);
			if (s < 0) {
				lpm4_stats[socket_id].nb_del_ko++;
				RTE_LOG(ERR, PKTJ_CTRL1,
					"failed to delete route...\n");
				return -1;
			}
			lpm4_stats[socket_id].nb_del_ok++;
		}
	}
	RTE_LOG(DEBUG, PKTJ_CTRL1, "neigh %s ope success\n", ipbuf);
	return 0;
}

static int
neighbor6(neighbor_action_t action,
	  int32_t port_id,
	  struct in6_addr* addr,
	  struct ether_addr* lladdr,
	  uint8_t flags,
	  __rte_unused uint16_t vlan_id,
	  void* args)
{
	// if port_id is not handled
	//   ignore, return immediatly
	// if neighbor add
	//   lookup neighbor
	//   if exists
	//     update lladdr, set flag as REACHABLE/STALE/DELAY
	//   else
	//     // This should not happen
	//     insert new nexthop
	//     set insert date=now, refcount = 0, flag=REACHABLE/STALE/DELAY
	// if neighbor delete
	//   lookup neighbor
	//   if exists
	//     if refcount != 0
	//       set nexthop as invalid
	//     else
	//       set flag empty
	//   else
	//     do nothing
	//     // this should not happen

	struct control_handle* handle = args;
	assert(handle != NULL);
	int s;
	uint16_t nexthop_id, find_id;
	int32_t socket_id = handle->socket_id;
	char ipbuf[INET6_ADDRSTRLEN];

	assert(neighbor6_struct != NULL);

	if (addr == NULL)
		return -1;
	inet_ntop(AF_INET6, addr, ipbuf, INET6_ADDRSTRLEN);

	if (action == NEIGHBOR_ADD) {
		if (lladdr == NULL)
			return -1;
		char ibuf[IFNAMSIZ];
		unsigned kni_vlan;

		if_indextoname(port_id, ibuf);
		s = sscanf(ibuf, "dpdk%10u.%10u", &port_id, &kni_vlan);

		if (s <= 0) {
			RTE_LOG(ERR, PKTJ_CTRL1,
				"received a neighbor "
				"announce for an unmanaged "
				"iface %s\n",
				ibuf);
			return -1;
		}

		s = neighbor6_lookup_nexthop(neighbor6_struct[socket_id], addr,
					     &nexthop_id);
		if (s < 0) {
			if (flags != NUD_NONE && flags != NUD_NOARP &&
			    flags != NUD_STALE) {
				RTE_LOG(ERR, PKTJ_CTRL1,
					"failed to change state in neighbor6 "
					"table (state %d, %s)...\n",
					flags, ipbuf);
				return -1;
			}

			{
				RTE_LOG(
				    DEBUG, PKTJ_CTRL1,
				    "adding ipv6 neighbor %s with port_id %d "
				    "vlan_id %d...\n",
				    ipbuf, port_id, kni_vlan);
			}

			s = neighbor6_add_nexthop(neighbor6_struct[socket_id],
						  addr, &nexthop_id,
						  NEI_ACTION_FWD);
			if (s < 0) {
				RTE_LOG(ERR, PKTJ_CTRL1,
					"failed to add a "
					"nexthop in neighbor "
					"table...\n");
				return -1;
			}

			// apply rate limit rule if next hop neighbor is in the
			// table
			apply_rate_limit_ipv6(addr, nexthop_id, socket_id);

			if (rte_lpm6_lookup(ipv6_pktj_lookup_struct[socket_id],
					    addr->s6_addr, &find_id) == 0) {
				s = rte_lpm6_add(
				    ipv6_pktj_lookup_struct[socket_id],
				    addr->s6_addr, 128, nexthop_id);
				if (s < 0) {
					lpm6_stats[socket_id].nb_add_ko++;
					RTE_LOG(ERR, PKTJ_CTRL1,
						"failed to add a route in "
						"lpm during neighbor "
						"adding...\n");
					return -1;
				}
				lpm6_stats[socket_id].nb_add_ok++;
			}
		}

		if (flags == NUD_FAILED) {
			neighbor6_set_action(neighbor6_struct[socket_id],
					     nexthop_id, NEI_ACTION_KNI);
		} else {
			neighbor6_set_action(neighbor6_struct[socket_id],
					     nexthop_id, NEI_ACTION_FWD);
		}
		RTE_LOG(DEBUG, PKTJ_CTRL1,
			"set neighbor6 with port_id %d state %d \n", port_id,
			flags);
		neighbor6_set_lladdr_port(neighbor6_struct[socket_id],
					  nexthop_id, &ports_eth_addr[port_id],
					  lladdr, port_id, kni_vlan);
		neighbor6_set_state(neighbor6_struct[socket_id], nexthop_id,
				    flags);
	}
	if (action == NEIGHBOR_DELETE) {
		if (flags != NUD_FAILED && flags != NUD_STALE) {
			RTE_LOG(
			    DEBUG, PKTJ_CTRL1,
			    "neighbor6 delete ope failed, bad NUD state: %d \n",
			    flags);
			return -1;
		}

		RTE_LOG(DEBUG, PKTJ_CTRL1, "deleting ipv6 neighbor...\n");
		s = neighbor6_lookup_nexthop(neighbor6_struct[socket_id], addr,
					     &nexthop_id);
		if (s < 0) {
			RTE_LOG(INFO, PKTJ_CTRL1,
				"failed to find a nexthop to "
				"delete in neighbor "
				"table...\n");
			return 0;
		}
		neighbor6_delete(neighbor6_struct[socket_id], nexthop_id);
		// FIXME not thread safe
		if (neighbor6_struct[socket_id]
			->entries.t6[nexthop_id]
			.neighbor.refcnt == 0) {
			s = rte_lpm6_delete(ipv6_pktj_lookup_struct[socket_id],
					    addr->s6_addr, 128);
			if (s < 0) {
				lpm6_stats[socket_id].nb_del_ko++;
				RTE_LOG(ERR, PKTJ_CTRL1,
					"failed to delete route...\n");
				return -1;
			}

			// reset rate limit for this id
			rlimit6_max[socket_id][nexthop_id] = UINT32_MAX;

			lpm6_stats[socket_id].nb_del_ok++;
		}
	}
	RTE_LOG(DEBUG, PKTJ_CTRL1, "neigh %s ope success\n", ipbuf);
	return 0;
}

static int
addr4(__rte_unused addr_action_t action,
      int32_t port_id,
      struct in_addr* addr,
      uint8_t prefixlen,
      void* args)
{
	char buf[255];
	char ibuf[IFNAMSIZ];
	struct control_handle* handle = args;
	assert(handle != NULL);
	int32_t socket_id = handle->socket_id;

	if_indextoname(port_id, ibuf);
	sscanf(ibuf, "dpdk%10d", &port_id);
	RTE_LOG(DEBUG, PKTJ_CTRL1, "addr4 port=%s %s/%d with port_id %d\n",
		ibuf, inet_ntop(AF_INET, addr, buf, 255), prefixlen, port_id);

	control_add_ipv4_local_entry(addr, addr, prefixlen, port_id, socket_id);

	return 0;
}

static int
addr6(__rte_unused addr_action_t action,
      int32_t port_id,
      struct in6_addr* addr,
      uint8_t prefixlen,
      void* args)
{
	char buf[255];
	char ibuf[IFNAMSIZ];
	struct control_handle* handle = args;
	assert(handle != NULL);
	int32_t socket_id = handle->socket_id;

	if_indextoname(port_id, ibuf);
	sscanf(ibuf, "dpdk%10d", &port_id);
	RTE_LOG(DEBUG, PKTJ_CTRL1, "addr6 port=%s %s/%d with port_id %d\n",
		ibuf, inet_ntop(AF_INET6, addr, buf, 255), prefixlen, port_id);

	control_add_ipv6_local_entry(addr, addr, prefixlen, port_id, socket_id);

	// multicast ipv6
	struct in6_addr mc_linklocal = IN6ADDR_ANY_INIT;
	mc_linklocal.s6_addr[0] = 0xff;
	mc_linklocal.s6_addr[1] = 0x02;
	control_add_ipv6_local_entry(&mc_linklocal, &mc_linklocal, 16, port_id,
				     socket_id);

	return 0;
}

static int
eth_link(link_action_t action,
	 int ifid,
	 struct ether_addr* lladdr,
	 int mtu,
	 const char* name,
	 oper_state_t state,
	 uint16_t vlanid,
	 __rte_unused void* args)
{
	char action_buf[4];
	char ebuf[32];
	unsigned l, i;

	if (action == LINK_ADD) {
		memcpy(action_buf, "add", 4);

	} else {
		memcpy(action_buf, "del", 4);
	}

	l = 0;
	for (i = 0; i < sizeof(*lladdr); i++) {
		if (i == 0) {
			snprintf(ebuf + l, sizeof(ebuf) - l, "%02x",
				 lladdr->addr_bytes[i]);
			l += 2;
		} else {
			snprintf(ebuf + l, sizeof(ebuf) - l, ":%02x",
				 lladdr->addr_bytes[i]);
			l += 3;
		}
	}
	if (l >= 32)
		l = 31;
	ebuf[l] = '\0';

	fprintf(stdout, "%d: link %s %s mtu %d label %s vlan %d ", ifid,
		action_buf, ebuf, mtu, name, vlanid);
	print_operstate(stdout, state);
	fprintf(stdout, "\n");
	fflush(stdout);
	return 0;
}

static int
add_invalid_neighbor4(neighbor_struct_t* neighbor_struct,
		      struct in_addr* ip,
		      uint16_t dst_port)
{
	struct ether_addr invalid_mac = {{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}};
	uint16_t nexthop_id;

	if (neighbor4_add_nexthop(neighbor_struct, ip, &nexthop_id,
				  NEI_ACTION_DROP) < 0) {
		return -1;
	}
	neighbor4_refcount_incr(neighbor_struct, nexthop_id);
	neighbor4_set_lladdr_port(neighbor_struct, nexthop_id, &invalid_mac,
				  &invalid_mac, dst_port, -1);
	return 0;
}

static int
add_invalid_neighbor6(neighbor_struct_t* neighbor_struct,
		      struct in6_addr* ip,
		      uint16_t dst_port)
{
	struct ether_addr invalid_mac = {{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}};
	uint16_t nexthop_id;

	if (neighbor6_add_nexthop(neighbor_struct, ip, &nexthop_id,
				  NEI_ACTION_DROP) < 0) {
		return -1;
	}

	neighbor6_refcount_incr(neighbor_struct, nexthop_id);
	neighbor6_set_lladdr_port(neighbor_struct, nexthop_id, &invalid_mac,
				  &invalid_mac, dst_port, -1);
	return 0;
}

static void
netl_log(const char *msg, uint32_t lvl)
{
	rte_log(lvl, RTE_LOGTYPE_PKTJ_CTRL1, "PKTJ_CRTL1: %s\n", msg);
}

void *
control_init(int32_t socket_id, unsigned events)
{
	struct netl_handle* netl_h;
	struct handle_res* res;

	netl_h = netl_create(events);
	if (netl_h == NULL) {
		RTE_LOG(ERR, PKTJ_CTRL1, "Couldn't initialize netlink socket");
		goto err;
	}

	neighbor4_struct[socket_id] = nei_create(socket_id);
	if (neighbor4_struct[socket_id] == NULL) {
		RTE_LOG(ERR, PKTJ_CTRL1,
			"Couldn't initialize neighbor4 struct");
		goto err;
	}

	neighbor6_struct[socket_id] = nei_create(socket_id);
	if (neighbor6_struct[socket_id] == NULL) {
		RTE_LOG(ERR, PKTJ_CTRL1,
			"Couldn't initialize neighbor6 struct");
		goto err;
	}

	netl_h->cb.addr4 = addr4;
	netl_h->cb.addr6 = addr6;
	netl_h->cb.neighbor4 = neighbor4;
	netl_h->cb.neighbor6 = neighbor6;
	netl_h->cb.route4 = route4;
	netl_h->cb.route6 = route6;
	netl_h->cb.link = eth_link;
	netl_h->cb.log = netl_log;

	struct in_addr invalid_ip = {INADDR_ANY};
	struct in6_addr invalid_ip6 = IN6ADDR_ANY_INIT;

	if (add_invalid_neighbor4(neighbor4_struct[socket_id], &invalid_ip,
				  BAD_PORT) < 0) {
		RTE_LOG(ERR, PKTJ_CTRL1,
			"Couldn't add drop target in neighbor4 table");
		goto err;
	}

	if (add_invalid_neighbor6(neighbor6_struct[socket_id], &invalid_ip6,
				  BAD_PORT) < 0) {
		RTE_LOG(ERR, PKTJ_CTRL1,
			"Couldn't add drop target in neighbor6 table");
		goto err;
	}

	res = rte_malloc("handle-res", sizeof(*res), socket_id);
	res->socket_id = socket_id;
	res->netl_h = netl_h;
	return res;
err:
	rte_panic("failed to init control_main");
}

void
control_stop(void* data)
{
	struct handle_res* res;
	struct netl_handle* netl_h;

	res = data;
	netl_h = res->netl_h;
	netl_close(netl_h);
}

void
control_terminate(void* data)
{
	struct handle_res* res;

	res = data;
	netl_free(res->netl_h);
	rte_free(res);
}

int
control_main(void* data)
{
	struct handle_res* res;
	struct netl_handle* netl_h;
	struct control_handle handle;

	res = data;
	netl_h = res->netl_h;
	handle.socket_id = res->socket_id;

	RTE_LOG(INFO, PKTJ_CTRL1, "init ok\n");
	int res_listen = netl_listen(netl_h, &handle);
	RTE_LOG(ERR, PKTJ_CTRL1, "netl_listen returned %d\n", res_listen);
	return 0;
}

int
control_add_ipv4_local_entry(struct in_addr* nexthop,
			     struct in_addr* saddr,
			     uint8_t depth,
			     uint32_t port_id,
			     int32_t socket_id)
{
	int s;
	uint16_t nexthop_id;

	s = neighbor4_lookup_nexthop(neighbor4_struct[socket_id], nexthop,
				     &nexthop_id);
	if (s < 0) {
		s = neighbor4_add_nexthop(neighbor4_struct[socket_id], nexthop,
					  &nexthop_id, NEI_ACTION_KNI);
		if (s < 0) {
			RTE_LOG(
			    ERR, PKTJ_CTRL1,
			    "failed to add a nexthop during route adding...\n");
			return -1;
		}
	}
	neighbor4_set_port(neighbor4_struct[socket_id], nexthop_id, port_id);
	s = rte_lpm_add(ipv4_pktj_lookup_struct[socket_id],
			rte_be_to_cpu_32(saddr->s_addr), depth, nexthop_id);
	if (s < 0) {
		RTE_LOG(
		    ERR, PKTJ_CTRL1,
		    "failed to add a route in lpm during route adding...\n");
		return -1;
	}
	neighbor4_refcount_incr(neighbor4_struct[socket_id], nexthop_id);
	return nexthop_id;
}

int
control_add_ipv6_local_entry(struct in6_addr* nexthop,
			     struct in6_addr* saddr,
			     uint8_t depth,
			     uint32_t port_id,
			     int32_t socket_id)
{
	int s;
	uint16_t nexthop_id;

	s = neighbor6_lookup_nexthop(neighbor6_struct[socket_id], nexthop,
				     &nexthop_id);
	if (s < 0) {
		s = neighbor6_add_nexthop(neighbor6_struct[socket_id], nexthop,
					  &nexthop_id, NEI_ACTION_KNI);
		if (s < 0) {
			RTE_LOG(
			    ERR, PKTJ_CTRL1,
			    "failed to add a nexthop during route adding...\n");
			return -1;
		}

		// apply rate limit rule if next hop neighbor is in the table
		apply_rate_limit_ipv6(nexthop, nexthop_id, socket_id);
	}
	neighbor6_set_port(neighbor6_struct[socket_id], nexthop_id, port_id);
	s = rte_lpm6_add(ipv6_pktj_lookup_struct[socket_id], saddr->s6_addr,
			 depth, nexthop_id);
	if (s < 0) {
		RTE_LOG(
		    ERR, PKTJ_CTRL1,
		    "failed to add a route in lpm during route adding...\n");
		return -1;
	}
	neighbor6_refcount_incr(neighbor6_struct[socket_id], nexthop_id);
	return nexthop_id;
}

int
control_callback_setup(const char* cb, uint8_t nb_ports)
{
	char cmd[CTRL_CBK_MAX_SIZE];
	int len;
	char ether1[ETHER_ADDR_FMT_SIZE];
	uint8_t port;
	const char* argv[4];

	len = snprintf(cmd, CTRL_CBK_MAX_SIZE, "%s", cb);

	for (port = 0; port < nb_ports; port++) {
		ether_format_addr(ether1, ETHER_ADDR_FMT_SIZE,
				  &ports_eth_addr[port]);
		len += snprintf(&cmd[len], CTRL_CBK_MAX_SIZE - len,
				" dpdk%d %s", port, ether1);

		if (len >= CTRL_CBK_MAX_SIZE) {
			rte_panic("control callback too long");
		}
	}

	argv[0] = "/bin/sh";
	argv[1] = "-c";
	argv[2] = cmd;
	argv[3] = NULL;

	RTE_LOG(INFO, PKTJ_CTRL1, "executing command `%s`\n", cmd);
	return posix_spawn(NULL, "/bin/sh", NULL, NULL, __DECONST(char**, argv),
			   environ);
}
