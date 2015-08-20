#include <stdio.h>
#include <unistd.h>
#include <assert.h>
#include <net/if.h>

#include <rte_common.h>
#include <rte_malloc.h>
#include <rte_log.h>
#include <rte_ip.h>
#include <rte_lpm.h>
#include <rte_lpm6.h>
#include <rte_ethdev.h>

#include <libnetlink.h>
#include <libneighbour.h>

#include "common.h"
#include "control.h"
#include "routing.h"

#define CTRL_CBK_MAX_SIZE 256

struct control_handle {
	int32_t socket_id;
};

struct handle_res {
	struct netl_handle *netl_h;
	int32_t socket_id;
};

static const char *oper_states[] = {
	"UNKNOWN", "NOTPRESENT", "DOWN", "LOWERLAYERDOWN",
	"TESTING", "DORMANT", "UP"
};

static void print_operstate(FILE * f, __u8 state)
{
	if (state >= sizeof(oper_states) / sizeof(oper_states[0]))
		fprintf(f, "state %#x ", state);
	else
		fprintf(f, "state %s ", oper_states[state]);
}


int control_add_ipv4_local_entry(struct in_addr *nexthop,
								 struct in_addr *saddr, uint8_t depth,
								 uint32_t port_id, int32_t socket_id);

int control_add_ipv6_local_entry(struct in6_addr *nexthop,
								 struct in6_addr *saddr, uint8_t depth,
								 uint32_t port_id, int32_t socket_id);
static int
route4(__rte_unused struct rtmsg *route, route_action_t action,
	   struct in_addr *addr, uint8_t depth, struct in_addr *nexthop,
	   void *args)
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

	struct control_handle *handle = args;
	assert(handle != NULL);
	uint8_t nexthop_id;
	int s;
	int32_t socket_id = handle->socket_id;


	if (action == ROUTE_ADD) {
		RTE_LOG(DEBUG, L3FWD_CTRL, "adding an ipv4 route...\n");
		// lookup nexthop
		s = neighbor4_lookup_nexthop(neighbor4_struct[socket_id], nexthop,
									 &nexthop_id);
		if (s < 0) {
			s = neighbor4_add_nexthop(neighbor4_struct[socket_id], nexthop,
									  &nexthop_id, NEI_ACTION_FWD);
			if (s < 0) {
				RTE_LOG(ERR, L3FWD_CTRL,
						"failed to add a nexthop during route adding...\n");
				return -1;
			}
		}
		s = rte_lpm_add(ipv4_rdpdk_lookup_struct[socket_id],
						rte_be_to_cpu_32(addr->s_addr), depth, nexthop_id);
		if (s < 0) {
			RTE_LOG(ERR, L3FWD_CTRL,
					"failed to add a route in lpm during route adding...\n");
			return -1;
		}
		neighbor4_refcount_incr(neighbor4_struct[socket_id], nexthop_id);

	}

	if (action == ROUTE_DELETE) {
		RTE_LOG(DEBUG, L3FWD_CTRL, "deleting an ipv4 route...\n");
		// lookup nexthop
		s = neighbor4_lookup_nexthop(neighbor4_struct[socket_id], nexthop,
									 &nexthop_id);
		if (s < 0) {
			RTE_LOG(ERR, L3FWD_CTRL,
					"failed to find nexthop during route deletion...\n");
			return -1;
		}

		s = rte_lpm_delete(ipv4_rdpdk_lookup_struct[socket_id],
						   rte_be_to_cpu_32(addr->s_addr), depth);
		if (s < 0) {
			RTE_LOG(ERR, L3FWD_CTRL, "failed to deletie route...\n");
			return -1;
		}
		neighbor4_refcount_decr(neighbor4_struct[socket_id], nexthop_id);

	}
	RTE_LOG(DEBUG, L3FWD_CTRL, "route ope success\n");
	return 0;
}

static int
route6(__rte_unused struct rtmsg *route, route_action_t action,
	   struct in6_addr *addr, uint8_t depth, struct in6_addr *nexthop,
	   void *args)
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

	struct control_handle *handle = args;
	assert(handle != NULL);
	uint8_t nexthop_id;
	int s;
	int32_t socket_id = handle->socket_id;


	if (action == ROUTE_ADD) {
		RTE_LOG(DEBUG, L3FWD_CTRL, "adding an ipv6 route...\n");
		// lookup nexthop
		s = neighbor6_lookup_nexthop(neighbor6_struct[socket_id], nexthop,
									 &nexthop_id);
		if (s < 0) {
			s = neighbor6_add_nexthop(neighbor6_struct[socket_id], nexthop,
									  &nexthop_id, NEI_ACTION_FWD);
			if (s < 0) {
				RTE_LOG(ERR, L3FWD_CTRL,
						"failed to add a nexthop during route adding...\n");
				return -1;
			}
		}
		s = rte_lpm6_add(ipv6_rdpdk_lookup_struct[socket_id],
						 addr->s6_addr, depth, nexthop_id);
		if (s < 0) {
			RTE_LOG(ERR, L3FWD_CTRL,
					"failed to add a route in lpm during route adding...\n");
			return -1;
		}
		neighbor6_refcount_incr(neighbor6_struct[socket_id], nexthop_id);

	}

	if (action == ROUTE_DELETE) {
		RTE_LOG(DEBUG, L3FWD_CTRL, "deleting an ipv6 route...\n");
		// lookup nexthop
		s = neighbor6_lookup_nexthop(neighbor6_struct[socket_id], nexthop,
									 &nexthop_id);
		if (s < 0) {
			RTE_LOG(ERR, L3FWD_CTRL,
					"failed to find nexthop during route deletion...\n");
			return -1;
		}

		s = rte_lpm6_delete(ipv6_rdpdk_lookup_struct[socket_id],
							addr->s6_addr, depth);
		if (s < 0) {
			RTE_LOG(ERR, L3FWD_CTRL, "failed to deletie route...\n");
			return -1;
		}
		neighbor6_refcount_decr(neighbor6_struct[socket_id], nexthop_id);

	}
	RTE_LOG(DEBUG, L3FWD_CTRL, "route ope success\n");
	return 0;
}


static int
neighbor4(neighbor_action_t action,
		  __s32 port_id, struct in_addr *addr, struct ether_addr *lladdr,
		  __u8 flags, __rte_unused __u16 vlan_id, void *args)
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

	struct control_handle *handle = args;
	assert(handle != NULL);
	int s;
	uint8_t nexthop_id;
	int32_t socket_id = handle->socket_id;

	assert(neighbor4_struct != NULL);

	if (addr == NULL)
		return -1;

	//FIXME must check that state is not NUD_FAILED or NUD_INVALID
	if (action == NEIGHBOR_ADD) {
		if (lladdr == NULL)
			return -1;
		char ibuf[IFNAMSIZ];
		unsigned kni_vlan;

		if_indextoname(port_id, ibuf);
		s = sscanf(ibuf, "dpdk%10u.%10u", &port_id, &kni_vlan);
		if (s <= 0) {
			RTE_LOG(ERR, L3FWD_CTRL,
					"received a neighbor announce for an unmanaged iface %s\n",
					ibuf);
			return -1;
		}
		RTE_LOG(DEBUG, L3FWD_CTRL,
				"adding ipv4 neighbor with port %s vlan_id %d...\n", ibuf,
				kni_vlan);

		s = neighbor4_lookup_nexthop(neighbor4_struct[socket_id], addr,
									 &nexthop_id);
		if (s < 0) {
			s = neighbor4_add_nexthop(neighbor4_struct[socket_id], addr,
									  &nexthop_id, NEI_ACTION_FWD);
			if (s < 0) {
				RTE_LOG(ERR, L3FWD_CTRL,
						"failed to add a nexthop in neighbor table...\n");
				return -1;
			}
		}
		RTE_LOG(DEBUG, L3FWD_CTRL, "add neighbor4 with port_id %d\n",
				port_id);
		neighbor4_set_lladdr_port(neighbor4_struct[socket_id], nexthop_id,
								  &ports_eth_addr[port_id], lladdr,
								  port_id, kni_vlan);
		neighbor4_set_state(neighbor4_struct[socket_id], nexthop_id,
							flags);
	}
	if (action == NEIGHBOR_DELETE) {
		RTE_LOG(DEBUG, L3FWD_CTRL, "deleting ipv4 neighbor...\n");
		s = neighbor4_lookup_nexthop(neighbor4_struct[socket_id], addr,
									 &nexthop_id);
		if (s < 0) {
			RTE_LOG(ERR, L3FWD_CTRL,
					"failed to find a nexthop to delete in neighbor table...\n");
			return 0;
		}
		neighbor4_delete(neighbor4_struct[socket_id], nexthop_id);
	}
	RTE_LOG(DEBUG, L3FWD_CTRL, "neigh ope success\n");
	return 0;
}

static int
neighbor6(neighbor_action_t action,
		  int32_t port_id, struct in6_addr *addr,
		  struct ether_addr *lladdr, uint8_t flags,
		  __rte_unused uint16_t vlan_id, void *args)
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

	struct control_handle *handle = args;
	assert(handle != NULL);
	int s;
	uint8_t nexthop_id;
	int32_t socket_id = handle->socket_id;

	assert(neighbor6_struct != NULL);

	if (addr == NULL)
		return -1;

	//FIXME must check that state is not NUD_FAILED or NUD_INVALID
	if (action == NEIGHBOR_ADD) {
		if (lladdr == NULL)
			return -1;
		char ibuf[IFNAMSIZ];
		unsigned kni_vlan;

		if_indextoname(port_id, ibuf);
		s = sscanf(ibuf, "dpdk%10u.%10u", &port_id, &kni_vlan);

		if (s <= 0) {
			RTE_LOG(ERR, L3FWD_CTRL,
					"received a neighbor announce for an unmanaged iface %s\n",
					ibuf);
			return -1;
		}
		RTE_LOG(DEBUG, L3FWD_CTRL,
				"adding ipv6 neighbor with port_id %d vlan_id %d...\n",
				port_id, kni_vlan);

		s = neighbor6_lookup_nexthop(neighbor6_struct[socket_id], addr,
									 &nexthop_id);
		if (s < 0) {
			s = neighbor6_add_nexthop(neighbor6_struct[socket_id], addr,
									  &nexthop_id, NEI_ACTION_FWD);
			if (s < 0) {
				RTE_LOG(ERR, L3FWD_CTRL,
						"failed to add a nexthop in neighbor table...\n");
				return -1;
			}
		}
		RTE_LOG(DEBUG, L3FWD_CTRL, "add neighbor4 with port_id %d\n",
				port_id);
		neighbor6_set_lladdr_port(neighbor6_struct[socket_id], nexthop_id,
								  &ports_eth_addr[port_id], lladdr,
								  port_id, kni_vlan);
		neighbor6_set_state(neighbor6_struct[socket_id], nexthop_id,
							flags);
	}
	if (action == NEIGHBOR_DELETE) {
		RTE_LOG(DEBUG, L3FWD_CTRL, "deleting ipv6 neighbor...\n");
		s = neighbor6_lookup_nexthop(neighbor6_struct[socket_id], addr,
									 &nexthop_id);
		if (s < 0) {
			RTE_LOG(ERR, L3FWD_CTRL,
					"failed to find a nexthop to delete in neighbor table...\n");
			return 0;
		}
		neighbor6_delete(neighbor6_struct[socket_id], nexthop_id);
	}
	RTE_LOG(DEBUG, L3FWD_CTRL, "neigh ope success\n");
	return 0;
}

static int addr4(__rte_unused addr_action_t action, int32_t port_id,
				 struct in_addr *addr, uint8_t prefixlen, void *args)
{
	char buf[255];
	char ibuf[IFNAMSIZ];
	struct control_handle *handle = args;
	assert(handle != NULL);
	int32_t socket_id = handle->socket_id;

	if_indextoname(port_id, ibuf);
	sscanf(ibuf, "dpdk%10d", &port_id);
	printf("SALUT port=%s %s/%d with port_id %d\n", ibuf,
		   inet_ntop(AF_INET, addr, buf, 255), prefixlen, port_id);

	control_add_ipv4_local_entry(addr, addr, 32, port_id, socket_id);

	return 0;
}

static int addr6(__rte_unused addr_action_t action, int32_t port_id,
				 struct in6_addr *addr, uint8_t prefixlen, void *args)
{
	char buf[255];
	char ibuf[IFNAMSIZ];
	struct control_handle *handle = args;
	assert(handle != NULL);
	int32_t socket_id = handle->socket_id;

	if_indextoname(port_id, ibuf);
	sscanf(ibuf, "dpdk%10d", &port_id);
	printf("SALUT port=%s %s/%d with port_id %d\n", ibuf,
		   inet_ntop(AF_INET6, addr, buf, 255), prefixlen, port_id);

	control_add_ipv6_local_entry(addr, addr, 32, port_id, socket_id);

	return 0;
}

static int
eth_link(link_action_t action, int ifid,
		 struct ether_addr *lladdr, int mtu,
		 const char *name, oper_state_t state, uint16_t vlanid,
		 __rte_unused void *args)
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
			snprintf(ebuf + l, 32, "%02x", lladdr->addr_bytes[i]);
			l += 2;
		} else {
			snprintf(ebuf + l, 32, ":%02x", lladdr->addr_bytes[i]);
			l += 3;
		}
	}
	ebuf[l] = '\0';

	fprintf(stdout, "%d: link %s %s mtu %d label %s vlan %d ", ifid,
			action_buf, ebuf, mtu, name, vlanid);
	print_operstate(stdout, state);
	fprintf(stdout, "\n");
	fflush(stdout);
	return 0;
}

void *control_init(int32_t socket_id)
{
	struct netl_handle *netl_h;
	struct handle_res *res;

	netl_h = netl_create();
	if (netl_h == NULL) {
		RTE_LOG(ERR, L3FWD_CTRL, "Couldn't initialize netlink socket");
		goto err;
	}

	neighbor4_struct[socket_id] = nei_create(socket_id);
	if (neighbor4_struct[socket_id] == NULL) {
		RTE_LOG(ERR, L3FWD_CTRL, "Couldn't initialize neighbor4 struct");
		goto err;
	}

	neighbor6_struct[socket_id] = nei_create(socket_id);
	if (neighbor6_struct[socket_id] == NULL) {
		RTE_LOG(ERR, L3FWD_CTRL, "Couldn't initialize neighbor6 struct");
		goto err;
	}

	netl_h->cb.addr4 = addr4;
	netl_h->cb.addr6 = addr6;
	netl_h->cb.neighbor4 = neighbor4;
	netl_h->cb.neighbor6 = neighbor6;
	netl_h->cb.route4 = route4;
	netl_h->cb.route6 = route6;
	netl_h->cb.link = eth_link;

	struct ether_addr invalid_mac =
		{ {0x00, 0x00, 0x00, 0x00, 0x00, 0x00} };
	struct in_addr invalid_ip = { INADDR_ANY };
	struct in6_addr invalid_ip6 = IN6ADDR_ANY_INIT;
	uint8_t nexthop_id;
	if (neighbor4_add_nexthop
		(neighbor4_struct[socket_id], &invalid_ip, &nexthop_id,
		 NEI_ACTION_DROP) < 0) {
		RTE_LOG(ERR, L3FWD_CTRL,
				"Couldn't add drop target in neighbor table");
		goto err;
	}
	neighbor4_refcount_incr(neighbor4_struct[socket_id], nexthop_id);
	neighbor4_set_lladdr_port(neighbor4_struct[socket_id], nexthop_id,
							  &invalid_mac, &invalid_mac, BAD_PORT, -1);
	if (neighbor6_add_nexthop
		(neighbor6_struct[socket_id], &invalid_ip6, &nexthop_id,
		 NEI_ACTION_DROP) < 0) {
		RTE_LOG(ERR, L3FWD_CTRL,
				"Couldn't add drop target in neighbor table");
		goto err;
	}
	neighbor6_refcount_incr(neighbor6_struct[socket_id], nexthop_id);
	neighbor6_set_lladdr_port(neighbor6_struct[socket_id], nexthop_id,
							  &invalid_mac, &invalid_mac, BAD_PORT, -1);


	res = rte_malloc("handle-res", sizeof(*res), socket_id);
	res->socket_id = socket_id;
	res->netl_h = netl_h;
	return res;
  err:
	rte_panic("failed to init control_main");
}

void control_stop(void *data)
{
	struct handle_res *res;
	struct netl_handle *netl_h;

	res = data;
	netl_h = res->netl_h;
	netl_close(netl_h);
}

void control_terminate(void *data)
{
	struct handle_res *res;

	res = data;
	netl_free(res->netl_h);
	rte_free(res);
}

int control_main(void *data)
{
	struct handle_res *res;
	struct netl_handle *netl_h;
	struct control_handle handle;

	res = data;
	netl_h = res->netl_h;
	handle.socket_id = res->socket_id;


	RTE_LOG(INFO, L3FWD_CTRL, "init ok\n");
	netl_listen(netl_h, &handle);
	RTE_LOG(INFO, L3FWD_CTRL, "netl_listen returned...\n");

	return 0;
}

int control_add_ipv4_local_entry(struct in_addr *nexthop,
								 struct in_addr *saddr, uint8_t depth,
								 uint32_t port_id, int32_t socket_id)
{
	int s;
	uint8_t nexthop_id;

	s = neighbor4_lookup_nexthop(neighbor4_struct[socket_id], nexthop,
								 &nexthop_id);
	if (s < 0) {
		s = neighbor4_add_nexthop(neighbor4_struct[socket_id], nexthop,
								  &nexthop_id, NEI_ACTION_KNI);
		if (s < 0) {
			RTE_LOG(ERR, L3FWD_CTRL,
					"failed to add a nexthop during route adding...\n");
			return -1;
		}
	}
	neighbor4_set_port(neighbor4_struct[socket_id], nexthop_id, port_id);
	s = rte_lpm_add(ipv4_rdpdk_lookup_struct[socket_id],
					rte_be_to_cpu_32(saddr->s_addr), depth, nexthop_id);
	if (s < 0) {
		RTE_LOG(ERR, L3FWD_CTRL,
				"failed to add a route in lpm during route adding...\n");
		return -1;
	}
	neighbor4_refcount_incr(neighbor4_struct[socket_id], nexthop_id);
	return nexthop_id;
}

int control_add_ipv6_local_entry(struct in6_addr *nexthop,
								 struct in6_addr *saddr, uint8_t depth,
								 uint32_t port_id, int32_t socket_id)
{
	int s;
	uint8_t nexthop_id;

	s = neighbor6_lookup_nexthop(neighbor6_struct[socket_id], nexthop,
								 &nexthop_id);
	if (s < 0) {
		s = neighbor6_add_nexthop(neighbor6_struct[socket_id], nexthop,
								  &nexthop_id, NEI_ACTION_KNI);
		if (s < 0) {
			RTE_LOG(ERR, L3FWD_CTRL,
					"failed to add a nexthop during route adding...\n");
			return -1;
		}
	}
	neighbor6_set_port(neighbor6_struct[socket_id], nexthop_id, port_id);
	s = rte_lpm6_add(ipv6_rdpdk_lookup_struct[socket_id],
					 saddr->s6_addr, depth, nexthop_id);
	if (s < 0) {
		RTE_LOG(ERR, L3FWD_CTRL,
				"failed to add a route in lpm during route adding...\n");
		return -1;
	}
	neighbor6_refcount_incr(neighbor6_struct[socket_id], nexthop_id);
	return nexthop_id;
}

int control_callback_setup(const char *cb)
{
	char cmd[CTRL_CBK_MAX_SIZE];
	int len;
	char ether1[ETHER_ADDR_FMT_SIZE];

	ether_format_addr(ether1, ETHER_ADDR_FMT_SIZE, ports_eth_addr);

	len =
		snprintf(cmd, CTRL_CBK_MAX_SIZE, "%s %s %s", cb, "dpdk0",
				 ether1);
	if (len > CTRL_CBK_MAX_SIZE) {
		rte_panic("control callback too long");
	}

	RTE_LOG(INFO, L3FWD_CTRL, "executing command `%s`\n", cmd);
	return system(cmd);
}
