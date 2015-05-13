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
	unsigned socketid;
};

struct handle_res {
	struct netl_handle *netl_h;
	unsigned socketid;
};

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
	unsigned socketid = handle->socketid;


	if (action == ROUTE_ADD) {
		RTE_LOG(DEBUG, L3FWD_CTRL, "adding an ipv4 route...\n");
		// lookup nexthop
		s = neighbor4_lookup_nexthop(neighbor4_struct[socketid], nexthop,
									 &nexthop_id);
		if (s < 0) {
			s = neighbor4_add_nexthop(neighbor4_struct[socketid], nexthop,
									  &nexthop_id, NEI_ACTION_FWD);
			if (s < 0) {
				RTE_LOG(ERR, L3FWD_CTRL,
						"failed to add a nexthop during route adding...\n");
				return -1;
			}
		}
		s = rte_lpm_add(ipv4_l3fwd_lookup_struct[socketid], rte_be_to_cpu_32(addr->s_addr),
						depth, nexthop_id);
		if (s < 0) {
			RTE_LOG(ERR, L3FWD_CTRL,
					"failed to add a route in lpm during route adding...\n");
			return -1;
		}
		neighbor4_refcount_incr(neighbor4_struct[socketid], nexthop_id);

	}

	if (action == ROUTE_DELETE) {
		RTE_LOG(DEBUG, L3FWD_CTRL, "deleting an ipv4 route...\n");
		// lookup nexthop
		s = neighbor4_lookup_nexthop(neighbor4_struct[socketid], nexthop,
									 &nexthop_id);
		if (s < 0) {
			RTE_LOG(ERR, L3FWD_CTRL,
					"failed to find nexthop during route deletion...\n");
			return -1;
		}

		s = rte_lpm_delete(ipv4_l3fwd_lookup_struct[socketid],
						   rte_be_to_cpu_32(addr->s_addr), depth);
		if (s < 0) {
			RTE_LOG(ERR, L3FWD_CTRL, "failed to deletie route...\n");
			return -1;
		}
		neighbor4_refcount_decr(neighbor4_struct[socketid], nexthop_id);

	}
	RTE_LOG(DEBUG, L3FWD_CTRL, "route ope success\n");
	return 0;
}

static int
neighbor4(neighbor_action_t action,
		  __s32 port_id, struct in_addr *addr, struct ether_addr *lladdr,
		  __u8 flags, void *args, __rte_unused __u16 vlanid)
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
	unsigned socketid = handle->socketid;

	assert(neighbor4_struct != NULL);

	if (addr == NULL)
		return -1;

	if (action == NEIGHBOR_ADD) {
		if (lladdr == NULL)
			return -1;
		char ibuf[IFNAMSIZ];
		unsigned kni_num;
		RTE_LOG(DEBUG, L3FWD_CTRL, "adding ipv4 neighbor...\n");

		if_indextoname(port_id, ibuf);
		s = sscanf(ibuf, "vEth%d_%d", &port_id, &kni_num);

		if (s <= 0) {
			RTE_LOG(ERR, L3FWD_CTRL,
					"received a neighbor announce for an unmanaged iface %s\n",
					ibuf);
			return -1;
		}

		s = neighbor4_lookup_nexthop(neighbor4_struct[socketid], addr,
									 &nexthop_id);
		if (s < 0) {
			s = neighbor4_add_nexthop(neighbor4_struct[socketid], addr,
									  &nexthop_id, NEI_ACTION_FWD);
			if (s < 0) {
				RTE_LOG(ERR, L3FWD_CTRL,
						"failed to add a nexthop in neighbor table...\n");
				return -1;
			}
		}
		//printf("%s\n", ibuf);
		neighbor4_set_lladdr_port(neighbor4_struct[socketid], nexthop_id,
								  lladdr, port_id);
		neighbor4_set_state(neighbor4_struct[socketid], nexthop_id, flags);
	}
	if (action == NEIGHBOR_DELETE) {
		RTE_LOG(DEBUG, L3FWD_CTRL, "deleting ipv4 neighbor...\n");
		s = neighbor4_lookup_nexthop(neighbor4_struct[socketid], addr,
									 &nexthop_id);
		if (s < 0) {
			RTE_LOG(ERR, L3FWD_CTRL,
					"failed to find a nexthop to delete in neighbor table...\n");
			return 0;
		}
		neighbor4_delete(neighbor4_struct[socketid], nexthop_id);
	}
	RTE_LOG(DEBUG, L3FWD_CTRL, "neigh ope success\n");
	return 0;
}

static int addr4(__rte_unused addr_action_t action, int32_t port_id,
				 struct in_addr *addr, uint8_t prefixlen)
{
	char buf[255];
	char ibuf[IFNAMSIZ];
	unsigned kni_num;

	if_indextoname(port_id, ibuf);
	sscanf(ibuf, "vEth%d_%d", &port_id, &kni_num);
	printf("SALUT port=%s %s/%d\n", ibuf,
		   inet_ntop(AF_INET, addr, buf, 255), prefixlen);

	control_add_ipv4_local_entry(addr, addr, 32, port_id);

	return 0;
}

void *control_init(unsigned socketid)
{
	struct netl_handle *netl_h;
	struct handle_res *res;

	netl_h = netl_create();
	if (netl_h == NULL) {
		RTE_LOG(ERR, L3FWD_CTRL, "Couldn't initialize netlink socket");
		goto err;
	}

	neighbor4_struct[socketid] = nei_create(socketid);
	if (neighbor4_struct[socketid] == NULL) {
		RTE_LOG(ERR, L3FWD_CTRL, "Couldn't initialize neighbor4 struct");
		goto err;
	}

	netl_h->cb.addr4 = addr4;
	netl_h->cb.neighbor4 = neighbor4;
	netl_h->cb.route4 = route4;

	struct ether_addr invalid_mac =
		{ {0x00, 0x00, 0x00, 0x00, 0x00, 0x00} };
	struct in_addr invalid_ip = { INADDR_ANY };
	uint8_t nexthop_id;
	if (neighbor4_add_nexthop
		(neighbor4_struct[socketid], &invalid_ip, &nexthop_id,
		 NEI_ACTION_DROP) < 0) {
		RTE_LOG(ERR, L3FWD_CTRL,
				"Couldn't add drop target in neighbor table");
		goto err;
	}
	neighbor4_refcount_incr(neighbor4_struct[socketid], nexthop_id);
	neighbor4_set_lladdr_port(neighbor4_struct[socketid], nexthop_id,
							  &invalid_mac, BAD_PORT);

	res = rte_malloc("handle-res", sizeof(*res), socketid);
	res->socketid = socketid;
	res->netl_h = netl_h;
	return res;
  err:
	rte_panic("failed to init control_main");
}

void *control_main(void *data)
{
	struct handle_res *res;
	struct netl_handle *netl_h;
	struct control_handle handle;

	res = data;
	netl_h = res->netl_h;
	handle.socketid = res->socketid;

	rte_free(res);

	RTE_LOG(INFO, L3FWD_CTRL, "init ok\n");
	netl_listen(netl_h, &handle);
	RTE_LOG(INFO, L3FWD_CTRL, "netl_listen returned...\n");

	return NULL;
}

int control_add_ipv4_local_entry(struct in_addr *nexthop,
								 struct in_addr *saddr, uint8_t depth,
								 uint32_t port_id)
{
	int s;
	uint8_t nexthop_id;
	unsigned i = 0;

	s = neighbor4_lookup_nexthop(neighbor4_struct[i], nexthop,
								 &nexthop_id);
	if (s < 0) {
		s = neighbor4_add_nexthop(neighbor4_struct[i], nexthop,
								  &nexthop_id, NEI_ACTION_KNI);
		if (s < 0) {
			RTE_LOG(ERR, L3FWD_CTRL,
					"failed to add a nexthop during route adding...\n");
			return -1;
		}
	}
	s = rte_lpm_add(ipv4_l3fwd_lookup_struct[i], rte_be_to_cpu_32(saddr->s_addr),
					depth, nexthop_id);
	if (s < 0) {
		RTE_LOG(ERR, L3FWD_CTRL,
				"failed to add a route in lpm during route adding...\n");
		return -1;
	}
	neighbor4_set_port(neighbor4_struct[i], nexthop_id, port_id);
	neighbor4_refcount_incr(neighbor4_struct[i], nexthop_id);
	return nexthop_id;
}

int control_callback_setup(const char *cb)
{
	char cmd[CTRL_CBK_MAX_SIZE];
	int len;
	char ether1[ETHER_ADDR_FMT_SIZE];
	char ether2[ETHER_ADDR_FMT_SIZE];

	ether_format_addr(ether1, ETHER_ADDR_FMT_SIZE, ports_eth_addr);
	ether_format_addr(ether2, ETHER_ADDR_FMT_SIZE, ports_eth_addr + 1);

	len =
		snprintf(cmd, CTRL_CBK_MAX_SIZE, "%s %s %s %s %s", cb, "vEth0_0",
				 ether1, "vEth1_0", ether2);
	if (len > CTRL_CBK_MAX_SIZE) {
		rte_panic("control callback too long");
	}

	RTE_LOG(INFO, L3FWD_CTRL, "executing command `%s`\n", cmd);
	return system(cmd);
}
