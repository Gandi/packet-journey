#include <stdio.h>
#include <unistd.h>

#include <rte_common.h>
#include <rte_ip.h>
#include <rte_lpm.h>
#include <rte_lpm6.h>
#include <rte_ethdev.h>

#include <router-dpdk/control.h>
#include "lib/libnetlink/libnetlink.h"
#include "lib/libneighbour/neighbour.h"

#include "routing.h"

struct control_handle {
	struct rte_lpm * route4;
	struct nei_table * neighbor4;
};

static int
route4(__rte_unused struct rtmsg* route, route_action_t action, struct in_addr* addr, uint8_t depth, struct in_addr* nexthop, void* args)
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
	uint8_t nexthop_id;
	int s;

	if (action == ROUTE_ADD)
	{
		// lookup nexthop
		s = neighbor4_lookup_nexthop(handle->neighbor4, nexthop, &nexthop_id);
		if (s < 0)
		{
			neighbor4_add_nexthop(handle->neighbor4, nexthop, &nexthop_id);
			// TODO if (s < 0) // No space available
		}

		s = rte_lpm_add(handle->route4, addr->s_addr, depth, nexthop_id);
		if (s < 0)
		{
			// TODO: most likely out of space
		}

		neighbor4_refcount_incr(handle->neighbor4, nexthop_id);
	}

	if (action == ROUTE_DELETE)
	{
		// lookup nexthop
		s = neighbor4_lookup_nexthop(handle->neighbor4, nexthop, &nexthop_id);
		if (s < 0)
		{
			// WTF ?! table corrupted
		}

		s = rte_lpm_delete(handle->route4, addr->s_addr, depth);
		if (s < 0)
		{
			// WTF Not found
		}

		neighbor4_refcount_decr(handle->neighbor4, nexthop_id);
	}

	return 0;
}

static int
neighbor4(__rte_unused struct ndmsg* neighbor, neighbor_action_t action, __s32 port_id, struct in_addr* addr, struct ether_addr* lladdr, __u8 flags, void* args)
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
	uint8_t nexthop_id;
	int s;

	if (handle == NULL)
		return -1;
	if (handle->neighbor4 == NULL)
		return -1;
	if (addr == NULL)
		return -1;

	if (action == NEIGHBOR_ADD)
	{
		if (lladdr == NULL)
			return -1;

		s = neighbor4_lookup_nexthop(handle->neighbor4, addr, &nexthop_id);
		if (s < 0)
		{
			s = neighbor4_add_nexthop(handle->neighbor4, addr, &nexthop_id);

			if (s < 0)
			{
				// Out of free neighbors entries :(
				return -1;
			}
		}

		neighbor4_set_port(handle->neighbor4,   nexthop_id, port_id);
		neighbor4_set_lladdr(handle->neighbor4, nexthop_id, lladdr);
		neighbor4_set_state(handle->neighbor4,  nexthop_id, flags);
	}

	if (action == NEIGHBOR_DELETE)
	{
		s = neighbor4_lookup_nexthop(handle->neighbor4, addr, &nexthop_id);
		if (s < 0)
			return 0;

		neighbor4_delete(handle->neighbor4, nexthop_id);
	}

	return 0;
}

void *control_main(__rte_unused void * argv)
{
	struct netl_handle * netl_h;
	struct control_handle handle;

	netl_h = netl_create();
	if (netl_h == NULL) {
		perror("Couldn't initialize netlink socket");
	}

	handle.neighbor4 = nei_create();
	if (handle.neighbor4 == NULL)
	{
		// TODO handle error
	}


	netl_h->cb.neighbor4 = neighbor4;
	netl_h->cb.route4 = route4;

	netl_listen(netl_h, &handle);

	return NULL;
}
