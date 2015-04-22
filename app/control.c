#include <stdio.h>
#include <unistd.h>
#include <assert.h>

#include <rte_common.h>
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

struct control_handle {
};

static unsigned g_max_socket;

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
	uint8_t nexthop_id;
	int s;
	unsigned i = 0;

	assert(handle != NULL);

	if (action == ROUTE_ADD) {
		RTE_LOG(DEBUG, L3FWD_CTRL, "adding an ipv4 route...\n");
		// lookup nexthop
		do {
			s = neighbor4_lookup_nexthop(neighbor4_struct[i], nexthop,
										 &nexthop_id);
			if (s < 0) {
				neighbor4_add_nexthop(neighbor4_struct[i], nexthop,
									  &nexthop_id, NEI_ACTION_FWD);
				if (s < 0) {
					RTE_LOG(ERR, L3FWD_CTRL,
							"failed to add a nexthop during route adding...\n");
					return -1;
				}
			}
			s = rte_lpm_add(ipv4_l3fwd_lookup_struct[i], addr->s_addr,
							depth, nexthop_id);
			if (s < 0) {
				RTE_LOG(ERR, L3FWD_CTRL,
						"failed to add a route in lpm during route adding...\n");
				return -1;
			}
			neighbor4_refcount_incr(neighbor4_struct[i], nexthop_id);

		} while (++i < g_max_socket);
	}

	if (action == ROUTE_DELETE) {
		RTE_LOG(DEBUG, L3FWD_CTRL, "deleting an ipv4 route...\n");
		// lookup nexthop
		do {
			s = neighbor4_lookup_nexthop(neighbor4_struct[i], nexthop,
										 &nexthop_id);
			if (s < 0) {
				RTE_LOG(ERR, L3FWD_CTRL,
						"failed to find nexthop during route deletion...\n");
				return -1;
			}

			s = rte_lpm_delete(ipv4_l3fwd_lookup_struct[i], addr->s_addr,
							   depth);
			if (s < 0) {
				RTE_LOG(ERR, L3FWD_CTRL, "failed to deletie route...\n");
				return -1;
			}
			neighbor4_refcount_decr(neighbor4_struct[i], nexthop_id);

		} while (++i < g_max_socket);
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
	unsigned i = 0;
	int s;
	uint8_t nexthop_id;

	assert(handle != NULL);
	assert(neighbor4_struct != NULL);

	if (addr == NULL)
		return -1;

	if (action == NEIGHBOR_ADD) {
		if (lladdr == NULL)
			return -1;
		RTE_LOG(DEBUG, L3FWD_CTRL, "adding ipv4 neighbor...\n");

		do {
			s = neighbor4_lookup_nexthop(neighbor4_struct[i], addr,
										 &nexthop_id);
			if (s < 0) {
				s = neighbor4_add_nexthop(neighbor4_struct[i], addr,
										  &nexthop_id, NEI_ACTION_FWD);
				if (s < 0) {
					RTE_LOG(ERR, L3FWD_CTRL,
							"failed to add a nexthop in neighbor table...\n");
					return -1;
				}
			}
			neighbor4_set_lladdr_port(neighbor4_struct[i], nexthop_id,
									  lladdr, port_id);
			neighbor4_set_state(neighbor4_struct[i], nexthop_id, flags);
		} while (++i < g_max_socket);
	}
	if (action == NEIGHBOR_DELETE) {
		RTE_LOG(DEBUG, L3FWD_CTRL, "deleting ipv4 neighbor...\n");
		do {
			s = neighbor4_lookup_nexthop(neighbor4_struct[i], addr,
										 &nexthop_id);
			if (s < 0) {
				RTE_LOG(ERR, L3FWD_CTRL,
						"failed to find a nexthop to delete in neighbor table...\n");
				return 0;
			}
			neighbor4_delete(neighbor4_struct[i], nexthop_id);
		} while (++i < g_max_socket);
	}
	RTE_LOG(DEBUG, L3FWD_CTRL, "neigh ope success\n");
	return 0;
}

static int addr4(__rte_unused addr_action_t action, __s32 port_id,
				 struct in_addr *addr, __u8 prefixlen)
{
	char buf[255];

	printf("SALUT port=%d %s/%d\n", port_id,
		   inet_ntop(AF_INET, addr, buf, 255), prefixlen);

	return 0;
}

void *control_main(void *argv)
{
	struct netl_handle *netl_h;
	struct control_handle handle;
	unsigned i = 0;

	g_max_socket = *(int *) (argv);

	netl_h = netl_create();
	if (netl_h == NULL) {
		RTE_LOG(ERR, L3FWD_CTRL, "Couldn't initialize netlink socket");
		goto err;
	}

	do {
		neighbor4_struct[i] =
			nei_create(i == g_max_socket ? SOCKET_ID_ANY : (int) i);
		if (neighbor4_struct[i] == NULL) {
			RTE_LOG(ERR, L3FWD_CTRL,
					"Couldn't initialize neighbor4 struct");
			goto err;
		}
	} while (++i < g_max_socket);

	netl_h->cb.addr4 = addr4;
	netl_h->cb.neighbor4 = neighbor4;
	netl_h->cb.route4 = route4;

	RTE_LOG(INFO, L3FWD_CTRL, "init ok\n");
	netl_listen(netl_h, &handle);
	RTE_LOG(INFO, L3FWD_CTRL, "netl_listen returned...\n");

	return NULL;
  err:
	rte_panic("failed to init control_main");
}

int control_add_ipv4_local_entry(struct in_addr *nexthop, struct in_addr *saddr, uint8_t depth, uint32_t port_id)
{
    int s;
	uint8_t nexthop_id;
    unsigned i = 0;

    s = neighbor4_lookup_nexthop(neighbor4_struct[i], nexthop,
            &nexthop_id);
    if (s < 0) {
        neighbor4_add_nexthop(neighbor4_struct[i], nexthop,
                &nexthop_id, NEI_ACTION_KNI);
        if (s < 0) {
            RTE_LOG(ERR, L3FWD_CTRL,
                    "failed to add a nexthop during route adding...\n");
            return -1;
        }
    }
    s = rte_lpm_add(ipv4_l3fwd_lookup_struct[i], saddr->s_addr,
            depth, nexthop_id);
    if (s < 0) {
        RTE_LOG(ERR, L3FWD_CTRL,
                "failed to add a route in lpm during route adding...\n");
        return -1;
    }
    neighbor4_set_port(neighbor4_struct[i], nexthop_id, port_id);
    neighbor4_refcount_incr(neighbor4_struct[i], nexthop_id);
    return 0;
}

int control_callback_setup(const char *cb)
{
    return system(cb);
}
