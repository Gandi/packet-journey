#include <string.h>
#include <unistd.h>
#include <sys/socket.h>


#include <rte_common.h>
#include <rte_malloc.h>
#include "libnetlink.h"


struct nd_rtattrs{
	struct rtattr unspec;
	struct rtattr dst;
	struct rtattr lladdr;
	struct rtattr cacheinfo;
	struct rtattr probes;
	struct rtattr vlan;
	struct rtattr port;
	struct rtattr vni;
	struct rtattr ifindex;
	struct rtattr master;
};

#define NDATTRS_MAX sizeof(struct nd_rtattrs) / sizeof(struct rtattr)
#define NDATTRS_RTA(n) \
	((struct rtattr*)(((char*)(n)) + NLMSG_ALIGN(sizeof(struct ndmsg))))
#define ND_RTATTRS_TYPE(r, type) \
	((struct rtattr*)(((char*)(r)) + (type * sizeof(struct rtattr))))

static int
netl_handler(struct netl_handle* h, __rte_unused struct sockaddr_nl* nladdr, struct nlmsghdr* hdr, void * args)
{
	int len = hdr->nlmsg_type;

	if (hdr->nlmsg_type == RTM_NEWROUTE ||
	    hdr->nlmsg_type == RTM_DELROUTE)
	{
		struct rtmsg *route = NLMSG_DATA(hdr);
		len -= NLMSG_LENGTH(sizeof(*route));

		if (len < 0) {
			// incomplete message
			return -1;
		}

		if (route->rtm_family != RTNL_FAMILY_IPMR &&
		    route->rtm_family != RTNL_FAMILY_IP6MR)
		{
			// TODO decap message
			// This is an unicast route, no interest for multicast
			route_action_t action;
			if (hdr->nlmsg_type == RTM_NEWROUTE)
				action = ROUTE_ADD;
			else
				action = ROUTE_DELETE;

			if (h->cb.route4 != NULL)
			{
				struct in_addr* addr;
				struct in_addr* nexthop;
				uint8_t len;
				h->cb.route4(route, action, addr, len, nexthop, args);
			}
		}
	}

	if (hdr->nlmsg_type == RTM_NEWLINK ||
	    hdr->nlmsg_type == RTM_DELLINK ||
	    hdr->nlmsg_type == RTM_SETLINK)
	{
		// TODO: store iface name for future use
	}

	if (hdr->nlmsg_type == RTM_NEWNEIGH ||
	    hdr->nlmsg_type == RTM_DELNEIGH)
	{
		struct ndmsg *neighbor = NLMSG_DATA(hdr);
		struct nd_rtattrs attrs;
		struct rtattr* it;
		struct rtattr* dst;

		len -= NLMSG_LENGTH(sizeof(*neighbor));

		if (len < 0) {
			// incomplete message
			return -1;
		}

		// Ignore non-ip
		if (neighbor->ndm_family != AF_INET &&
		    neighbor->ndm_family != AF_INET6)
			return 0;

		// Read attributes
		it = NDATTRS_RTA(neighbor);
		memset(&attrs, 0, sizeof(attrs));
		int attr_len = hdr->nlmsg_len - NLMSG_LENGTH(sizeof(*neighbor));
		unsigned short type;
		while (RTA_OK(it, attr_len))
		{
			type = it->rta_type;
			dst = ND_RTATTRS_TYPE(&attrs, type);

			if (type < NDATTRS_MAX && !dst)
				dst = it;
			it = RTA_NEXT(it, attr_len);
		}

		if (neighbor->ndm_family == AF_INET)
		{
			// TODO RTA_PAYLOAD(&(attrs.dst)) == 4 (bytes)
			struct in_addr* addr = RTA_DATA(&(attrs.dst));
			// TODO RTA_PAYLOAD(&(attrs.lladdr)) == 6 (bytes)
			struct ether_addr* lladdr = RTA_DATA(&(attrs.lladdr));
			neighbor_action_t action;
			if (hdr->nlmsg_type == RTM_NEWNEIGH)
				action = NEIGHBOR_ADD;
			else
				action = NEIGHBOR_DELETE;

			if (h->cb.neighbor4 != NULL)
			{
				__u8 flags = neighbor->ndm_state;
				h->cb.neighbor4(neighbor, action, neighbor->ndm_ifindex, addr, lladdr, flags, args);
			}
		}

		if (neighbor->ndm_family == AF_INET6)
		{
			// TODO
		}
	}

	return 0;
}

int
netl_listen(struct netl_handle* h, void* args)
{
	int len, buflen, err;
	ssize_t status;
	struct nlmsghdr *hdr;
	struct sockaddr_nl nladdr;
	struct iovec iov;
	struct msghdr msg = {
		.msg_name = &nladdr,
		.msg_namelen = sizeof(nladdr),
		.msg_iov = &iov,
		.msg_iovlen = 1,
	};
	char buf[8192];

	if (h == NULL)
		return -1;

	iov.iov_base = buf;
	while (1)
	{
		iov.iov_len = sizeof(buf);
		status = recvmsg(h->fd, &msg, 0);
		if (status < 0)
		{
			// TODO: EINT / EAGAIN / ENOBUF should continue
			return -1;
		}

		if (status == 0)
		{
			// EOF
			return -1;
		}

		if (msg.msg_namelen != sizeof(nladdr)) {
			// Invalid length
			return -1;
		}

		for (hdr = (struct nlmsghdr*)buf; (size_t) status >= sizeof(*hdr); )
		{
			len = hdr->nlmsg_len;
			buflen = len - sizeof(*hdr);

			if (buflen < 0 || buflen > status)
			{
				// truncated
				return -1;
			}

			err = netl_handler(h, &nladdr, hdr, args);
			if (err < 0)
				return err;

			status -= NLMSG_ALIGN(len);
			hdr = (struct nlmsghdr*) ((char*) hdr + NLMSG_ALIGN(len));
		}

		if (status) {
			// content not read
			return -1;
		}

	}

	return 1;
}


struct netl_handle*
netl_create(void)
{
	struct netl_handle* netl_handle;
	int rcvbuf = 1024*1024;
	socklen_t addr_len;
	unsigned subscriptions = 0;

	// get notified whenever ip changes
	subscriptions |= RTNLGRP_IPV4_IFADDR;
	subscriptions |= RTNLGRP_IPV6_IFADDR;

	// get notified on new routes
	subscriptions |= RTNLGRP_IPV4_ROUTE;
	subscriptions |= RTNLGRP_IPV6_ROUTE;

	// subscriptions |= RTNLGRP_IPV6_PREFIX;
	// prefix is for ipv6 RA

	// get notified by arp or ipv6 nd
	subscriptions |= RTNLGRP_NEIGH;

	// called whenever an iface is added/removed
	// subscriptions |= RTNLGRP_IPV4_NETCONF;
	// subscriptions |= RTNLGRP_IPV6_NETCONF;


	netl_handle = rte_malloc("netl_handle", sizeof(struct netl_handle), 0);
	if (netl_handle == NULL)
		return NULL;

	netl_handle->fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
	if (netl_handle->fd < 0)
	{
		perror("Cannot open netlink socket");
		goto free_netl_handle;
	}

	if (setsockopt(netl_handle->fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf)) < 0)
	{
		perror("Cannot set RCVBUF");
		goto free_netl_handle;
	}

	memset(&netl_handle->local, 0, sizeof(netl_handle->local));
	netl_handle->local.nl_family = AF_NETLINK;
	netl_handle->local.nl_groups = subscriptions;

	netl_handle->cb.neighbor4 = NULL;
	netl_handle->cb.route4 = NULL;

	if (bind(netl_handle->fd, (struct sockaddr*)&(netl_handle->local), sizeof(netl_handle->local)) < 0)
	{
		perror("Cannot bind netlink socket");
		goto free_netl_handle;
	}

	addr_len = sizeof(netl_handle->local);
	if (getsockname(netl_handle->fd, (struct sockaddr*) &netl_handle->local, &addr_len) < 0)
	{
		perror("Cannot getsockname");
		goto free_netl_handle;
	}

	if(addr_len != sizeof(netl_handle->local))
	{
		perror("Wrong address length");
		goto free_netl_handle;
	}

	if (netl_handle->local.nl_family != AF_NETLINK) {
		perror("Wrong address family");
		goto free_netl_handle;
	}

	return netl_handle;

free_netl_handle:
	rte_free(netl_handle);
	return NULL;
}

int
netl_free(struct netl_handle* h)
{
	if (h != NULL) {
		if (h->fd > 0)
		{
			close(h->fd);
			h->fd = -1;
		}

		rte_free(h);
	}

	return 0;
}
