#include <string.h>
#include <unistd.h>
#include <sys/socket.h>


#include <rte_common.h>
#include <rte_malloc.h>
#include <libnetlink.h>

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

#if 0
struct if_rtattrs {
	struct rtattr unspec;
	struct rtattr address;
	struct rtattr local;
	struct rtattr label;
	struct rtattr broadcast;
	struct rtattr anycast;
	struct rtattr cacheinfo;
	struct rtattr multicast;
	struct rtattr flags;
};

#define IF_ATTRS_MAX sizeof(struct if_rtattrs) / sizeof(struct rtattr)
#define IFA_RTA(r)  ((struct rtattr*)(((char*)(r)) + NLMSG_ALIGN(sizeof(struct ifaddrmsg))))
#define IF_RTATTRS_TYPE(r, type) \
	((struct rtattr*)(((char*)(r)) + (type * sizeof(struct rtattr))))
#endif

static inline __u32 rta_getattr_u32(const struct rtattr *rta)
{
    return *(__u32 *)RTA_DATA(rta);
}
static int parse_rtattr_flags(struct rtattr *tb[], int max, struct rtattr *rta,
		       int len, unsigned short flags)
{
	unsigned short type;

	memset(tb, 0, sizeof(struct rtattr *) * (max + 1));
	while (RTA_OK(rta, len)) {
		type = rta->rta_type & ~flags;
		if ((type <= max) && (!tb[type]))
			tb[type] = rta;
		rta = RTA_NEXT(rta,len);
	}
	if (len)
		fprintf(stderr, "!!!Deficit %d, rta_len=%d\n", len, rta->rta_len);
	return 0;
}

static unsigned int get_ifa_flags(struct ifaddrmsg *ifa,
				  struct rtattr *ifa_flags_attr)
{
	return ifa_flags_attr ? rta_getattr_u32(ifa_flags_attr) :
				ifa->ifa_flags;
}



static int
netl_handler(struct netl_handle* h, __rte_unused struct sockaddr_nl* nladdr, struct nlmsghdr* hdr, void * args)
{
	struct rtattr* it;
	struct rtattr* dst;
	int len = hdr->nlmsg_len;

	if (hdr->nlmsg_type == RTM_NEWADDR ||
	    hdr->nlmsg_type == RTM_DELADDR)
	{
		//struct if_rtattrs attrs;
        struct rtattr * rta_tb[IFA_MAX+1];
		struct ifaddrmsg *ifa = NLMSG_DATA(hdr);
        unsigned int ifa_flags;
        char abuf[256];
		addr_action_t action;
		len -= NLMSG_LENGTH(sizeof(*ifa));

		if (len < 0) {
			// incomplete message
			return -1;
		}

		if (hdr->nlmsg_type == RTM_NEWADDR)
			action = ADDR_ADD;
		else if (hdr->nlmsg_type == RTM_NEWADDR)
			action = ADDR_DELETE;


        parse_rtattr_flags(rta_tb, IFA_MAX, IFA_RTA(ifa), len, 0);
        ifa_flags = get_ifa_flags(ifa, rta_tb[IFA_FLAGS]);
		// Read attributes
		it = IFA_RTA(ifa);
		//memset(&attrs, 0, sizeof(attrs));

		fprintf(stderr, "\n");

        if (!rta_tb[IFA_LOCAL])
            rta_tb[IFA_LOCAL] = rta_tb[IFA_ADDRESS];
        if (!rta_tb[IFA_ADDRESS])
            rta_tb[IFA_ADDRESS] = rta_tb[IFA_LOCAL];

        if (rta_tb[IFA_LOCAL]) {
            fprintf(stderr, "%s", inet_ntop(ifa->ifa_family, RTA_DATA(rta_tb[IFA_LOCAL]), abuf, sizeof(abuf)));
#if 0
            if (rta_tb[IFA_ADDRESS] == NULL ||
                    memcmp(RTA_DATA(rta_tb[IFA_ADDRESS]), RTA_DATA(rta_tb[IFA_LOCAL]),
                        ifa->ifa_family == AF_INET ? 4 : 16) == 0) {
                fprintf(fp, "/%d ", ifa->ifa_prefixlen);
            } else {
                fprintf(fp, " peer %s/%d ",
                        format_host(ifa->ifa_family,
                            RTA_PAYLOAD(rta_tb[IFA_ADDRESS]),
                            RTA_DATA(rta_tb[IFA_ADDRESS]),
                            abuf, sizeof(abuf)),
                        ifa->ifa_prefixlen);
            }
#endif
        }


#if 0
		int i;
		char * ptr = &attrs;
		for(i=0; i<sizeof(attrs); i++)
			fprintf(stderr, "%02x ", ptr[i]);
		fprintf(stderr, "\n");

		ptr = &attrs.address;
		for(i=0; i<sizeof(attrs.address); i++)
			fprintf(stderr, "%02x ", ptr[i]);
		fprintf(stderr, "\n");
#endif

		if (h->cb.addr4 != NULL)
		{
			h->cb.addr4(action);
		}
	}

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
netl_close(struct netl_handle* h) {
	
	if (h->fd > 0) {
		h->closing = 1;
		close(h->fd);
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

	if (h->cb.init != NULL)
	{
		err = h->cb.init(args);
		if (err != 0)
			return err;
	}

	while (h->closing != 1)
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

static inline __u32 nl_mgrp(__u32 group)
{
	return group ? (1 << (group - 1)) : 0;
}


struct netl_handle*
netl_create(void)
{
	struct netl_handle* netl_handle;
	int rcvbuf = 1024*1024;
	socklen_t addr_len;
	unsigned subscriptions = 0;

	// get notified whenever interface change (new vlans / ...)
	subscriptions |= nl_mgrp(RTNLGRP_LINK);

	// get notified whenever ip changes
	subscriptions |= nl_mgrp(RTNLGRP_IPV4_IFADDR);
	subscriptions |= nl_mgrp(RTNLGRP_IPV6_IFADDR);

	// get notified on new routes
	subscriptions |= nl_mgrp(RTNLGRP_IPV4_ROUTE);
	subscriptions |= nl_mgrp(RTNLGRP_IPV6_ROUTE);

	// subscriptions |= RTNLGRP_IPV6_PREFIX;
	// prefix is for ipv6 RA

	// get notified by arp or ipv6 nd
	subscriptions |= nl_mgrp(RTNLGRP_NEIGH);

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

	netl_handle->closing = 0;

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
