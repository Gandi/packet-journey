#include <signal.h>
#include <net/if.h>
#include <libnetlink.h>

#include "rdpdk_common.h"


#define TEST(predicate, message)\
	if(!(predicate)) {\
		fprintf(stderr, "%s:%d " message "\n", __FILE__, __LINE__);;\
		exit(1);\
	}

struct netl_handle *h = NULL;


static int addr4(addr_action_t action, __s32 port_id, struct in_addr *addr,
				 __u8 prefixlen)
{
	char action_buf[4];
	char abuf[256];
	char ibuf[IFNAMSIZ];

	if (action == ADDR_ADD)
		memcpy(action_buf, "add", 4);
	else
		memcpy(action_buf, "del", 4);

	if (if_indextoname(port_id, ibuf) == NULL)
		snprintf(ibuf, IFNAMSIZ, "if%d", port_id);

	fprintf(stdout, "addr4 %s %s/%d dev %s\n", action_buf,
			inet_ntop(AF_INET, addr, abuf, sizeof(abuf)), prefixlen, ibuf);
	fflush(stdout);
}

static int addr6(addr_action_t action, __s32 port_id, struct in_addr6 *addr,
				 __u8 prefixlen)
{
	char action_buf[4];
	char abuf[256];
	char ibuf[IFNAMSIZ];

	if (action == ADDR_ADD)
		memcpy(action_buf, "add", 4);
	else
		memcpy(action_buf, "del", 4);

	if (if_indextoname(port_id, ibuf) == NULL)
		snprintf(ibuf, IFNAMSIZ, "if%d", port_id);

	fprintf(stdout, "addr6 %s %s/%d dev %s\n", action_buf,
			inet_ntop(AF_INET6, addr, abuf, sizeof(abuf)), prefixlen, ibuf);
	fflush(stdout);
}

static int
route6(struct rtmsg *route, route_action_t action, struct in6_addr *addr,
	   uint8_t len, struct in6_addr *nexthop, void *args)
{
	char action_buf[7];
	char buf[256];

	if (action == ROUTE_ADD)
		memcpy(action_buf, "add", 4);
	else
		memcpy(action_buf, "delete", 7);

	fprintf(stdout, "route6 %s %s/%d", action_buf,
			inet_ntop(AF_INET6, addr, buf, 256), len);
	fprintf(stdout, " via %s\n", inet_ntop(AF_INET6, nexthop, buf, 256));
	fflush(stdout);
}

static int
route4(struct rtmsg *route, route_action_t action, struct in_addr *addr,
	   uint8_t len, struct in_addr *nexthop, void *args)
{
	char action_buf[7];
	char buf[256];

	if (action == ROUTE_ADD)
		memcpy(action_buf, "add", 4);
	else
		memcpy(action_buf, "delete", 7);

	fprintf(stdout, "route4 %s %s/%d", action_buf,
			inet_ntop(AF_INET, addr, buf, 256), len);
	fprintf(stdout, " via %s\n", inet_ntop(AF_INET, nexthop, buf, 256));
	fflush(stdout);
}

static int init_handler(void *args)
{
	printf("START\n");
	fflush(stdout);

	return 0;
}


static void stop_listen(int signum)
{
	fprintf(stderr, "received %d\n", signum);
	if (h != NULL) {
		netl_close(h);

		printf("EOF\n");
	}
}

int main(void)
{
	int s;

	char *argv[7] = { "test", "-l", "0", "-n", "1", "--log-level", "0" };
	rdpdk_init(7, argv);

	h = netl_create();
	if (h == NULL) {
		perror("Couldn't create netlink handler");
		goto fail;
	}

	signal(SIGINT, stop_listen);
	signal(SIGTERM, stop_listen);

	h->cb.init = init_handler;
	h->cb.addr4 = addr4;
	h->cb.addr6 = addr6;
	h->cb.route4 = route4;
	h->cb.route6 = route6;

	s = netl_listen(h, NULL);

	netl_free(h);

	printf("EOF\n");
	return 0;

  free_netl:
	netl_free(h);
  fail:
	return 1;
}
