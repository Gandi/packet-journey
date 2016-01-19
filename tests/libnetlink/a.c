#include <signal.h>
#include <net/if.h>
#include <libnetlink.h>

#include "pktj_common.h"

#define TEST(predicate, message)\
	if(!(predicate)) {\
		fprintf(stderr, "%s:%d " message "\n", __FILE__, __LINE__);;\
		exit(1);\
	}

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

struct netl_handle *h = NULL;

static int neighbor4(neighbor_action_t action,
					 __s32 port_id, struct in_addr *addr,
					 struct ether_addr *lladdr, __u8 flags,
					 uint16_t vlanid, pktj_unused(void *args))
{
	char action_buf[4];
	char abuf[256];
	char ebuf[32];
	char ibuf[IFNAMSIZ];
	unsigned l, i;

	if (action == NEIGHBOR_ADD)
		memcpy(action_buf, "add", 4);
	else
		memcpy(action_buf, "del", 4);

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

	fprintf(stdout, "neigh4 %s %s lladdr %s nud ", action_buf,
			inet_ntop(AF_INET, addr, abuf, sizeof(abuf)), ebuf);
#define PRINT_FLAG(f) if (flags & NUD_##f) { \
	flags &= ~NUD_##f; fprintf(stdout, #f "%s", flags ? "," : ""); }
	PRINT_FLAG(INCOMPLETE);
	PRINT_FLAG(REACHABLE);
	PRINT_FLAG(STALE);
	PRINT_FLAG(DELAY);
	PRINT_FLAG(PROBE);
	PRINT_FLAG(FAILED);
	PRINT_FLAG(NOARP);
	PRINT_FLAG(PERMANENT);
#undef PRINT_FLAG

	if (if_indextoname(port_id, ibuf) == NULL)
		snprintf(ibuf, IFNAMSIZ, "if%d", port_id);
	fprintf(stdout, " dev %s", ibuf);
	if (vlanid)
		fprintf(stdout, " vlanid %d", vlanid);
	fprintf(stdout, "\n");
	fflush(stdout);
	return 0;
}

static int neighbor6(neighbor_action_t action,
					 __s32 port_id, struct in6_addr *addr,
					 struct ether_addr *lladdr, __u8 flags,
					 uint16_t vlanid, pktj_unused(void *args))
{
	char action_buf[4];
	char abuf[256];
	char ebuf[32];
	char ibuf[IFNAMSIZ];
	unsigned l, i;

	if (action == NEIGHBOR_ADD)
		memcpy(action_buf, "add", 4);
	else
		memcpy(action_buf, "del", 4);

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

	fprintf(stdout, "neigh6 %s %s lladdr %s nud ", action_buf,
			inet_ntop(AF_INET6, addr, abuf, sizeof(abuf)), ebuf);
#define PRINT_FLAG(f) if (flags & NUD_##f) { \
	flags &= ~NUD_##f; fprintf(stdout, #f "%s", flags ? "," : ""); }
	PRINT_FLAG(INCOMPLETE);
	PRINT_FLAG(REACHABLE);
	PRINT_FLAG(STALE);
	PRINT_FLAG(DELAY);
	PRINT_FLAG(PROBE);
	PRINT_FLAG(FAILED);
	PRINT_FLAG(NOARP);
	PRINT_FLAG(PERMANENT);
#undef PRINT_FLAG

	if (if_indextoname(port_id, ibuf) == NULL)
		snprintf(ibuf, IFNAMSIZ, "if%d", port_id);
	fprintf(stdout, " dev %s", ibuf);
	if (vlanid)
		fprintf(stdout, " vlanid %d", vlanid);
	fprintf(stdout, "\n");
	fflush(stdout);
	return 0;
}

static int addr4(addr_action_t action, __s32 port_id, struct in_addr *addr,
				 __u8 prefixlen, pktj_unused(void *args))
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
	return 0;
}

static int addr6(addr_action_t action, __s32 port_id,
				 struct in6_addr *addr, __u8 prefixlen,
				 pktj_unused(void *args))
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
			inet_ntop(AF_INET6, addr, abuf, sizeof(abuf)), prefixlen,
			ibuf);
	fflush(stdout);
	return 0;
}

static int
route6(pktj_unused(struct rtmsg *route), route_action_t action,
	   struct in6_addr *addr, uint8_t len, struct in6_addr *nexthop,
	   pktj_unused(uint8_t type), pktj_unused(void *args))
{
	char action_buf[4];
	char buf[256];

	if (action == ROUTE_ADD)
		memcpy(action_buf, "add", 4);
	else
		memcpy(action_buf, "del", 4);

	fprintf(stdout, "route6 %s %s/%d", action_buf,
			inet_ntop(AF_INET6, addr, buf, 256), len);
	fprintf(stdout, " via %s\n", inet_ntop(AF_INET6, nexthop, buf, 256));
	fflush(stdout);
	return 0;
}

static int
route4(pktj_unused(struct rtmsg *route), route_action_t action,
	   struct in_addr *addr, uint8_t len, struct in_addr *nexthop,
	   pktj_unused(uint8_t type), pktj_unused(void *args))
{
	char action_buf[4];
	char buf[256];

	if (action == ROUTE_ADD)
		memcpy(action_buf, "add", 4);
	else
		memcpy(action_buf, "del", 4);

	fprintf(stdout, "route4 %s %s/%d", action_buf,
			inet_ntop(AF_INET, addr, buf, 256), len);
	fprintf(stdout, " via %s\n", inet_ntop(AF_INET, nexthop, buf, 256));
	fflush(stdout);
	return 0;
}

static int
link(link_action_t action, int ifid,
	 struct ether_addr *lladdr, int mtu,
	 const char *name, oper_state_t state, uint16_t vlanid,
	 pktj_unused(void *args))
{
	char action_buf[4];
	char ebuf[32];
	unsigned l, i;

	if (action == LINK_ADD)
		memcpy(action_buf, "add", 4);
	else
		memcpy(action_buf, "del", 4);

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

static int init_handler(pktj_unused(void *args))
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
	pktj_init(7, argv);

	h = netl_create(NETLINK4_EVENTS | NETLINK6_EVENTS);
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
	h->cb.neighbor4 = neighbor4;
	h->cb.neighbor6 = neighbor6;
	h->cb.link = link;

	s = netl_listen(h, NULL);
	if (s != 0)
		goto free_netl;

	netl_free(h);

	printf("EOF\n");
	return 0;

  free_netl:
	netl_free(h);
  fail:
	return 1;
}
