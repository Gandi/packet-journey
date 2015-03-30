#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <arpa/inet.h>

#include <rte_ether.h>

#define NEIGHBOR_FLAGS_INCOMPLETE 0x01
#define NEIGHBOR_FLAGS_REACHABLE  0x02
#define NEIGHBOR_FLAGS_STALE      0x04
#define NEIGHBOR_FLAGS_DELAY      0x08
#define NEIGHBOR_FLAGS_PROBE      0x10
#define NEIGHBOR_FLAGS_FAILED     0x20
#define NEIGHBOR_FLAGS_NOARP      0x40
#define NEIGHBOR_FLAGS_PERMANENT  0x80
#define NEIGHBOR_FLAGS_NONE       0x00

typedef enum { LINK_ADD, LINK_DELETE } link_action_t;
typedef enum { ADDR_ADD, ADDR_DELETE } addr_action_t;
typedef enum { ROUTE_ADD, ROUTE_DELETE } route_action_t;
typedef enum { NEIGHBOR_ADD, NEIGHBOR_DELETE } neighbor_action_t;

typedef enum {
	LINK_UNKNOWN,
	LINK_NOTPRESENT,
	LINK_DOWN,
	LINK_LOWERLAYERDOWN,
	LINK_TESTING,
	LINK_DORMANT,
	LINK_UP
} oper_state_t;

struct netl_handle {
	int fd;
	uint8_t closing;
	struct sockaddr_nl local;
	struct netl_callbacks {
		int (*init) (void *args);
		int (*end) (void *args);
		int (*link) (struct ifinfomsg *, link_action_t action, int ifid,
					 int master_ifid, struct ether_addr *, int mtu,
					 const char *name, oper_state_t state);
		int (*addr4) (addr_action_t action, __s32 port_id,
					  struct in_addr * addr, __u8 prefixlen);
		int (*addr6) (addr_action_t action, __s32 port_id,
					  struct in6_addr * addr, __u8 prefixlen);
		int (*route4) (struct rtmsg * route, route_action_t action,
					   struct in_addr * addr, uint8_t len,
					   struct in_addr * nexthop, void *args);
		int (*route6) (struct rtmsg * route, route_action_t action,
					   struct in6_addr * addr, uint8_t len,
					   struct in6_addr * nexthop, void *args);
		int (*neighbor4) (struct ndmsg * neighbor,
						  neighbor_action_t action, __s32 port_id,
						  struct in_addr * addr,
						  struct ether_addr * lladdr, __u8 flags,
						  void *args);
		int (*neighbor6) (struct ndmsg * neighbor,
						  neighbor_action_t action, __s32 port_id,
						  struct in6_addr * addr,
						  struct ether_addr * lladdr, __u8 flags,
						  void *args);
	} cb;
};

int netl_close(struct netl_handle *);

int netl_listen(struct netl_handle *, void *args);
struct netl_handle *netl_create(void);
int netl_free(struct netl_handle *);
