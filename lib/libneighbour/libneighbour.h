#include <rte_ether.h>
#include <netinet/in.h>
#include <linux/types.h>

#ifdef LPM6_16BIT
#define NEI_NUM_ENTRIES (1 << 16)
#else
#define NEI_NUM_ENTRIES (1 << 8)
#endif

struct nei_entry {
	struct ether_addr nexthop_hwaddr;	/* 6 bytes */
	struct ether_addr port_addr;	/* 6 bytes */

	uint8_t in_use;
	uint8_t valid;

//same as NUD_* defines from linux/neighbour.h, like NUD_DELAY
	uint8_t state;

#define NEI_ACTION_FWD      0x01
#define NEI_ACTION_DROP     0x02
#define NEI_ACTION_KNI      0x03
	uint8_t action;

	int16_t vlan_id;
	uint16_t port_id;

	int32_t refcnt;
};								//24bytes

//must be 16bytes aligned
struct nei_entry4 {
	struct nei_entry neighbor;

	struct in_addr addr;
	uint8_t pad[4];
};

struct nei_entry6 {
	struct nei_entry neighbor;

	struct in6_addr addr;		//16bytes
	uint8_t pad[8];
};

struct nei_table {
	union {
		struct nei_entry4 t4[NEI_NUM_ENTRIES];
		struct nei_entry6 t6[NEI_NUM_ENTRIES];
	} entries;
};

int neighbor4_lookup_nexthop(struct nei_table *, struct in_addr *nexthop,
							 uint16_t * nexthop_id, uint16_t exclude_id);
int neighbor4_add_nexthop(struct nei_table *, struct in_addr *nexthop,
						  uint16_t * nexthop_id, uint8_t action);
int neighbor4_set_nexthop(struct nei_table *, struct in_addr *nexthop,
						  uint16_t nexthop_id, uint8_t action);
int neighbor4_refcount_incr(struct nei_table *, uint16_t nexthop_id);
int neighbor4_refcount_decr(struct nei_table *, uint16_t nexthop_id);
int neighbor4_set_lladdr_port(struct nei_table *, uint16_t nexthop_id,
							  struct ether_addr *port_addr,
							  struct ether_addr *lladdr, int16_t port_id,
							  int16_t vlan_id);
int neighbor4_copy_lladdr_port(struct nei_table *t, uint16_t src_nexthop_id, uint16_t dst_nexthop_id);
int neighbor4_set_state(struct nei_table *, uint16_t nexthop_id, uint8_t flags);
int neighbor4_set_action(struct nei_table *t, uint16_t nexthop_id, uint8_t action);
int neighbor4_set_port(struct nei_table *t, uint16_t nexthop_id,
					   int32_t port_id);
int neighbor4_delete(struct nei_table *, uint16_t nexthop_id);

int neighbor6_lookup_nexthop(struct nei_table *, struct in6_addr *nexthop,
							 uint16_t * nexthop_id, uint16_t exclude_id);
int neighbor6_add_nexthop(struct nei_table *, struct in6_addr *nexthop,
						  uint16_t *nexthop_id, uint8_t action);
int neighbor6_set_nexthop(struct nei_table *, struct in6_addr *nexthop,
						  uint16_t nexthop_id, uint8_t action);
int neighbor6_refcount_incr(struct nei_table *, uint16_t nexthop_id);
int neighbor6_refcount_decr(struct nei_table *, uint16_t nexthop_id);
int neighbor6_set_lladdr_port(struct nei_table *, uint16_t nexthop_id,
							  struct ether_addr *port_addr,
							  struct ether_addr *lladdr, int16_t port_id,
							  int16_t vlan_id);
int neighbor6_copy_lladdr_port(struct nei_table *t, uint16_t src_nexthop_id, uint16_t dst_nexthop_id);
int neighbor6_set_state(struct nei_table *, uint16_t nexthop_id, uint8_t flags);
int neighbor6_set_action(struct nei_table *, uint16_t nexthop_id, uint8_t action);
int neighbor6_set_port(struct nei_table *t, uint16_t nexthop_id,
					   int32_t port_id);
int neighbor6_delete(struct nei_table *, uint16_t nexthop_id);


struct nei_table *nei_create(int socketid);
void nei_free(struct nei_table *nei);
