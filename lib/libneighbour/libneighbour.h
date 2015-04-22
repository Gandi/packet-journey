#include <rte_ether.h>
#include <netinet/in.h>
#include <linux/types.h>

#define NEI_NUM_ENTRIES 256


struct nei_entry4 {
	uint8_t in_use;
	uint8_t valid;
	//uint8_t output_port;

	struct in_addr addr;
	struct ether_addr nexthop_hwaddr;

	//unsigned long inserted;
	//unsigned long delayed;
	//uint8_t state;
	__u8 state;
#define NEI_STATE_REACHABLE 0x01
#define NEI_STATE_STALE     0x02
#define NEI_STATE_DELAY     0x03
	__s32 port_id;
	uint8_t action;
#define NEI_ACTION_FWD      0x01
#define NEI_ACTION_DROP     0x02
#define NEI_ACTION_KNI      0x03
	int refcnt;
};

struct nei_table {
	struct nei_entry4 entries4[NEI_NUM_ENTRIES];
};

int
neighbor4_lookup_nexthop(struct nei_table *, struct in_addr *, uint8_t *);
int neighbor4_add_nexthop(struct nei_table *, struct in_addr *nexthop,
						  uint8_t * nexthop_id, uint8_t action);
int neighbor4_refcount_incr(struct nei_table *, uint8_t);
int neighbor4_refcount_decr(struct nei_table *, uint8_t);

int
neighbor4_set_lladdr_port(struct nei_table *, uint8_t, struct ether_addr *,
						  __s32 port_id);
int neighbor4_set_state(struct nei_table *, uint8_t, __u8 flags);

//if (neighbor4_refcount(neighbor, nexthop_id) > 0)
// neighbor4_flag_invalid(neighbor, nexthop_id);
//else
// neighbor4_free(neighbor, nexthop_id)
void neighbor4_delete(struct nei_table *, uint8_t);
int neighbor4_set_port(struct nei_table *t, uint8_t nexthop_id,
					   __s32 port_id);


struct nei_table *nei_create(int socketid);

void nei_free(struct nei_table *nei);
