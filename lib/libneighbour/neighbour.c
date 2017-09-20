#include <string.h>

#include "pktj_common.h"
#include "libneighbour.h"

inline static void neighbor6_free(struct nei_entry6 *e)
{
	memset(e, 0, sizeof(*e));
}

int
neighbor6_lookup_nexthop(struct nei_table *t, struct in6_addr *nexthop,
						 uint16_t *nexthop_id, uint16_t exclude_id)
{
	int i;
	struct nei_entry6 *entry;

	for (i = 0; i < NEI_NUM_ENTRIES; i++) {
		entry = &(t->entries.t6[i]);
		if (i != exclude_id && entry->neighbor.in_use
			&& !memcmp(entry->addr.s6_addr, nexthop->s6_addr,
					   sizeof(nexthop->s6_addr))) {
			*nexthop_id = i;
			return 0;
		}
	}

	return -1;
}

int
neighbor6_set_nexthop(struct nei_table *t, struct in6_addr *nexthop,
					  uint16_t nexthop_id, uint8_t action)
{
	struct nei_entry6 *entry;

	entry = &(t->entries.t6[nexthop_id]);

	entry->neighbor.in_use = 1;
	entry->neighbor.valid = 0;
	entry->neighbor.action = action;
	memcpy(entry->addr.s6_addr, nexthop->s6_addr,
		sizeof(nexthop->s6_addr));
	memset(entry->neighbor.nexthop_hwaddr.addr_bytes, 0,
		sizeof(entry->neighbor.nexthop_hwaddr.addr_bytes));

	return 0;
}

int
neighbor6_add_nexthop(struct nei_table *t, struct in6_addr *nexthop,
					  uint16_t * nexthop_id, uint8_t action)
{
	int i;
	struct nei_entry6 *entry;

	for (i = 0; i < NEI_NUM_ENTRIES; i++) {
		entry = &(t->entries.t6[i]);
		if (entry->neighbor.in_use == 0) {
			*nexthop_id = i;

			return neighbor6_set_nexthop(t, nexthop, i, action);
		}
	}

	return -1;
}

int neighbor6_refcount_incr(struct nei_table *t, uint16_t nexthop_id)
{
	struct nei_entry6 *entry;

	entry = &(t->entries.t6[nexthop_id]);

	if (entry->neighbor.in_use == 0)
		return -1;

	return ++entry->neighbor.refcnt;
}

int neighbor6_refcount_decr(struct nei_table *t, uint16_t nexthop_id)
{
	struct nei_entry6 *entry;

	entry = &(t->entries.t6[nexthop_id]);

	if (entry->neighbor.in_use == 0)
		return -1;

	if (entry->neighbor.refcnt == 0)
		return -2;

	return --entry->neighbor.refcnt;
}

int
neighbor6_set_lladdr_port(struct nei_table *t, uint16_t nexthop_id,
						  struct ether_addr *port_addr,
						  struct ether_addr *lladdr, int16_t port_id,
						  int16_t vlan_id)
{
	struct nei_entry6 *entry;

	entry = &t->entries.t6[nexthop_id];

	if (entry->neighbor.in_use == 0)
		return -1;

	entry->neighbor.valid = 1;

	memcpy(&entry->neighbor.port_addr, port_addr, sizeof(*port_addr));
	memcpy(&entry->neighbor.nexthop_hwaddr, lladdr, sizeof(*lladdr));
	entry->neighbor.port_id = port_id;
	entry->neighbor.vlan_id = vlan_id;
	return 0;
}

int neighbor6_copy_lladdr_port(struct nei_table *t, uint16_t src_nexthop_id, uint16_t dst_nexthop_id)
{
	struct nei_entry6 *src_entry, *dst_entry;

	src_entry = &t->entries.t6[src_nexthop_id];
	dst_entry = &t->entries.t6[dst_nexthop_id];

	if (src_entry->neighbor.in_use == 0)
		return -1;

	dst_entry->neighbor.valid = src_entry->neighbor.valid;

	memcpy(&dst_entry->neighbor.port_addr, &src_entry->neighbor.port_addr, sizeof(struct ether_addr));
	memcpy(&dst_entry->neighbor.nexthop_hwaddr, &src_entry->neighbor.nexthop_hwaddr, sizeof(struct ether_addr));
	dst_entry->neighbor.port_id = src_entry->neighbor.port_id;
	dst_entry->neighbor.vlan_id = src_entry->neighbor.vlan_id;

	return 0;
}

int
neighbor6_set_state(struct nei_table *t, uint16_t nexthop_id, uint8_t flags)
{
	struct nei_entry6 *entry;

	entry = &t->entries.t6[nexthop_id];

	if (entry->neighbor.in_use == 0)
		return -1;

	entry->neighbor.state = flags;
	return 0;
}

int
neighbor6_set_action(struct nei_table *t, uint16_t nexthop_id, uint8_t action)
{
	struct nei_entry6 *entry;

	entry = &t->entries.t6[nexthop_id];

	if (entry->neighbor.in_use == 0)
		return -1;

	entry->neighbor.action = action;
	return 0;
}

int
neighbor6_set_port(struct nei_table *t, uint16_t nexthop_id,
				   int32_t port_id)
{
	struct nei_entry6 *entry;

	entry = &t->entries.t6[nexthop_id];

	if (entry->neighbor.in_use == 0)
		return -1;

	entry->neighbor.port_id = port_id;
	return 0;
}

int neighbor6_delete(struct nei_table *t, uint16_t nexthop_id)
{
	struct nei_entry6 *entry;

	entry = &t->entries.t6[nexthop_id];

	if (entry->neighbor.in_use == 0)
		return 1;

	if (entry->neighbor.refcnt > 0) {
		entry->neighbor.valid = 0;
	} else {
		neighbor6_free(entry);
	}

    //FIXME not thread safe, need locking
	return entry->neighbor.refcnt;
}


inline static void neighbor4_free(struct nei_entry4 *e)
{
	memset(e, 0, sizeof(*e));
}

int
neighbor4_lookup_nexthop(struct nei_table *t, struct in_addr *nexthop,
						 uint16_t *nexthop_id, uint16_t exclude_id)
{
	int i;
	struct nei_entry4 *entry;

	for (i = 0; i < NEI_NUM_ENTRIES; i++) {
		entry = &(t->entries.t4[i]);
		if (i != exclude_id && entry->neighbor.in_use
			&& entry->addr.s_addr == nexthop->s_addr) {
			*nexthop_id = i;
			return 0;
		}
	}

	return -1;
}

int
neighbor4_set_nexthop(struct nei_table *t, struct in_addr *nexthop,
					  uint16_t nexthop_id, uint8_t action)
{
	struct nei_entry4 *entry;

	entry = &(t->entries.t4[nexthop_id]);

	entry->neighbor.in_use = 1;
	entry->neighbor.valid = 0;
	entry->neighbor.action = action;
	entry->addr.s_addr = nexthop->s_addr;
	memset(&entry->neighbor.nexthop_hwaddr.addr_bytes, 0,
		sizeof(entry->neighbor.nexthop_hwaddr.addr_bytes));

	return 0;
}

int
neighbor4_add_nexthop(struct nei_table *t, struct in_addr *nexthop,
					  uint16_t *nexthop_id, uint8_t action)
{
	int i;
	struct nei_entry4 *entry;

	for (i = 0; i < NEI_NUM_ENTRIES; i++) {
		entry = &(t->entries.t4[i]);
		if (entry->neighbor.in_use == 0) {
			*nexthop_id = i;

			return neighbor4_set_nexthop(t, nexthop, i, action);
		}
	}

	return -1;
}

int neighbor4_refcount_incr(struct nei_table *t, uint16_t nexthop_id)
{
	struct nei_entry4 *entry;

	entry = &(t->entries.t4[nexthop_id]);

	if (entry->neighbor.in_use == 0)
		return -1;

	return ++entry->neighbor.refcnt;
}

int neighbor4_refcount_decr(struct nei_table *t, uint16_t nexthop_id)
{
	struct nei_entry4 *entry;

	entry = &(t->entries.t4[nexthop_id]);

	if (entry->neighbor.in_use == 0)
		return -1;

	if (entry->neighbor.refcnt == 0)
		return -2;

	return --entry->neighbor.refcnt;
}

int
neighbor4_set_lladdr_port(struct nei_table *t, uint16_t nexthop_id,
						  struct ether_addr *port_addr,
						  struct ether_addr *lladdr, int16_t port_id,
						  int16_t vlan_id)
{
	struct nei_entry4 *entry;

	entry = &t->entries.t4[nexthop_id];

	if (entry->neighbor.in_use == 0)
		return -1;

	entry->neighbor.valid = 1;

	memcpy(&entry->neighbor.port_addr, port_addr, sizeof(*port_addr));
	memcpy(&entry->neighbor.nexthop_hwaddr, lladdr, sizeof(*lladdr));
	entry->neighbor.port_id = port_id;
	entry->neighbor.vlan_id = vlan_id;
	return 0;
}

int neighbor4_copy_lladdr_port(struct nei_table *t, uint16_t src_nexthop_id, uint16_t dst_nexthop_id)
{
	struct nei_entry4 *src_entry, *dst_entry;

	src_entry = &t->entries.t4[src_nexthop_id];
	dst_entry = &t->entries.t4[dst_nexthop_id];

	if (src_entry->neighbor.in_use == 0)
		return -1;

	dst_entry->neighbor.valid = src_entry->neighbor.valid;

	memcpy(&dst_entry->neighbor.port_addr, &src_entry->neighbor.port_addr, sizeof(struct ether_addr));
	memcpy(&dst_entry->neighbor.nexthop_hwaddr, &src_entry->neighbor.nexthop_hwaddr, sizeof(struct ether_addr));
	dst_entry->neighbor.port_id = src_entry->neighbor.port_id;
	dst_entry->neighbor.vlan_id = src_entry->neighbor.vlan_id;

	return 0;
}

int
neighbor4_set_state(struct nei_table *t, uint16_t nexthop_id, uint8_t flags)
{
	struct nei_entry4 *entry;

	entry = &t->entries.t4[nexthop_id];

	if (entry->neighbor.in_use == 0)
		return -1;

	entry->neighbor.state = flags;
	return 0;
}

int
neighbor4_set_action(struct nei_table *t, uint16_t nexthop_id, uint8_t action)
{
	struct nei_entry4 *entry;

	entry = &t->entries.t4[nexthop_id];

	if (entry->neighbor.in_use == 0)
		return -1;

	entry->neighbor.action = action;
	return 0;
}

int
neighbor4_set_port(struct nei_table *t, uint16_t nexthop_id,
				   int32_t port_id)
{
	struct nei_entry4 *entry;

	entry = &t->entries.t4[nexthop_id];

	if (entry->neighbor.in_use == 0)
		return -1;

	entry->neighbor.port_id = port_id;
	return 0;
}

int neighbor4_delete(struct nei_table *t, uint16_t nexthop_id)
{
	struct nei_entry4 *entry;

	entry = &t->entries.t4[nexthop_id];

	if (entry->neighbor.in_use == 0)
		return 1;

	if (entry->neighbor.refcnt > 0) {
		entry->neighbor.valid = 0;
	} else {
		neighbor4_free(entry);
	}

    //FIXME not thread safe, need locking
	return entry->neighbor.refcnt;
}

struct nei_table *nei_create(int socketid)
{
	struct nei_table *nei_table;

	nei_table =
		pktj_calloc("nei_table", 1, sizeof(struct nei_table), 64,
					 socketid);

	return nei_table;
}

void nei_free(struct nei_table *table)
{
	if (table != NULL)
		pktj_free(table);
}
