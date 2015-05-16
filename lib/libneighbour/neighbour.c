#include <string.h>

#include "rdpdk_common.h"
#include "libneighbour.h"

inline static void neighbor6_free(struct nei_entry6 *e)
{
	memset(e, 0, sizeof(*e));
}

int
neighbor6_lookup_nexthop(struct nei_table *t, struct in6_addr *nexthop,
						 uint8_t * nexthop_id)
{
	int i;
	struct nei_entry6 *entry;

	for (i = 0; i < NEI_NUM_ENTRIES; i++) {
		entry = &(t->entries.t6[i]);
		if (entry->neighbor.in_use
			&& entry->addr.s6_addr == nexthop->s6_addr) {
			*nexthop_id = i;
			return 0;
		}
	}

	return -1;
}

int
neighbor6_add_nexthop(struct nei_table *t, struct in6_addr *nexthop,
					  uint8_t * nexthop_id, uint8_t action)
{
	int i;
	struct nei_entry6 *entry;

	for (i = 0; i < NEI_NUM_ENTRIES; i++) {
		entry = &(t->entries.t6[i]);
		if (entry->neighbor.in_use == 0) {
			*nexthop_id = i;

			entry->neighbor.in_use = 1;
			entry->neighbor.valid = 0;
			entry->neighbor.action = action;
			memcpy(entry->addr.s6_addr, nexthop->s6_addr,
				   sizeof(*nexthop->s6_addr));
			memset(&entry->neighbor.nexthop_hwaddr.addr_bytes, 0,
				   sizeof(entry->neighbor.nexthop_hwaddr.addr_bytes));

			return 0;
		}
	}

	return -1;
}

int neighbor6_refcount_incr(struct nei_table *t, uint8_t nexthop_id)
{
	struct nei_entry6 *entry;

	entry = &(t->entries.t6[nexthop_id]);

	if (entry->neighbor.in_use == 0)
		return -1;

	return ++entry->neighbor.refcnt;
}

int neighbor6_refcount_decr(struct nei_table *t, uint8_t nexthop_id)
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
neighbor6_set_lladdr_port(struct nei_table *t, uint8_t nexthop_id,
						  struct ether_addr *lladdr, int32_t port_id)
{
	struct nei_entry6 *entry;

	entry = &t->entries.t6[nexthop_id];

	if (entry->neighbor.in_use == 0)
		return -1;

	entry->neighbor.valid = 1;

	memcpy(&entry->neighbor.nexthop_hwaddr, lladdr, sizeof(*lladdr));
	entry->neighbor.port_id = port_id;
	return 0;
}

int
neighbor6_set_state(struct nei_table *t, uint8_t nexthop_id, uint8_t flags)
{
	struct nei_entry6 *entry;

	entry = &t->entries.t6[nexthop_id];

	if (entry->neighbor.in_use == 0)
		return -1;

	entry->neighbor.state = flags;
	return 0;
}

int
neighbor6_set_port(struct nei_table *t, uint8_t nexthop_id,
				   int32_t port_id)
{
	struct nei_entry6 *entry;

	entry = &t->entries.t6[nexthop_id];

	if (entry->neighbor.in_use == 0)
		return -1;

	entry->neighbor.port_id = port_id;
	return 0;
}

void neighbor6_delete(struct nei_table *t, uint8_t nexthop_id)
{
	struct nei_entry6 *entry;

	entry = &t->entries.t6[nexthop_id];

	if (entry->neighbor.in_use == 0)
		return;

	if (entry->neighbor.refcnt > 0) {
		entry->neighbor.valid = 0;
	} else {
		neighbor6_free(entry);
	}

	return;
}


inline static void neighbor4_free(struct nei_entry4 *e)
{
	memset(e, 0, sizeof(*e));
}

int
neighbor4_lookup_nexthop(struct nei_table *t, struct in_addr *nexthop,
						 uint8_t * nexthop_id)
{
	int i;
	struct nei_entry4 *entry;

	for (i = 0; i < NEI_NUM_ENTRIES; i++) {
		entry = &(t->entries.t4[i]);
		if (entry->neighbor.in_use
			&& entry->addr.s_addr == nexthop->s_addr) {
			*nexthop_id = i;
			return 0;
		}
	}

	return -1;
}

int
neighbor4_add_nexthop(struct nei_table *t, struct in_addr *nexthop,
					  uint8_t * nexthop_id, uint8_t action)
{
	int i;
	struct nei_entry4 *entry;

	for (i = 0; i < NEI_NUM_ENTRIES; i++) {
		entry = &(t->entries.t4[i]);
		if (entry->neighbor.in_use == 0) {
			*nexthop_id = i;

			entry->neighbor.in_use = 1;
			entry->neighbor.valid = 0;
			entry->neighbor.action = action;
			entry->addr.s_addr = nexthop->s_addr;
			memset(&entry->neighbor.nexthop_hwaddr.addr_bytes, 0,
				   sizeof(entry->neighbor.nexthop_hwaddr.addr_bytes));

			return 0;
		}
	}

	return -1;
}

int neighbor4_refcount_incr(struct nei_table *t, uint8_t nexthop_id)
{
	struct nei_entry4 *entry;

	entry = &(t->entries.t4[nexthop_id]);

	if (entry->neighbor.in_use == 0)
		return -1;

	return ++entry->neighbor.refcnt;
}

int neighbor4_refcount_decr(struct nei_table *t, uint8_t nexthop_id)
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
neighbor4_set_lladdr_port(struct nei_table *t, uint8_t nexthop_id,
						  struct ether_addr *lladdr, int32_t port_id)
{
	struct nei_entry4 *entry;

	entry = &t->entries.t4[nexthop_id];

	if (entry->neighbor.in_use == 0)
		return -1;

	entry->neighbor.valid = 1;

	memcpy(&entry->neighbor.nexthop_hwaddr, lladdr, sizeof(*lladdr));
	entry->neighbor.port_id = port_id;
	return 0;
}

int
neighbor4_set_state(struct nei_table *t, uint8_t nexthop_id, uint8_t flags)
{
	struct nei_entry4 *entry;

	entry = &t->entries.t4[nexthop_id];

	if (entry->neighbor.in_use == 0)
		return -1;

	entry->neighbor.state = flags;
	return 0;
}

int
neighbor4_set_port(struct nei_table *t, uint8_t nexthop_id,
				   int32_t port_id)
{
	struct nei_entry4 *entry;

	entry = &t->entries.t4[nexthop_id];

	if (entry->neighbor.in_use == 0)
		return -1;

	entry->neighbor.port_id = port_id;
	return 0;
}

void neighbor4_delete(struct nei_table *t, uint8_t nexthop_id)
{
	struct nei_entry4 *entry;

	entry = &t->entries.t4[nexthop_id];

	if (entry->neighbor.in_use == 0)
		return;

	if (entry->neighbor.refcnt > 0) {
		entry->neighbor.valid = 0;
	} else {
		neighbor4_free(entry);
	}

	return;
}

struct nei_table *nei_create(int socketid)
{
	struct nei_table *nei_table;

	nei_table =
		rdpdk_malloc("nei_table", sizeof(struct nei_table), 64, socketid);
	if (nei_table == NULL)
		return NULL;

	memset(nei_table->entries.t6, 0, sizeof(nei_table->entries.t6));

	return nei_table;
}

void nei_free(struct nei_table *table)
{
	if (table != NULL)
		rdpdk_free(table);
}
