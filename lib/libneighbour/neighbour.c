#include <string.h>

#include "rdpdk_common.h"
#include "libneighbour.h"


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
		entry = &(t->entries4[i]);
		if (entry->in_use && entry->addr.s_addr == nexthop->s_addr) {
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
		entry = &(t->entries4[i]);
		if (entry->in_use == 0) {
			*nexthop_id = i;

			entry->in_use = 1;
			entry->valid = 0;
            entry->action = action;
			entry->addr.s_addr = nexthop->s_addr;
			memset(&entry->nexthop_hwaddr.addr_bytes, 0,
				   sizeof(entry->nexthop_hwaddr.addr_bytes));

			return 0;
		}
	}

	return -1;
}

int neighbor4_refcount_incr(struct nei_table *t, uint8_t nexthop_id)
{
	struct nei_entry4 *entry;

	entry = &(t->entries4[nexthop_id]);

	if (entry->in_use == 0)
		return -1;

	return ++entry->refcnt;
}

int neighbor4_refcount_decr(struct nei_table *t, uint8_t nexthop_id)
{
	struct nei_entry4 *entry;

	entry = &(t->entries4[nexthop_id]);

	if (entry->in_use == 0)
		return -1;

	if (entry->refcnt == 0)
		return -2;

	return --entry->refcnt;
}

int
neighbor4_set_lladdr_port(struct nei_table *t, uint8_t nexthop_id,
						  struct ether_addr *lladdr, __s32 port_id)
{
	struct nei_entry4 *entry;

	entry = &t->entries4[nexthop_id];

	if (entry->in_use == 0)
		return -1;

	entry->valid = 1;

	memcpy(&entry->nexthop_hwaddr, lladdr, sizeof(*lladdr));
	entry->port_id = port_id;
	return 0;
}

int
neighbor4_set_state(struct nei_table *t, uint8_t nexthop_id, __u8 flags)
{
	struct nei_entry4 *entry;

	entry = &t->entries4[nexthop_id];

	if (entry->in_use == 0)
		return -1;

	entry->state = flags;
	return 0;
}

int
neighbor4_set_port(struct nei_table *t, uint8_t nexthop_id, __s32 port_id)
{
	struct nei_entry4 *entry;

	entry = &t->entries4[nexthop_id];

	if (entry->in_use == 0)
		return -1;

	entry->port_id = port_id;
	return 0;
}

void neighbor4_delete(struct nei_table *t, uint8_t nexthop_id)
{
	struct nei_entry4 *entry;

	entry = &t->entries4[nexthop_id];

	if (entry->in_use == 0)
		return;

	if (entry->refcnt > 0) {
		entry->valid = 0;
	} else {
		neighbor4_free(entry);
	}

	return;
}

struct nei_table *nei_create(int socketid)
{
	struct nei_table *nei_table;

	nei_table =
		rdpdk_malloc("nei_table", sizeof(struct nei_table), 0, socketid);
	if (nei_table == NULL)
		return NULL;

	memset(nei_table->entries4, 0, sizeof(nei_table->entries4));

	return nei_table;
}

void nei_free(struct nei_table *table)
{
	if (table != NULL)
		rdpdk_free(table);
}
