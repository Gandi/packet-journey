#include "rdpdk_common.h"
#include <libneighbour.h>

#define IP4(a,b,c,d) \
	(a & 0xff) +\
	((b & 0xff) << 8) +\
	((c & 0xff) << 16) +\
	((d & 0xff) << 24)

#define TEST(predicate, message)\
	if(!(predicate)) {\
		fprintf(stderr, "%s:%d " message "\n", __FILE__, __LINE__);;\
		exit(1);\
	}

int main(void)
{
	int s;
	struct nei_table *t;
	struct in_addr nexthop;
	uint8_t id;

	char *argv[7] = { "test", "-l", "0", "-n", "1", "--log-level", "0" };

	rdpdk_init(7, argv);

	t = nei_create(SOCKET_ID_ANY);
	if (t == NULL) {
		perror("Failed to initialize neighbour table");
		exit(1);
	}
	// Populate table
	nexthop.s_addr = IP4(1, 2, 3, 4);
	s = neighbor4_add_nexthop(t, &nexthop, &id, NEI_ACTION_FWD);
	TEST(s == 0, "neighbor add should succeed")

		TEST(id == 0, "first entry is expected to be at index 0")
		TEST(t->entries.t4[id].neighbor.state == 0,
			 "Flags should be zeroed upon insert")
		TEST(t->entries.t4[id].neighbor.in_use == 1,
			 "Entry should be flagged in_use after insertion")

		TEST(t->entries.t4[1].neighbor.in_use == 0 ||
			 t->entries.t4[NEI_NUM_ENTRIES - 1].neighbor.in_use == 0,
			 "Unknown entries should be invalid")

		nexthop.s_addr = IP4(1, 2, 3, 5);
	s = neighbor4_add_nexthop(t, &nexthop, &id, NEI_ACTION_FWD);
	TEST(s == 0, "neighbor add should succeed")
		TEST(id == 1, "entry is expected to be at index 1")

		neighbor4_delete(t, 0);
	TEST(t->entries.t4[0].neighbor.in_use == 0,
		 "First entry has been deleted, it should not be in_use anymore")

		nexthop.s_addr = IP4(1, 2, 3, 6);
	s = neighbor4_add_nexthop(t, &nexthop, &id, NEI_ACTION_FWD);
	TEST(s == 0, "neighbor add should succeed")
		TEST(id == 0,
			 "first entry was empty, new entry should take index 0")
		TEST(t->entries.t4[0].neighbor.in_use == 1,
			 "First entry should be in use again")
#if 0
	__s32 port_id = 1;
	struct ether_addr lladdr = {
		.addr_bytes = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66}
	};
#endif



	printf("EOF\n");
	return 0;
}
