#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>


/** Tbl entry structure. It is the same for both tbl24 and tbl8 */
struct rte_lpm6_tbl_entry {
		uint32_t next_hop:	  21;  /**< Next hop / next table to be checked. */
		uint32_t depth  :8;	  /**< Rule depth. */
		/* Flags. */
		uint32_t valid	 :1;   /**< Validation flag. */
		uint32_t valid_group :1; /**< Group validation flag. */
		uint32_t ext_entry :1;   /**< External entry. */
};

struct rte_lpm_tbl_entry {
	uint32_t next_hop    :23;
	uint32_t ext_entry   :1; /**XXX: dirty hack, not really present */
	uint32_t valid       :1;   /**< Validation flag. */
	uint32_t valid_group :1;
	uint32_t depth       :6; /**< Rule depth. */
};

void
print_usage()
{
	fprintf(stdout, "tbl_dumper tbl_dump_file {nexthop|valid|valid_group|ext_entry|depth|dump|dumprange|nonfree} value");
}

void print_tbl(struct rte_lpm_tbl_entry tbl, uint32_t tbl_idx)
{
		fprintf(stdout, "idx %d, tbl %d, next_hop: %d, depth %d, valid: %d, valid_group: %d, ext_entry %d\n",
			tbl_idx, tbl_idx / 256, tbl.next_hop, tbl.depth, tbl.valid, tbl.valid_group, tbl.ext_entry);
}

int main(int argc, const char *argv[])
{
	int fd;
	int opt_idx;
	int checked_value;
	struct stat sb;
	size_t tbl_size;
	uint32_t tbl_idx;
	struct rte_lpm_tbl_entry *tbl;
	char *opts_str[] = {
		"nexthop",
		"valid",
		"valid_group",
		"ext_entry",
		"depth",
		"dump",
		"dumprange",
		"nonfree",
		NULL
		};

	if (argc < 4) {
		print_usage();
		return EXIT_FAILURE;
	}

	for (opt_idx = 0; opts_str[opt_idx] != NULL; ++opt_idx) {
		if (strcmp(argv[2], opts_str[opt_idx]) == 0) {
			break;
		}
	}
	if (opts_str[opt_idx] == NULL) {
		fprintf(stderr, "invalid filter\n");
		print_usage();
		return EXIT_FAILURE;
	}

	checked_value = atoi(argv[3]);

	fd = open(argv[1], O_RDONLY);
	if (fd < 0) {
		perror("open:");
		return EXIT_FAILURE;
	}

	if (fstat(fd, &sb) < 0) {
		perror("fstat:");
		return EXIT_FAILURE;
	}

	tbl_size = sb.st_size;

	tbl = mmap(NULL, tbl_size, PROT_READ, MAP_PRIVATE, fd, 0);

	for (tbl_idx = 0; tbl_idx < tbl_size / sizeof(*tbl); ++tbl_idx) {
		switch (opt_idx) {
			case 0:
				if (tbl[tbl_idx].next_hop == checked_value)
					print_tbl(tbl[tbl_idx], tbl_idx);
				break;
			case 1:
				if (tbl[tbl_idx].valid == checked_value)
					print_tbl(tbl[tbl_idx], tbl_idx);
				break;
			case 2:
				if (tbl[tbl_idx].valid_group == checked_value)
					print_tbl(tbl[tbl_idx], tbl_idx);
				break;
			case 3:
				if (tbl[tbl_idx].ext_entry == checked_value)
					print_tbl(tbl[tbl_idx], tbl_idx);
				break;
			case 4:
				if (tbl[tbl_idx].depth == checked_value)
					print_tbl(tbl[tbl_idx], tbl_idx);
				break;
			case 5:
				if (tbl_idx == checked_value)
					print_tbl(tbl[tbl_idx], tbl_idx);
				break;
			case 6:
				if (tbl_idx / 256 == checked_value)
					print_tbl(tbl[tbl_idx], tbl_idx);
				break;
			case 7:
				if (*((uint32_t*)&tbl[tbl_idx]) != 0)
					print_tbl(tbl[tbl_idx], tbl_idx);
				break;
		}
	}
	
	return EXIT_SUCCESS;
}
