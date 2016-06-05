#ifndef __PKTJ_COMMON_H
#define __PKTJ_COMMON_H

#define USE_RTE_FUNCS 1

#ifndef USE_RTE_FUNCS
#define pktj_init(argc, argv) \
	(void)(argc);         \
	(void)(argv)
#define pktj_malloc(str, len, align, socket) malloc(len)
#define pktj_calloc(str, nb_item, item_len, align, socket) \
	calloc((nb_item), (item_len))
#define pktj_free(ptr) free(ptr)
#define pktj_unused(x) x __attribute__((unused))
#define SOCKET_ID_ANY -1
#else
#include <rte_common.h>
#include <rte_malloc.h>
#define pktj_init(argc, argv) rte_eal_init(argc, argv)
#define pktj_malloc(str, len, flag, socket) \
	rte_malloc_socket(str, (len), flag, socket)
#define pktj_calloc(str, nb_item, item_len, flag, socket) \
	rte_calloc_socket(str, (nb_item), (item_len), flag, socket)
#define pktj_free(ptr) rte_free(ptr)
#define pktj_unused(x) __rte_unused x
#endif

#endif
