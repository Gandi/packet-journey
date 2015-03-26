#ifndef __RDPDK_COMMON_H
#define __RDPDK_COMMON_H

#ifndef USE_RTE_FUNCS
# define rdpdk_init(argc, argv) (void*)(argc);(void*)(argv)
# define rdpdk_malloc(str, len, flag) malloc(len) 
# define rdpdk_free(ptr) free(ptr)
# define rdpdk_unused(x) x __attribute__((unused))
#else
# include <rte_common.h>
# include <rte_malloc.h>
# define rdpdk_init(argc, argv) rte_eal_init(argc, argv)
# define rdpdk_malloc(str, len, flag) rte_malloc(str, len, flag) 
# define rdpdk_free(ptr) rte_free(ptr)
# define rdpdk_unused(x) __rte_unused x
#endif

#endif
