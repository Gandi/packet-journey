#include "common.h"

typedef struct rte_lpm lookup_struct_t;
typedef struct rte_lpm6 lookup6_struct_t;

extern lookup_struct_t *ipv4_l3fwd_lookup_struct[NB_SOCKETS];
