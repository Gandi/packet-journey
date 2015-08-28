#ifndef __DPDPK_ROUTING_H
#define __DPDPK_ROUTING_H

typedef struct rte_lpm lookup_struct_t;
typedef struct rte_lpm6 lookup6_struct_t;
typedef struct nei_table neighbor_struct_t;

extern lookup_struct_t *ipv4_rdpdk_lookup_struct[NB_SOCKETS];
extern lookup6_struct_t *ipv6_rdpdk_lookup_struct[NB_SOCKETS];
extern neighbor_struct_t *neighbor4_struct[NB_SOCKETS];
extern neighbor_struct_t *neighbor6_struct[NB_SOCKETS];
extern struct rte_eth_conf port_conf;

extern struct rte_eth_conf port_conf;
uint8_t get_port_n_rx_queues(uint8_t port);
#endif
