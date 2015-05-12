#ifndef __RDPDK_APP_CONTROL_H
#define __RDPDK_APP_CONTROL_H

void *control_init(unsigned nb_socket);
void *control_main(void *argv);

int control_callback_setup(const char *cb);
int control_add_ipv4_local_entry(struct in_addr *nexthop,
								 struct in_addr *saddr, uint8_t depth,
								 uint32_t port_id);

extern struct nei_entry kni_neighbor[RTE_MAX_ETHPORTS];
extern struct ether_addr ports_eth_addr[RTE_MAX_ETHPORTS];

#endif
