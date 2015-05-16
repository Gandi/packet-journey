#ifndef __RDPDK_APP_CONTROL_H
#define __RDPDK_APP_CONTROL_H

void *control_init(int32_t nb_socket);
void *control_main(void *argv);

int control_callback_setup(const char *cb);
extern struct nei_entry kni_neighbor[RTE_MAX_ETHPORTS];
extern struct ether_addr ports_eth_addr[RTE_MAX_ETHPORTS];

#endif
