#ifndef __RDPDK_APP_CONTROL_H
#define __RDPDK_APP_CONTROL_H

void *control_main(__rte_unused void *argv);

int control_callback_setup(const char *cb);
int control_add_ipv4_local_entry(struct in_addr *nexthop,
								 struct in_addr *saddr, uint8_t depth,
								 uint32_t port_id);

#endif
