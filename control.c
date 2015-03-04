#include <stdio.h>
#include <unistd.h>

#include <rte_common.h>
#include <rte_ip.h>
#include <rte_lpm.h>
#include <rte_lpm6.h>
#include <rte_ethdev.h>


#include <protobuf-c/protobuf-c.h>
#include <protobuf-c-rpc/protobuf-c-rpc.h>
#include <protobuf-c-rpc/protobuf-c-rpc-dispatch.h>

#include <router-dpdk/control.h>

#include "routing.h"

#define UNUSED(x) x __attribute__((unused))


void *control_main(void *UNUSED(argv))
{
	return NULL;
}
