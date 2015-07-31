#ifndef __RDPDK_APP_COMMON_H
#define __RDPDK_APP_COMMON_H

#define RTE_LOGTYPE_RDPDK1 RTE_LOGTYPE_USER1
#define RTE_LOGTYPE_RDPDK_CTRL1 RTE_LOGTYPE_USER1
#define RTE_LOGTYPE_CMDLINE1 RTE_LOGTYPE_USER1

#define RTE_LOGTYPE_RDPDK2 RTE_LOGTYPE_USER2
#define RTE_LOGTYPE_RDPDK_CTRL2 RTE_LOGTYPE_USER2
#define RTE_LOGTYPE_CMDLINE2 RTE_LOGTYPE_USER2

#define RTE_LOGTYPE_RDPDK3 RTE_LOGTYPE_USER3
#define RTE_LOGTYPE_RDPDK_CTRL3 RTE_LOGTYPE_USER3
#define RTE_LOGTYPE_CMDLINE3 RTE_LOGTYPE_USER3

#define RTE_LOGTYPE_RDPDK4 RTE_LOGTYPE_USER4
#define RTE_LOGTYPE_RDPDK_CTRL4 RTE_LOGTYPE_USER4
#define RTE_LOGTYPE_CMDLINE4 RTE_LOGTYPE_USER4

#define RTE_LOGTYPE_RDPDK5 RTE_LOGTYPE_USER5
#define RTE_LOGTYPE_RDPDK_CTRL5 RTE_LOGTYPE_USER5
#define RTE_LOGTYPE_CMDLINE5 RTE_LOGTYPE_USER5

#define RTE_LOGTYPE_RDPDK6 RTE_LOGTYPE_USER6
#define RTE_LOGTYPE_RDPDK_CTRL6 RTE_LOGTYPE_USER6
#define RTE_LOGTYPE_CMDLINE6 RTE_LOGTYPE_USER6

#define RTE_LOGTYPE_RDPDK7 RTE_LOGTYPE_USER7
#define RTE_LOGTYPE_RDPDK_CTRL7 RTE_LOGTYPE_USER7
#define RTE_LOGTYPE_CMDLINE7 RTE_LOGTYPE_USER7

#define NB_SOCKETS 4
#define FWDSTEP	4
#define MAX_PKT_BURST     32
#define MAX_PACKET_SZ     2048

/* Used to mark destination port as 'invalid'. */
#define	BAD_PORT	((uint16_t)-1)

struct lcore_stats {
	/* total packet processed recently */
	uint64_t nb_rx;
	/* total packet sent recently */
	uint64_t nb_tx;
	/* total packet sent to kni recently */
	uint64_t nb_kni_tx;
	/* total packet received by kni recently */
	uint64_t nb_kni_rx;
	/* total packet dropped recently */
	uint64_t nb_dropped;
	/* total packet dropped recently by kni */
	uint64_t nb_kni_dropped;
	/* total iterations looped recently */
	uint64_t nb_iteration_looped;
	/* port id, for now we have only one */
	uint64_t port_id;
} __rte_cache_aligned;

extern struct lcore_stats stats[RTE_MAX_LCORE];

typedef uint8_t portid_t;

#endif
