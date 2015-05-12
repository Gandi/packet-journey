#ifndef __RDPDK_APP_COMMON_H
#define __RDPDK_APP_COMMON_H


#define NB_SOCKETS 8
#define RTE_LOGTYPE_L3FWD RTE_LOGTYPE_USER1
#define RTE_LOGTYPE_L3FWD_CTRL RTE_LOGTYPE_USER1
#define RTE_LOGTYPE_CMDLINE RTE_LOGTYPE_USER1
#define FWDSTEP	4

#ifdef RDPDK_DEBUG
#define L3FWD_DEBUG_TRACE(fmt, args...) do {                        \
		RTE_LOG(ERR, L3FWD, "%s: " fmt, __func__, ## args); \
	} while (0)
#else
#define L3FWD_DEBUG_TRACE(fmt, args...)
#endif

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
	/* total iterations looped recently */
	uint64_t nb_iteration_looped;
	/* port id, for now we have only one */
	uint64_t port_id;
} __rte_cache_aligned;

extern struct lcore_stats stats[RTE_MAX_LCORE];


#endif
