#ifndef __RDPDK_APP_COMMON_H
#define __RDPDK_APP_COMMON_H

#define NB_SOCKETS 8
#define RTE_LOGTYPE_L3FWD RTE_LOGTYPE_USER1
#define RTE_LOGTYPE_L3FWD_CTRL RTE_LOGTYPE_USER1
#define RTE_LOGTYPE_CMDLINE RTE_LOGTYPE_USER1
#define FWDSTEP	4

#ifdef RDPDK_DEBUG
#define L3FWD_DEBUG_TRACE(fmt, args...) do {                        \
		RTE_LOG(ERR, PMD, "%s: " fmt, __func__, ## args); \
	} while (0)
#else
#define L3FWD_DEBUG_TRACE(fmt, args...)
#endif

/* Used to mark destination port as 'invalid'. */
#define	BAD_PORT	((uint16_t)-1)

#endif
