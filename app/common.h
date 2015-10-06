/*
 * rdpdk - userland router which uses DPDK for its fastpath switching
 *
 */
/*
 * Copyright (c) 2015 Gandi S.A.S.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

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
#define FWDSTEP 4
#define MAX_PKT_BURST 32
#define MAX_PACKET_SZ 2048

/* Used to mark destination port as 'invalid'. */
#define BAD_PORT ((uint16_t)-1)

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
	/* total packet dropped recently by acl */
	uint64_t nb_acl_dropped;
	/* total packet dropped recently by rate_liming */
	uint64_t nb_ratel_dropped;
	/* total iterations looped recently */
	uint64_t nb_iteration_looped;
	/* port id, for now we have only one */
	uint64_t port_id;
} __rte_cache_aligned;

extern struct lcore_stats stats[RTE_MAX_LCORE];

struct lpm_stats_t {
	uint64_t nb_add_ok;
	uint64_t nb_add_ko;
	uint64_t nb_del_ok;
	uint64_t nb_del_ko;
};

extern struct lpm_stats_t lpm4_stats[NB_SOCKETS];
extern struct lpm_stats_t lpm6_stats[NB_SOCKETS];

typedef uint8_t portid_t;

#endif
