/*
 * Packet-journey userland router which uses DPDK for its fastpath switching
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

#ifndef __PKTJ_ACL_H
#define __PKTJ_ACL_H

#include <rte_version.h>

#define DEFAULT_MAX_CATEGORIES 1
#define ACL_DENY_SIGNATURE 0xf0000000

#define OFF_ETHHEAD (sizeof(struct ether_hdr))
#define OFF_IPV42PROTO (offsetof(struct ipv4_hdr, next_proto_id))
#define OFF_IPV62PROTO (offsetof(struct ipv6_hdr, proto))
#define MBUF_IPV4_2PROTO(m) \
	(rte_pktmbuf_mtod((m), uint8_t*) + OFF_ETHHEAD + OFF_IPV42PROTO)
#define MBUF_IPV6_2PROTO(m) \
	(rte_pktmbuf_mtod((m), uint8_t*) + OFF_ETHHEAD + OFF_IPV62PROTO)

#ifdef L3FWDACL_DEBUG

void dump_acl4_rule(struct rte_mbuf* m, uint32_t sig);
void dump_acl6_rule(struct rte_mbuf* m, uint32_t sig);

#endif

int acl_init(int is_ipv4);

struct acl_search_t {
	const uint8_t* data_ipv4[MAX_PKT_BURST];
	struct rte_mbuf* m_ipv4[MAX_PKT_BURST];
	uint32_t res_ipv4[MAX_PKT_BURST];
	int num_ipv4;

	const uint8_t* data_ipv6[MAX_PKT_BURST];
	struct rte_mbuf* m_ipv6[MAX_PKT_BURST];
	uint32_t res_ipv6[MAX_PKT_BURST];
	int num_ipv6;
};

struct acl_parm {
	const char* rule_ipv4_name;
	const char* rule_ipv6_name;
	int aclavx2;
};

extern struct acl_parm acl_parm_config;

extern struct rte_acl_ctx* ipv4_acx[NB_SOCKETS];
extern struct rte_acl_ctx* ipv6_acx[NB_SOCKETS];

#if RTE_VER_MINOR > 1 && RTE_VER_MAJOR == 2
/*
 * That effectively defines order of IPV4VLAN classifications:
 *  - PROTO
 *  - VLAN (TAG and DOMAIN)
 *  - SRC IP ADDRESS
 *  - DST IP ADDRESS
 *  - PORTS (SRC and DST)
 */
enum { RTE_ACL_IPV4VLAN_PROTO,
       RTE_ACL_IPV4VLAN_VLAN,
       RTE_ACL_IPV4VLAN_SRC,
       RTE_ACL_IPV4VLAN_DST,
       RTE_ACL_IPV4VLAN_PORTS,
       RTE_ACL_IPV4VLAN_NUM };

#endif

#endif
