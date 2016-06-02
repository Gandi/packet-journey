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
/*
 * Parts from:
 *
 * Copyright(c) 2010-2015 Intel Corporation. All rights reserved.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * * Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 * * Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in
 *   the documentation and/or other materials provided with the
 *   distribution.
 * * Neither the name of Intel Corporation nor the names of its
 *   contributors may be used to endorse or promote products derived
 *   from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <string.h>
#include <sys/queue.h>
#include <stdarg.h>
#include <errno.h>
#include <getopt.h>

#include <rte_common.h>
#include <rte_byteorder.h>
#include <rte_log.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_memzone.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_launch.h>
#include <rte_atomic.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_interrupts.h>
#include <rte_pci.h>
#include <rte_random.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_ring.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_string_fns.h>
#include <cmdline_parse.h>
#include <cmdline_parse_ipaddr.h>
#include <rte_acl.h>

#include <libneighbour.h>

#include "common.h"
#include "routing.h"
#include "acl.h"
#include "config.h"

/***********************start of ACL part******************************/
#define MAX_ACL_RULE_NUM 100000
#define L3FWD_ACL_IPV4_NAME "pktj-acl-ipv4"
#define L3FWD_ACL_IPV6_NAME "pktj-acl-ipv6"
#define ACL_LEAD_CHAR ('@')
#define COMMENT_LEAD_CHAR ('#')
#define RTE_LOGTYPE_PKTJ_ACL RTE_LOGTYPE_USER3
#define acl_log(format, ...) RTE_LOG(ERR, PKTJ_ACL, format, ##__VA_ARGS__)
#define uint32_t_to_char(ip, a, b, c, d)               \
	do {                                           \
		*a = (unsigned char)(ip >> 24 & 0xff); \
		*b = (unsigned char)(ip >> 16 & 0xff); \
		*c = (unsigned char)(ip >> 8 & 0xff);  \
		*d = (unsigned char)(ip & 0xff);       \
	} while (0)

#define GET_CB_FIELD(in, fd, base, lim, dlm)                      \
	do {                                                      \
		unsigned long val;                                \
		char* end;                                        \
		errno = 0;                                        \
		val = strtoul((in), &end, (base));                \
		if (errno != 0 || end[0] != (dlm) || val > (lim)) \
			return -EINVAL;                           \
		(fd) = (typeof(fd))val;                           \
		(in) = end + 1;                                   \
	} while (0)

/*
  * Forward port info save in ACL lib starts from 1
  * since ACL assume 0 is invalid.
  * So, need add 1 when saving and minus 1 when forwarding packets.
  */
#define FWD_PORT_SHIFT 1

/*
 * Rule and trace formats definitions.
 */

enum { PROTO_FIELD_IPV4,
       SRC_FIELD_IPV4,
       DST_FIELD_IPV4,
       SRCP_FIELD_IPV4,
       DSTP_FIELD_IPV4,
       NUM_FIELDS_IPV4 };

struct rte_acl_field_def ipv4_defs[NUM_FIELDS_IPV4] = {
    {
	.type = RTE_ACL_FIELD_TYPE_BITMASK,
	.size = sizeof(uint8_t),
	.field_index = PROTO_FIELD_IPV4,
	.input_index = RTE_ACL_IPV4VLAN_PROTO,
	.offset = 0,
    },
    {
	.type = RTE_ACL_FIELD_TYPE_MASK,
	.size = sizeof(uint32_t),
	.field_index = SRC_FIELD_IPV4,
	.input_index = RTE_ACL_IPV4VLAN_SRC,
	.offset = offsetof(struct ipv4_hdr, src_addr) -
		  offsetof(struct ipv4_hdr, next_proto_id),
    },
    {
	.type = RTE_ACL_FIELD_TYPE_MASK,
	.size = sizeof(uint32_t),
	.field_index = DST_FIELD_IPV4,
	.input_index = RTE_ACL_IPV4VLAN_DST,
	.offset = offsetof(struct ipv4_hdr, dst_addr) -
		  offsetof(struct ipv4_hdr, next_proto_id),
    },
    {
	.type = RTE_ACL_FIELD_TYPE_RANGE,
	.size = sizeof(uint16_t),
	.field_index = SRCP_FIELD_IPV4,
	.input_index = RTE_ACL_IPV4VLAN_PORTS,
	.offset =
	    sizeof(struct ipv4_hdr) - offsetof(struct ipv4_hdr, next_proto_id),
    },
    {
	.type = RTE_ACL_FIELD_TYPE_RANGE,
	.size = sizeof(uint16_t),
	.field_index = DSTP_FIELD_IPV4,
	.input_index = RTE_ACL_IPV4VLAN_PORTS,
	.offset = sizeof(struct ipv4_hdr) -
		  offsetof(struct ipv4_hdr, next_proto_id) +
		  sizeof(uint16_t),
    },
};

#define IPV6_ADDR_LEN 16
#define IPV6_ADDR_U16 (IPV6_ADDR_LEN / sizeof(uint16_t))
#define IPV6_ADDR_U32 (IPV6_ADDR_LEN / sizeof(uint32_t))

enum { PROTO_FIELD_IPV6,
       SRC1_FIELD_IPV6,
       SRC2_FIELD_IPV6,
       SRC3_FIELD_IPV6,
       SRC4_FIELD_IPV6,
       DST1_FIELD_IPV6,
       DST2_FIELD_IPV6,
       DST3_FIELD_IPV6,
       DST4_FIELD_IPV6,
       SRCP_FIELD_IPV6,
       DSTP_FIELD_IPV6,
       NUM_FIELDS_IPV6 };

struct rte_acl_field_def ipv6_defs[NUM_FIELDS_IPV6] = {
    {
	.type = RTE_ACL_FIELD_TYPE_BITMASK,
	.size = sizeof(uint8_t),
	.field_index = PROTO_FIELD_IPV6,
	.input_index = PROTO_FIELD_IPV6,
	.offset = 0,
    },
    {
	.type = RTE_ACL_FIELD_TYPE_MASK,
	.size = sizeof(uint32_t),
	.field_index = SRC1_FIELD_IPV6,
	.input_index = SRC1_FIELD_IPV6,
	.offset = offsetof(struct ipv6_hdr, src_addr) -
		  offsetof(struct ipv6_hdr, proto),
    },
    {
	.type = RTE_ACL_FIELD_TYPE_MASK,
	.size = sizeof(uint32_t),
	.field_index = SRC2_FIELD_IPV6,
	.input_index = SRC2_FIELD_IPV6,
	.offset = offsetof(struct ipv6_hdr, src_addr) -
		  offsetof(struct ipv6_hdr, proto) +
		  sizeof(uint32_t),
    },
    {
	.type = RTE_ACL_FIELD_TYPE_MASK,
	.size = sizeof(uint32_t),
	.field_index = SRC3_FIELD_IPV6,
	.input_index = SRC3_FIELD_IPV6,
	.offset = offsetof(struct ipv6_hdr, src_addr) -
		  offsetof(struct ipv6_hdr, proto) +
		  2 * sizeof(uint32_t),
    },
    {
	.type = RTE_ACL_FIELD_TYPE_MASK,
	.size = sizeof(uint32_t),
	.field_index = SRC4_FIELD_IPV6,
	.input_index = SRC4_FIELD_IPV6,
	.offset = offsetof(struct ipv6_hdr, src_addr) -
		  offsetof(struct ipv6_hdr, proto) +
		  3 * sizeof(uint32_t),
    },
    {
	.type = RTE_ACL_FIELD_TYPE_MASK,
	.size = sizeof(uint32_t),
	.field_index = DST1_FIELD_IPV6,
	.input_index = DST1_FIELD_IPV6,
	.offset = offsetof(struct ipv6_hdr, dst_addr) -
		  offsetof(struct ipv6_hdr, proto),
    },
    {
	.type = RTE_ACL_FIELD_TYPE_MASK,
	.size = sizeof(uint32_t),
	.field_index = DST2_FIELD_IPV6,
	.input_index = DST2_FIELD_IPV6,
	.offset = offsetof(struct ipv6_hdr, dst_addr) -
		  offsetof(struct ipv6_hdr, proto) +
		  sizeof(uint32_t),
    },
    {
	.type = RTE_ACL_FIELD_TYPE_MASK,
	.size = sizeof(uint32_t),
	.field_index = DST3_FIELD_IPV6,
	.input_index = DST3_FIELD_IPV6,
	.offset = offsetof(struct ipv6_hdr, dst_addr) -
		  offsetof(struct ipv6_hdr, proto) +
		  2 * sizeof(uint32_t),
    },
    {
	.type = RTE_ACL_FIELD_TYPE_MASK,
	.size = sizeof(uint32_t),
	.field_index = DST4_FIELD_IPV6,
	.input_index = DST4_FIELD_IPV6,
	.offset = offsetof(struct ipv6_hdr, dst_addr) -
		  offsetof(struct ipv6_hdr, proto) +
		  3 * sizeof(uint32_t),
    },
    {
	.type = RTE_ACL_FIELD_TYPE_RANGE,
	.size = sizeof(uint16_t),
	.field_index = SRCP_FIELD_IPV6,
	.input_index = SRCP_FIELD_IPV6,
	.offset = sizeof(struct ipv6_hdr) - offsetof(struct ipv6_hdr, proto),
    },
    {
	.type = RTE_ACL_FIELD_TYPE_RANGE,
	.size = sizeof(uint16_t),
	.field_index = DSTP_FIELD_IPV6,
	.input_index = SRCP_FIELD_IPV6,
	.offset = sizeof(struct ipv6_hdr) - offsetof(struct ipv6_hdr, proto) +
		  sizeof(uint16_t),
    },
};

enum { CB_FLD_SRC_ADDR,
       CB_FLD_DST_ADDR,
       CB_FLD_SRC_PORT_LOW,
       CB_FLD_SRC_PORT_DLM,
       CB_FLD_SRC_PORT_HIGH,
       CB_FLD_DST_PORT_LOW,
       CB_FLD_DST_PORT_DLM,
       CB_FLD_DST_PORT_HIGH,
       CB_FLD_PROTO,
       CB_FLD_NUM,
};

RTE_ACL_RULE_DEF(acl4_rule, RTE_DIM(ipv4_defs));
RTE_ACL_RULE_DEF(acl6_rule, RTE_DIM(ipv6_defs));

#ifdef L3FWDACL_DEBUG
static struct {
	struct acl4_rule* rule_ipv4;
	struct acl6_rule* rule_ipv6;
} acl_config;
#endif

struct rte_acl_ctx* ipv4_acx[NB_SOCKETS];
struct rte_acl_ctx* ipv6_acx[NB_SOCKETS];

struct acl_parm acl_parm_config;

const char cb_port_delim[] = ":";

static inline void
print_one_ipv4_rule(struct acl4_rule* rule, int extra)
{
	unsigned char a, b, c, d;

	uint32_t_to_char(rule->field[SRC_FIELD_IPV4].value.u32, &a, &b, &c, &d);
	acl_log("%hhu.%hhu.%hhu.%hhu/%u ", a, b, c, d,
		rule->field[SRC_FIELD_IPV4].mask_range.u32);
	uint32_t_to_char(rule->field[DST_FIELD_IPV4].value.u32, &a, &b, &c, &d);
	acl_log("%hhu.%hhu.%hhu.%hhu/%u ", a, b, c, d,
		rule->field[DST_FIELD_IPV4].mask_range.u32);
	acl_log("%hu : %hu %hu : %hu 0x%hhx/0x%hhx ",
		rule->field[SRCP_FIELD_IPV4].value.u16,
		rule->field[SRCP_FIELD_IPV4].mask_range.u16,
		rule->field[DSTP_FIELD_IPV4].value.u16,
		rule->field[DSTP_FIELD_IPV4].mask_range.u16,
		rule->field[PROTO_FIELD_IPV4].value.u8,
		rule->field[PROTO_FIELD_IPV4].mask_range.u8);
	if (extra)
		acl_log("0x%x-0x%x-0x%x ", rule->data.category_mask,
			rule->data.priority, rule->data.userdata);
}

static inline void
print_one_ipv6_rule(struct acl6_rule* rule, int extra)
{
	unsigned char a, b, c, d;

	uint32_t_to_char(rule->field[SRC1_FIELD_IPV6].value.u32, &a, &b, &c,
			 &d);
	acl_log("%.2x%.2x:%.2x%.2x", a, b, c, d);
	uint32_t_to_char(rule->field[SRC2_FIELD_IPV6].value.u32, &a, &b, &c,
			 &d);
	acl_log(":%.2x%.2x:%.2x%.2x", a, b, c, d);
	uint32_t_to_char(rule->field[SRC3_FIELD_IPV6].value.u32, &a, &b, &c,
			 &d);
	acl_log(":%.2x%.2x:%.2x%.2x", a, b, c, d);
	uint32_t_to_char(rule->field[SRC4_FIELD_IPV6].value.u32, &a, &b, &c,
			 &d);
	acl_log(":%.2x%.2x:%.2x%.2x/%u ", a, b, c, d,
		rule->field[SRC1_FIELD_IPV6].mask_range.u32 +
		    rule->field[SRC2_FIELD_IPV6].mask_range.u32 +
		    rule->field[SRC3_FIELD_IPV6].mask_range.u32 +
		    rule->field[SRC4_FIELD_IPV6].mask_range.u32);

	uint32_t_to_char(rule->field[DST1_FIELD_IPV6].value.u32, &a, &b, &c,
			 &d);
	acl_log("%.2x%.2x:%.2x%.2x", a, b, c, d);
	uint32_t_to_char(rule->field[DST2_FIELD_IPV6].value.u32, &a, &b, &c,
			 &d);
	acl_log(":%.2x%.2x:%.2x%.2x", a, b, c, d);
	uint32_t_to_char(rule->field[DST3_FIELD_IPV6].value.u32, &a, &b, &c,
			 &d);
	acl_log(":%.2x%.2x:%.2x%.2x", a, b, c, d);
	uint32_t_to_char(rule->field[DST4_FIELD_IPV6].value.u32, &a, &b, &c,
			 &d);
	acl_log(":%.2x%.2x:%.2x%.2x/%u ", a, b, c, d,
		rule->field[DST1_FIELD_IPV6].mask_range.u32 +
		    rule->field[DST2_FIELD_IPV6].mask_range.u32 +
		    rule->field[DST3_FIELD_IPV6].mask_range.u32 +
		    rule->field[DST4_FIELD_IPV6].mask_range.u32);

	acl_log("%hu : %hu %hu : %hu 0x%hhx/0x%hhx ",
		rule->field[SRCP_FIELD_IPV6].value.u16,
		rule->field[SRCP_FIELD_IPV6].mask_range.u16,
		rule->field[DSTP_FIELD_IPV6].value.u16,
		rule->field[DSTP_FIELD_IPV6].mask_range.u16,
		rule->field[PROTO_FIELD_IPV6].value.u8,
		rule->field[PROTO_FIELD_IPV6].mask_range.u8);
	if (extra)
		acl_log("0x%x-0x%x-0x%x ", rule->data.category_mask,
			rule->data.priority, rule->data.userdata);
}

/* Bypass comment and empty lines */
static inline int
is_bypass_line(char* buff)
{
	int i = 0;

	/* comment line */
	if (buff[0] == COMMENT_LEAD_CHAR)
		return 1;
	/* empty line */
	while (buff[i] != '\0') {
		if (!isspace(buff[i]))
			return 0;
		i++;
	}
	return 1;
}

#ifdef L3FWDACL_DEBUG
void
dump_acl4_rule(struct rte_mbuf* m, uint32_t sig)
{
	uint32_t offset = sig & ~ACL_DENY_SIGNATURE;
	unsigned char a, b, c, d;
	struct ipv4_hdr* ipv4_hdr =
	    (struct ipv4_hdr*)(rte_pktmbuf_mtod(m, unsigned char*) +
			       sizeof(struct ether_hdr));

	uint32_t_to_char(rte_bswap32(ipv4_hdr->src_addr), &a, &b, &c, &d);
	acl_log("Packet Src:%hhu.%hhu.%hhu.%hhu ", a, b, c, d);
	uint32_t_to_char(rte_bswap32(ipv4_hdr->dst_addr), &a, &b, &c, &d);
	acl_log("Dst:%hhu.%hhu.%hhu.%hhu ", a, b, c, d);

	acl_log("Src port:%hu,Dst port:%hu ",
		rte_bswap16(*(uint16_t*)(ipv4_hdr + 1)),
		rte_bswap16(*((uint16_t*)(ipv4_hdr + 1) + 1)));
	acl_log("hit ACL %d - ", offset);

	print_one_ipv4_rule(acl_config.rule_ipv4 + offset, 1);

	acl_log("\n\n");
}

void
dump_acl6_rule(struct rte_mbuf* m, uint32_t sig)
{
	unsigned i;
	uint32_t offset = sig & ~ACL_DENY_SIGNATURE;
	struct ipv6_hdr* ipv6_hdr =
	    (struct ipv6_hdr*)(rte_pktmbuf_mtod(m, unsigned char*) +
			       sizeof(struct ether_hdr));

	acl_log("Packet Src");
	for (i = 0; i < RTE_DIM(ipv6_hdr->src_addr); i += sizeof(uint16_t))
		acl_log(":%.2x%.2x", ipv6_hdr->src_addr[i],
			ipv6_hdr->src_addr[i + 1]);

	acl_log("\nDst");
	for (i = 0; i < RTE_DIM(ipv6_hdr->dst_addr); i += sizeof(uint16_t))
		acl_log(":%.2x%.2x", ipv6_hdr->dst_addr[i],
			ipv6_hdr->dst_addr[i + 1]);

	acl_log("\nSrc port:%hu,Dst port:%hu ",
		rte_bswap16(*(uint16_t*)(ipv6_hdr + 1)),
		rte_bswap16(*((uint16_t*)(ipv6_hdr + 1) + 1)));
	acl_log("hit ACL %d - ", offset);

	print_one_ipv6_rule(acl_config.rule_ipv6 + offset, 1);

	acl_log("\n\n");
}
#endif /* L3FWDACL_DEBUG */

static inline void
dump_ipv4_rules(struct acl4_rule* rule, int num, int extra)
{
	int i;

	for (i = 0; i < num; i++, rule++) {
		acl_log("\t%d:", i + 1);
		print_one_ipv4_rule(rule, extra);
		acl_log("\n");
	}
}

static inline void
dump_ipv6_rules(struct acl6_rule* rule, int num, int extra)
{
	int i;

	for (i = 0; i < num; i++, rule++) {
		acl_log("\t%d:", i + 1);
		print_one_ipv6_rule(rule, extra);
		acl_log("\n");
	}
}

/*
 * Parses IPV6 address, expects the following format:
 * XXXX:XXXX:XXXX:XXXX:XXXX:XXXX:XXXX:XXXX (where X - is a hexedecimal digit).
 */
static int
parse_ipv6_addr(const char* in,
		const char** end,
		uint32_t v[IPV6_ADDR_U32],
		char dlm)
{
	uint32_t addr[IPV6_ADDR_U16];

	GET_CB_FIELD(in, addr[0], 16, UINT16_MAX, ':');
	GET_CB_FIELD(in, addr[1], 16, UINT16_MAX, ':');
	GET_CB_FIELD(in, addr[2], 16, UINT16_MAX, ':');
	GET_CB_FIELD(in, addr[3], 16, UINT16_MAX, ':');
	GET_CB_FIELD(in, addr[4], 16, UINT16_MAX, ':');
	GET_CB_FIELD(in, addr[5], 16, UINT16_MAX, ':');
	GET_CB_FIELD(in, addr[6], 16, UINT16_MAX, ':');
	GET_CB_FIELD(in, addr[7], 16, UINT16_MAX, dlm);

	*end = in;

	v[0] = (addr[0] << 16) + addr[1];
	v[1] = (addr[2] << 16) + addr[3];
	v[2] = (addr[4] << 16) + addr[5];
	v[3] = (addr[6] << 16) + addr[7];

	return 0;
}

static int
parse_ipv6_net(const char* in, struct rte_acl_field field[4])
{
	int32_t rc;
	const char* mp;
	uint32_t i, m, v[4];
	const uint32_t nbu32 = sizeof(uint32_t) * CHAR_BIT;

	// TODO may be replaced by inet_pton with some refactoring
	/* get address. */
	rc = parse_ipv6_addr(in, &mp, v, '/');
	if (rc != 0)
		return rc;

	/* get mask. */
	GET_CB_FIELD(mp, m, 0, CHAR_BIT * sizeof(v), 0);

	/* put all together. */
	for (i = 0; i != RTE_DIM(v); i++) {
		if (m >= (i + 1) * nbu32)
			field[i].mask_range.u32 = nbu32;
		else
			field[i].mask_range.u32 =
			    m > (i * nbu32) ? m - (i * 32) : 0;

		field[i].value.u32 = v[i];
	}

	return 0;
}

static int
parse_cb_ipv6_rule(char* str, struct rte_acl_rule* v)
{
	int i, rc;
	char *s, *sp, *in[CB_FLD_NUM];
	static const char* dlm = " \t\n";
	int dim = CB_FLD_NUM;
	s = str;

	for (i = 0; i != dim; i++, s = NULL) {
		in[i] = strtok_r(s, dlm, &sp);
		if (in[i] == NULL)
			return -EINVAL;
	}

	rc = parse_ipv6_net(in[CB_FLD_SRC_ADDR], v->field + SRC1_FIELD_IPV6);
	if (rc != 0) {
		acl_log("failed to read source address/mask: %s\n",
			in[CB_FLD_SRC_ADDR]);
		return rc;
	}

	rc = parse_ipv6_net(in[CB_FLD_DST_ADDR], v->field + DST1_FIELD_IPV6);
	if (rc != 0) {
		acl_log("failed to read destination address/mask: %s\n",
			in[CB_FLD_DST_ADDR]);
		return rc;
	}

	/* source port. */
	GET_CB_FIELD(in[CB_FLD_SRC_PORT_LOW],
		     v->field[SRCP_FIELD_IPV6].value.u16, 0, UINT16_MAX, 0);
	GET_CB_FIELD(in[CB_FLD_SRC_PORT_HIGH],
		     v->field[SRCP_FIELD_IPV6].mask_range.u16, 0, UINT16_MAX,
		     0);

	if (strncmp(in[CB_FLD_SRC_PORT_DLM], cb_port_delim,
		    sizeof(cb_port_delim)) != 0)
		return -EINVAL;

	/* destination port. */
	GET_CB_FIELD(in[CB_FLD_DST_PORT_LOW],
		     v->field[DSTP_FIELD_IPV6].value.u16, 0, UINT16_MAX, 0);
	GET_CB_FIELD(in[CB_FLD_DST_PORT_HIGH],
		     v->field[DSTP_FIELD_IPV6].mask_range.u16, 0, UINT16_MAX,
		     0);

	if (strncmp(in[CB_FLD_DST_PORT_DLM], cb_port_delim,
		    sizeof(cb_port_delim)) != 0)
		return -EINVAL;

	if (v->field[SRCP_FIELD_IPV6].mask_range.u16 <
		v->field[SRCP_FIELD_IPV6].value.u16 ||
	    v->field[DSTP_FIELD_IPV6].mask_range.u16 <
		v->field[DSTP_FIELD_IPV6].value.u16)
		return -EINVAL;

	GET_CB_FIELD(in[CB_FLD_PROTO], v->field[PROTO_FIELD_IPV6].value.u8, 0,
		     UINT8_MAX, '/');
	GET_CB_FIELD(in[CB_FLD_PROTO], v->field[PROTO_FIELD_IPV6].mask_range.u8,
		     0, UINT8_MAX, 0);
	return 0;
}

/*
 * Parse ClassBench rules file.
 * Expected format:
 * '@'<src_ipv4_addr>'/'<masklen> <space> \
 * <dst_ipv4_addr>'/'<masklen> <space> \
 * <src_port_low> <space> ":" <src_port_high> <space> \
 * <dst_port_low> <space> ":" <dst_port_high> <space> \
 * <proto>'/'<mask>
 */
static int
parse_ipv4_net(const char* in, uint32_t* addr, uint32_t* mask_len)
{
	uint8_t a, b, c, d, m;

	// TODO may be replaced by inet_pton with some refactoring
	GET_CB_FIELD(in, a, 0, UINT8_MAX, '.');
	GET_CB_FIELD(in, b, 0, UINT8_MAX, '.');
	GET_CB_FIELD(in, c, 0, UINT8_MAX, '.');
	GET_CB_FIELD(in, d, 0, UINT8_MAX, '/');
	GET_CB_FIELD(in, m, 0, sizeof(uint32_t) * CHAR_BIT, 0);

	addr[0] = IPv4(a, b, c, d);
	mask_len[0] = m;

	return 0;
}

static int
parse_cb_ipv4vlan_rule(char* str, struct rte_acl_rule* v)
{
	int i, rc;
	char *s, *sp, *in[CB_FLD_NUM];
	static const char* dlm = " \t\n";
	int dim = CB_FLD_NUM;
	s = str;

	for (i = 0; i != dim; i++, s = NULL) {
		in[i] = strtok_r(s, dlm, &sp);
		if (in[i] == NULL)
			return -EINVAL;
	}

	rc = parse_ipv4_net(in[CB_FLD_SRC_ADDR],
			    &v->field[SRC_FIELD_IPV4].value.u32,
			    &v->field[SRC_FIELD_IPV4].mask_range.u32);
	if (rc != 0) {
		acl_log("failed to read source address/mask: %s\n",
			in[CB_FLD_SRC_ADDR]);
		return rc;
	}

	rc = parse_ipv4_net(in[CB_FLD_DST_ADDR],
			    &v->field[DST_FIELD_IPV4].value.u32,
			    &v->field[DST_FIELD_IPV4].mask_range.u32);
	if (rc != 0) {
		acl_log("failed to read destination address/mask: %s\n",
			in[CB_FLD_DST_ADDR]);
		return rc;
	}

	GET_CB_FIELD(in[CB_FLD_SRC_PORT_LOW],
		     v->field[SRCP_FIELD_IPV4].value.u16, 0, UINT16_MAX, 0);
	GET_CB_FIELD(in[CB_FLD_SRC_PORT_HIGH],
		     v->field[SRCP_FIELD_IPV4].mask_range.u16, 0, UINT16_MAX,
		     0);

	if (strncmp(in[CB_FLD_SRC_PORT_DLM], cb_port_delim,
		    sizeof(cb_port_delim)) != 0)
		return -EINVAL;

	GET_CB_FIELD(in[CB_FLD_DST_PORT_LOW],
		     v->field[DSTP_FIELD_IPV4].value.u16, 0, UINT16_MAX, 0);
	GET_CB_FIELD(in[CB_FLD_DST_PORT_HIGH],
		     v->field[DSTP_FIELD_IPV4].mask_range.u16, 0, UINT16_MAX,
		     0);

	if (strncmp(in[CB_FLD_DST_PORT_DLM], cb_port_delim,
		    sizeof(cb_port_delim)) != 0)
		return -EINVAL;

	if (v->field[SRCP_FIELD_IPV4].mask_range.u16 <
		v->field[SRCP_FIELD_IPV4].value.u16 ||
	    v->field[DSTP_FIELD_IPV4].mask_range.u16 <
		v->field[DSTP_FIELD_IPV4].value.u16)
		return -EINVAL;

	GET_CB_FIELD(in[CB_FLD_PROTO], v->field[PROTO_FIELD_IPV4].value.u8, 0,
		     UINT8_MAX, '/');
	GET_CB_FIELD(in[CB_FLD_PROTO], v->field[PROTO_FIELD_IPV4].mask_range.u8,
		     0, UINT8_MAX, 0);

	return 0;
}

static int
add_rules(const char* rule_path,
	  struct rte_acl_rule** pacl_base,
	  unsigned int* pacl_num,
	  uint32_t rule_size,
	  int (*parser)(char*, struct rte_acl_rule*))
{
	char buff[LINE_MAX];
	struct rte_acl_rule* next;
	uint8_t* acl_rules = 0;
	unsigned int acl_num = 0, total_num = 0;
	unsigned int acl_cnt = 0;
	FILE* fh = fopen(rule_path, "rb");
	unsigned int i = 0;

	if (fh == NULL) {
		acl_log("%s: Open %s failed\n", __func__, rule_path);
		return -1;
	}

	while ((fgets(buff, LINE_MAX, fh) != NULL)) {
		if (buff[0] == ACL_LEAD_CHAR)
			acl_num++;
	}

	fseek(fh, 0, SEEK_SET);

	if (!acl_num) {
		fclose(fh);
		*pacl_num = 0;
		return 0;
	}

	acl_rules = calloc(acl_num, rule_size);

	// XXX do we want to keep that rte_exit ?
	if (NULL == acl_rules)
		rte_exit(EXIT_FAILURE, "%s: failed to malloc memory\n",
			 __func__);

	i = 0;
	while (fgets(buff, LINE_MAX, fh) != NULL) {
		i++;

		if (is_bypass_line(buff))
			continue;

		char s = buff[0];

		/* ACL entry */
		if (s == ACL_LEAD_CHAR)
			next = (struct rte_acl_rule*)(acl_rules +
						      acl_cnt * rule_size);

		/* Illegal line */
		else {
			acl_log(
			    "%s Line %u: should start with leading "
			    "char %c\n",
			    rule_path, i, ACL_LEAD_CHAR);
			goto err;
		}

		if (parser(buff + 1, next) != 0) {
			acl_log("%s Line %u: parse rules error\n", rule_path,
				i);
			goto err;
		}

		next->data.userdata = ACL_DENY_SIGNATURE + acl_cnt;
		acl_cnt++;

		next->data.priority = total_num;
		next->data.category_mask = -1;
		total_num++;
	}

	fclose(fh);

	*pacl_base = (struct rte_acl_rule*)acl_rules;
	*pacl_num = acl_num;

	return 0;
err:
	free(acl_rules);
	fclose(fh);
	return -EINVAL;
}

static void
dump_acl_config(void)
{
	RTE_LOG(INFO, PKTJ1, "ACL option are:\n");
	RTE_LOG(INFO, PKTJ1, CMD_LINE_OPT_RULE_IPV4 ": %s\n",
		acl_parm_config.rule_ipv4_name);
	RTE_LOG(INFO, PKTJ1, CMD_LINE_OPT_RULE_IPV6 ": %s\n",
		acl_parm_config.rule_ipv6_name);
	RTE_LOG(INFO, PKTJ1, CMD_LINE_OPT_ACLAVX2 ": %d\n",
		acl_parm_config.aclavx2);
}

static int
check_acl_config(void)
{
	if (acl_parm_config.rule_ipv4_name == NULL) {
		acl_log("ACL IPv4 rule file not specified\n");
		return -1;
	} else if (acl_parm_config.rule_ipv6_name == NULL) {
		acl_log("ACL IPv6 rule file not specified\n");
		return -1;
	}

	return 0;
}

static struct rte_acl_ctx*
setup_acl(struct rte_acl_rule* acl_base,
	  unsigned int acl_num,
	  int ipv6,
	  int socketid)
{
	char name[PATH_MAX];
	struct rte_acl_param acl_param;
	struct rte_acl_config acl_build_param;
	struct rte_acl_ctx* context;
	int dim = ipv6 ? RTE_DIM(ipv6_defs) : RTE_DIM(ipv4_defs);
	static uint32_t ctx_count[NB_SOCKETS] = {0};

	if (!acl_num)
		return NULL;

	/* Create ACL contexts */
	snprintf(name, sizeof(name), "%s%d-%d",
		 ipv6 ? L3FWD_ACL_IPV6_NAME : L3FWD_ACL_IPV4_NAME, socketid,
		 ctx_count[socketid]++);

	acl_param.name = name;
	acl_param.socket_id = socketid;
	acl_param.rule_size = RTE_ACL_RULE_SZ(dim);
	acl_param.max_rule_num = MAX_ACL_RULE_NUM;

	if ((context = rte_acl_create(&acl_param)) == NULL) {
		acl_log("Failed to create ACL context\n");
		goto err;
	}

	if (acl_parm_config.aclavx2 &&
	    rte_acl_set_ctx_classify(context, RTE_ACL_CLASSIFY_AVX2) != 0) {
		acl_log("Failed to setup classify method for  ACL context\n");
		goto err;
	}

	if (rte_acl_add_rules(context, acl_base, acl_num) < 0) {
		acl_log("add rules failed\n");
		goto err;
	}

	/* Perform builds */
	memset(&acl_build_param, 0, sizeof(acl_build_param));

	acl_build_param.num_categories = DEFAULT_MAX_CATEGORIES;
	acl_build_param.num_fields = dim;
	memcpy(&acl_build_param.defs, ipv6 ? ipv6_defs : ipv4_defs,
	       ipv6 ? sizeof(ipv6_defs) : sizeof(ipv4_defs));

	if (rte_acl_build(context, &acl_build_param) != 0) {
		acl_log("Failed to build ACL trie\n");
		goto err;
	}

	rte_acl_dump(context);

	return context;
err:
	rte_acl_free(context);
	return NULL;
}

int
acl_init(int is_ipv4)
{
	unsigned int i;
	struct rte_acl_rule *acl_base_ipv4 = NULL, *acl_base_ipv6 = NULL;
	unsigned int acl_num_ipv4 = 0, acl_num_ipv6 = 0;
	struct rte_acl_ctx* acl_ctx;

	if (check_acl_config() != 0) {
		acl_log("Failed to get valid ACL options\n");
		return -1;
	}

	dump_acl_config();

	if (is_ipv4) {
		/* Load  rules from the input file */
		if (add_rules(acl_parm_config.rule_ipv4_name, &acl_base_ipv4,
			      &acl_num_ipv4, sizeof(struct acl4_rule),
			      &parse_cb_ipv4vlan_rule) < 0) {
			acl_log("Failed to add ipv4 rules\n");
			return -1;
		}

		acl_log("IPv4 ACL entries %u:\n", acl_num_ipv4);
		dump_ipv4_rules((struct acl4_rule*)acl_base_ipv4, acl_num_ipv4,
				1);
		for (i = 0; i < NB_SOCKETS; i++) {
			if ((acl_ctx = setup_acl(acl_base_ipv4, acl_num_ipv4, 0,
						 i)) != NULL) {
				ipv4_acx[i] = acl_ctx;
			} else if (acl_num_ipv4 == 0) {
				ipv4_acx[i] = NULL;
			} else {
				acl_log(
				    "setup_acl failed for ipv4 with "
				    "socketid %d, keeping previous rules "
				    "for that socket\n",
				    i);
			}
		}
#ifdef L3FWDACL_DEBUG
		if (acl_base_ipv4) {
			acl_config.rule_ipv4 = (struct acl4_rule*)acl_base_ipv4;
		}
#else
		free(acl_base_ipv4);
#endif
	} else {
		if (add_rules(acl_parm_config.rule_ipv6_name, &acl_base_ipv6,
			      &acl_num_ipv6, sizeof(struct acl6_rule),
			      &parse_cb_ipv6_rule) < 0) {
			acl_log("Failed to add ipv6 rules\n");
			return -1;
		}

		acl_log("IPv6 ACL entries %u:\n", acl_num_ipv6);
		dump_ipv6_rules((struct acl6_rule*)acl_base_ipv6, acl_num_ipv6,
				1);
		for (i = 0; i < NB_SOCKETS; i++) {
			if ((acl_ctx = setup_acl(acl_base_ipv6, acl_num_ipv6, 1,
						 i)) != NULL) {
				ipv6_acx[i] = acl_ctx;
			} else if (acl_num_ipv6 == 0) {
				ipv6_acx[i] = NULL;
			} else {
				acl_log(
				    "setup_acl failed for ipv6 with "
				    "socketid %d, keeping previous rules "
				    "for that socket\n",
				    i);
			}
		}
#ifdef L3FWDACL_DEBUG
		if (acl_base_ipv6) {
			acl_config.rule_ipv6 = (struct acl6_rule*)acl_base_ipv6;
		}
#else
		free(acl_base_ipv6);
#endif
	}

	int socketid, lcore_id;
	for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
		if (rte_lcore_is_enabled(lcore_id) == 0)
			continue;

		if (numa_on)
			socketid = rte_lcore_to_socket_id(lcore_id);
		else
			socketid = 0;

		rte_atomic64_cmpset(
		    (uintptr_t*)&lcore_conf[lcore_id].new_acx_ipv4,
		    (uintptr_t)lcore_conf[lcore_id].new_acx_ipv4,
		    (uintptr_t)ipv4_acx[socketid]);
		rte_atomic64_cmpset(
		    (uintptr_t*)&lcore_conf[lcore_id].new_acx_ipv6,
		    (uintptr_t)lcore_conf[lcore_id].new_acx_ipv6,
		    (uintptr_t)ipv6_acx[socketid]);
	}

	return 0;
}
