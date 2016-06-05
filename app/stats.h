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

#ifndef __PKTJ_STATS_H
#define __PKTJ_STATS_H

#define RSS_HASH_KEY_LENGTH 52

enum { CMD_STATS_JSON = 1, CMD_STATS_CSV, CMD_LPM_STATS, CMD_LPM_STATS_JSON };

void nic_stats_display(struct cmdline* cl, portid_t port_id, int option);
void nic_stats_clear(struct cmdline* cl, portid_t port_id);
void nic_xstats_display(struct cmdline* cl, portid_t port_id, int option);
void nic_xstats_clear(struct cmdline* cl, portid_t port_id);
void port_infos_display(struct cmdline* cl, portid_t port_id);
void pktj_stats_display(struct cmdline* cl, int option, int delay);
void pktj_lpm_stats_display(struct cmdline* cl, int is_ipv4, int option);
void port_rss_hash_conf_show(struct cmdline* cl,
			     portid_t port_id,
			     int show_rss_key);
void port_rss_hash_key_update(struct cmdline* cl,
			      portid_t port_id,
			      uint8_t* hash_key);

#endif
