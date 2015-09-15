#ifndef __RDPDK_STATS_H
#define __RDPDK_STATS_H

#define RSS_HASH_KEY_LENGTH 52

enum { CMD_STATS_JSON = 1, CMD_STATS_CSV, CMD_LPM_STATS, CMD_LPM_STATS_JSON };

void nic_stats_display(struct cmdline *cl, portid_t port_id, int option);
void nic_stats_clear(struct cmdline *cl, portid_t port_id);
void nic_xstats_display(struct cmdline *cl, portid_t port_id, int option);
void nic_xstats_clear(struct cmdline *cl, portid_t port_id);
void port_infos_display(struct cmdline *cl, portid_t port_id);
void rdpdk_stats_display(struct cmdline *cl, int option, int delay);
void rdpdk_lpm_stats_display(struct cmdline *cl, int is_ipv4, int option);
void port_rss_hash_conf_show(struct cmdline *cl, portid_t port_id,
			     int show_rss_key);
void port_rss_hash_key_update(struct cmdline *cl, portid_t port_id,
			      uint8_t *hash_key);

#endif
