#ifndef __RDPDK_CONFIG_H
#define __RDPDK_CONFIG_H

void print_usage(const char *prgname);
int parse_args(int argc, char **argv);

extern uint16_t nb_lcore_params;
extern struct lcore_params *lcore_params;
extern uint32_t enabled_port_mask;
extern int promiscuous_on;
extern int numa_on;
extern const char *callback_setup;
extern const char *unixsock_path;
extern struct rte_eth_conf port_conf;

struct lcore_params {
	uint8_t port_id;
	uint8_t queue_id;
	uint8_t lcore_id;
} __rte_cache_aligned;

#define CMD_LINE_OPT_CONFIG "config"
#define CMD_LINE_OPT_KNICONFIG "kniconfig"
#define CMD_LINE_OPT_CALLBACK_SETUP "callback-setup"
#define CMD_LINE_OPT_UNIXSOCK "unixsock"
#define CMD_LINE_OPT_RULE_IPV4 "rule_ipv4"
#define CMD_LINE_OPT_RULE_IPV6 "rule_ipv6"
#define CMD_LINE_OPT_SCALAR	"scalar"
#define CMD_LINE_OPT_PROMISC "promiscuous"
#define CMD_LINE_OPT_NO_NUMA "no-numa"
#define CMD_LINE_OPT_ENABLE_JUMBO "enable-jumbo"
#define CMD_LINE_OPT_MAXPKT_LEN "max-pkt-len"
#define CMD_LINE_OPT_PORTMASK	"portmask"
#define CMD_LINE_OPT_CONFIGFILE	"configfile"

#define FILE_MAIN_CONFIG	"rdpdk"

#define MAX_LCORE_PARAMS 1024
#define MAX_JUMBO_PKT_LEN  9600

#endif
