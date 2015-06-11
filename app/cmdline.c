#define _GNU_SOURCE
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <termios.h>
#include <unistd.h>
#include <poll.h>

#include <rte_common.h>
#include <rte_log.h>
#include <rte_lcore.h>
#include <rte_lpm.h>
#include <rte_lpm6.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_string_fns.h>

#include <cmdline_rdline.h>
#include <cmdline_parse.h>
#include <cmdline_socket.h>
#include <cmdline_parse_ipaddr.h>
#include <cmdline_parse_num.h>
#include <cmdline_parse_string.h>
#include <cmdline.h>


#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <libneighbour.h>

#include "common.h"
#include "cmdline.h"
#include "routing.h"
#include "acl.h"

#define CMDLINE_MAX_SOCK 32
#define CMDLINE_POLL_TIMEOUT 1000

static pthread_t cmdline_tid;
static int cmdline_thread_loop;

typedef uint8_t portid_t;

#define RSS_HASH_KEY_LENGTH 52
static void
port_rss_reta_info(portid_t port_id,
				   struct rte_eth_rss_reta_entry64 *reta_conf,
				   uint16_t nb_entries)
{
	uint16_t i, idx, shift;
	int ret;

	ret = rte_eth_dev_rss_reta_query(port_id, reta_conf, nb_entries);
	if (ret != 0) {
		printf("Failed to get RSS RETA info, return code = %d\n", ret);
		return;
	}

	for (i = 0; i < nb_entries; i++) {
		idx = i / RTE_RETA_GROUP_SIZE;
		shift = i % RTE_RETA_GROUP_SIZE;
		if (!(reta_conf[idx].mask & (1ULL << shift)))
			continue;
		printf("RSS RETA configuration: hash index=%u, queue=%u\n",
			   i, reta_conf[idx].reta[shift]);
	}
}

/*
 * Displays the RSS hash functions of a port, and, optionaly, the RSS hash
 * key of the port.
 */
static void port_rss_hash_conf_show(portid_t port_id, int show_rss_key)
{
	struct rss_type_info {
		char str[32];
		uint64_t rss_type;
	};
	static const struct rss_type_info rss_type_table[] = {
		{"ipv4", ETH_RSS_IPV4},
		{"ipv4-frag", ETH_RSS_FRAG_IPV4},
		{"ipv4-tcp", ETH_RSS_NONFRAG_IPV4_TCP},
		{"ipv4-udp", ETH_RSS_NONFRAG_IPV4_UDP},
		{"ipv4-sctp", ETH_RSS_NONFRAG_IPV4_SCTP},
		{"ipv4-other", ETH_RSS_NONFRAG_IPV4_OTHER},
		{"ipv6", ETH_RSS_IPV6},
		{"ipv6-frag", ETH_RSS_FRAG_IPV6},
		{"ipv6-tcp", ETH_RSS_NONFRAG_IPV6_TCP},
		{"ipv6-udp", ETH_RSS_NONFRAG_IPV6_UDP},
		{"ipv6-sctp", ETH_RSS_NONFRAG_IPV6_SCTP},
		{"ipv6-other", ETH_RSS_NONFRAG_IPV6_OTHER},
		{"l2-payload", ETH_RSS_L2_PAYLOAD},
		{"ipv6-ex", ETH_RSS_IPV6_EX},
		{"ipv6-tcp-ex", ETH_RSS_IPV6_TCP_EX},
		{"ipv6-udp-ex", ETH_RSS_IPV6_UDP_EX},
	};

	struct rte_eth_rss_conf rss_conf;
	uint8_t rss_key[10 * 8];
	uint64_t rss_hf;
	uint8_t i;
	int diag;

	/* Get RSS hash key if asked to display it */
	rss_conf.rss_key = (show_rss_key) ? rss_key : NULL;
	diag = rte_eth_dev_rss_hash_conf_get(port_id, &rss_conf);
	if (diag != 0) {
		switch (diag) {
		case -ENODEV:
			printf("port index %d invalid\n", port_id);
			break;
		case -ENOTSUP:
			printf("operation not supported by device\n");
			break;
		default:
			printf("operation failed - diag=%d\n", diag);
			break;
		}
		return;
	}
	rss_hf = rss_conf.rss_hf;
	if (rss_hf == 0) {
		printf("RSS disabled\n");
		return;
	}
	printf("RSS functions:\n ");
	for (i = 0; i < RTE_DIM(rss_type_table); i++) {
		if (rss_hf & rss_type_table[i].rss_type)
			printf("%s ", rss_type_table[i].str);
	}
	printf("\n");
	if (!show_rss_key)
		return;
	printf("RSS key:\n");
	for (i = 0; i < rss_conf.rss_key_len; i++)
		printf("%02X", rss_key[i]);
	printf("\n");
}

static void port_rss_hash_key_update(portid_t port_id, uint8_t * hash_key)
{
	struct rte_eth_rss_conf rss_conf;
	int diag;

	rss_conf.rss_key = NULL;
	diag = rte_eth_dev_rss_hash_conf_get(port_id, &rss_conf);
	if (diag == 0) {
		rss_conf.rss_key = hash_key;
		rss_conf.rss_key_len = RSS_HASH_KEY_LENGTH;
		diag = rte_eth_dev_rss_hash_update(port_id, &rss_conf);
	}
	if (diag == 0)
		return;

	switch (diag) {
	case -ENODEV:
		printf("port index %d invalid\n", port_id);
		break;
	case -ENOTSUP:
		printf("operation not supported by device\n");
		break;
	default:
		printf("operation failed - diag=%d\n", diag);
		break;
	}
}


/* *** Show RSS hash configuration *** */
struct cmd_showport_rss_hash {
	cmdline_fixed_string_t show;
	cmdline_fixed_string_t port;
	uint8_t port_id;
	cmdline_fixed_string_t rss_hash;
	cmdline_fixed_string_t key;	/* optional argument */
};

static void cmd_showport_rss_hash_parsed(void *parsed_result,
										 __attribute__ ((unused))
										 struct cmdline *cl,
										 void *show_rss_key)
{
	struct cmd_showport_rss_hash *res = parsed_result;

	port_rss_hash_conf_show(res->port_id, show_rss_key != NULL);
}

cmdline_parse_token_string_t cmd_showport_rss_hash_show =
TOKEN_STRING_INITIALIZER(struct cmd_showport_rss_hash, show, "show");
cmdline_parse_token_string_t cmd_showport_rss_hash_port =
TOKEN_STRING_INITIALIZER(struct cmd_showport_rss_hash, port, "port");
cmdline_parse_token_num_t cmd_showport_rss_hash_port_id =
TOKEN_NUM_INITIALIZER(struct cmd_showport_rss_hash, port_id, UINT8);
cmdline_parse_token_string_t cmd_showport_rss_hash_rss_hash =
TOKEN_STRING_INITIALIZER(struct cmd_showport_rss_hash, rss_hash,
						 "rss-hash");
cmdline_parse_token_string_t cmd_showport_rss_hash_rss_key =
TOKEN_STRING_INITIALIZER(struct cmd_showport_rss_hash, key, "key");

cmdline_parse_inst_t cmd_showport_rss_hash = {
	.f = cmd_showport_rss_hash_parsed,
	.data = NULL,
	.help_str = "show port X rss-hash (X = port number)\n",
	.tokens = {
			   (void *) &cmd_showport_rss_hash_show,
			   (void *) &cmd_showport_rss_hash_port,
			   (void *) &cmd_showport_rss_hash_port_id,
			   (void *) &cmd_showport_rss_hash_rss_hash,
			   NULL,
			   },
};

cmdline_parse_inst_t cmd_showport_rss_hash_key = {
	.f = cmd_showport_rss_hash_parsed,
	.data = (void *) 1,
	.help_str = "show port X rss-hash key (X = port number)\n",
	.tokens = {
			   (void *) &cmd_showport_rss_hash_show,
			   (void *) &cmd_showport_rss_hash_port,
			   (void *) &cmd_showport_rss_hash_port_id,
			   (void *) &cmd_showport_rss_hash_rss_hash,
			   (void *) &cmd_showport_rss_hash_rss_key,
			   NULL,
			   },
};



/* *** configure rss *** */
struct cmd_config_rss {
	cmdline_fixed_string_t port;
	cmdline_fixed_string_t keyword;
	cmdline_fixed_string_t all;
	cmdline_fixed_string_t name;
	cmdline_fixed_string_t value;
};

static void
cmd_config_rss_parsed(void *parsed_result, __attribute__ ((unused))
					  struct cmdline *cl, __attribute__ ((unused))
					  void *data)
{
	struct cmd_config_rss *res = parsed_result;
	struct rte_eth_rss_conf rss_conf;
	uint8_t i;

	if (!strcmp(res->value, "all"))
		rss_conf.rss_hf = ETH_RSS_IP | ETH_RSS_TCP |
			ETH_RSS_UDP | ETH_RSS_SCTP | ETH_RSS_L2_PAYLOAD;
	else if (!strcmp(res->value, "ip"))
		rss_conf.rss_hf = ETH_RSS_IP;
	else if (!strcmp(res->value, "udp"))
		rss_conf.rss_hf = ETH_RSS_UDP;
	else if (!strcmp(res->value, "tcp"))
		rss_conf.rss_hf = ETH_RSS_TCP;
	else if (!strcmp(res->value, "sctp"))
		rss_conf.rss_hf = ETH_RSS_SCTP;
	else if (!strcmp(res->value, "ether"))
		rss_conf.rss_hf = ETH_RSS_L2_PAYLOAD;
	else if (!strcmp(res->value, "none"))
		rss_conf.rss_hf = 0;
	else {
		printf("Unknown parameter\n");
		return;
	}
	rss_conf.rss_key = NULL;
	for (i = 0; i < rte_eth_dev_count(); i++)
		rte_eth_dev_rss_hash_update(i, &rss_conf);
}

cmdline_parse_token_string_t cmd_config_rss_port =
TOKEN_STRING_INITIALIZER(struct cmd_config_rss, port, "port");
cmdline_parse_token_string_t cmd_config_rss_keyword =
TOKEN_STRING_INITIALIZER(struct cmd_config_rss, keyword, "config");
cmdline_parse_token_string_t cmd_config_rss_all =
TOKEN_STRING_INITIALIZER(struct cmd_config_rss, all, "all");
cmdline_parse_token_string_t cmd_config_rss_name =
TOKEN_STRING_INITIALIZER(struct cmd_config_rss, name, "rss");
cmdline_parse_token_string_t cmd_config_rss_value =
TOKEN_STRING_INITIALIZER(struct cmd_config_rss, value,
						 "all#ip#tcp#udp#sctp#ether#none");

cmdline_parse_inst_t cmd_config_rss = {
	.f = cmd_config_rss_parsed,
	.data = NULL,
	.help_str = "port config all rss all|ip|tcp|udp|sctp|ether|none",
	.tokens = {
			   (void *) &cmd_config_rss_port,
			   (void *) &cmd_config_rss_keyword,
			   (void *) &cmd_config_rss_all,
			   (void *) &cmd_config_rss_name,
			   (void *) &cmd_config_rss_value,
			   NULL,
			   },
};

/* *** configure rss hash key *** */
struct cmd_config_rss_hash_key {
	cmdline_fixed_string_t port;
	cmdline_fixed_string_t config;
	uint8_t port_id;
	cmdline_fixed_string_t rss_hash_key;
	cmdline_fixed_string_t key;
};

static uint8_t hexa_digit_to_value(char hexa_digit)
{
	if ((hexa_digit >= '0') && (hexa_digit <= '9'))
		return (uint8_t) (hexa_digit - '0');
	if ((hexa_digit >= 'a') && (hexa_digit <= 'f'))
		return (uint8_t) ((hexa_digit - 'a') + 10);
	if ((hexa_digit >= 'A') && (hexa_digit <= 'F'))
		return (uint8_t) ((hexa_digit - 'A') + 10);
	/* Invalid hexa digit */
	return 0xFF;
}

static uint8_t parse_and_check_key_hexa_digit(char *key, int idx)
{
	uint8_t hexa_v;

	hexa_v = hexa_digit_to_value(key[idx]);
	if (hexa_v == 0xFF)
		printf("invalid key: character %c at position %d is not a "
			   "valid hexa digit\n", key[idx], idx);
	return hexa_v;
}

static void
cmd_config_rss_hash_key_parsed(void *parsed_result,
							   __attribute__ ((unused))
							   struct cmdline *cl, __attribute__ ((unused))
							   void *data)
{
	struct cmd_config_rss_hash_key *res = parsed_result;
	uint8_t hash_key[RSS_HASH_KEY_LENGTH];
	uint8_t xdgt0;
	uint8_t xdgt1;
	int i;

	/* Check the length of the RSS hash key */
	if (strlen(res->key) != (RSS_HASH_KEY_LENGTH * 2)) {
		printf("key length: %d invalid - key must be a string of %d"
			   "hexa-decimal numbers\n", (int) strlen(res->key),
			   RSS_HASH_KEY_LENGTH * 2);
		return;
	}
	/* Translate RSS hash key into binary representation */
	for (i = 0; i < RSS_HASH_KEY_LENGTH; i++) {
		xdgt0 = parse_and_check_key_hexa_digit(res->key, (i * 2));
		if (xdgt0 == 0xFF)
			return;
		xdgt1 = parse_and_check_key_hexa_digit(res->key, (i * 2) + 1);
		if (xdgt1 == 0xFF)
			return;
		hash_key[i] = (uint8_t) ((xdgt0 * 16) + xdgt1);
	}
	port_rss_hash_key_update(res->port_id, hash_key);
}

cmdline_parse_token_string_t cmd_config_rss_hash_key_port =
TOKEN_STRING_INITIALIZER(struct cmd_config_rss_hash_key, port, "port");
cmdline_parse_token_string_t cmd_config_rss_hash_key_config =
TOKEN_STRING_INITIALIZER(struct cmd_config_rss_hash_key, config,
						 "config");
cmdline_parse_token_num_t cmd_config_rss_hash_key_port_id =
TOKEN_NUM_INITIALIZER(struct cmd_config_rss_hash_key, port_id, UINT8);
cmdline_parse_token_string_t cmd_config_rss_hash_key_rss_hash_key =
TOKEN_STRING_INITIALIZER(struct cmd_config_rss_hash_key,
						 rss_hash_key, "rss-hash-key");
cmdline_parse_token_string_t cmd_config_rss_hash_key_value =
TOKEN_STRING_INITIALIZER(struct cmd_config_rss_hash_key, key, NULL);

cmdline_parse_inst_t cmd_config_rss_hash_key = {
	.f = cmd_config_rss_hash_key_parsed,
	.data = NULL,
	.help_str = "port config X rss-hash-key 104 hexa digits",
	.tokens = {
			   (void *) &cmd_config_rss_hash_key_port,
			   (void *) &cmd_config_rss_hash_key_config,
			   (void *) &cmd_config_rss_hash_key_port_id,
			   (void *) &cmd_config_rss_hash_key_rss_hash_key,
			   (void *) &cmd_config_rss_hash_key_value,
			   NULL,
			   },
};

/* *** Configure RSS RETA *** */
struct cmd_config_rss_reta {
	cmdline_fixed_string_t port;
	cmdline_fixed_string_t keyword;
	uint8_t port_id;
	cmdline_fixed_string_t name;
	cmdline_fixed_string_t list_name;
	cmdline_fixed_string_t list_of_items;
};

static int
parse_reta_config(const char *str,
				  struct rte_eth_rss_reta_entry64 *reta_conf,
				  uint16_t nb_entries)
{
	int i;
	unsigned size;
	uint16_t hash_index, idx, shift;
	uint8_t nb_queue;
	char s[256];
	const char *p, *p0 = str;
	char *end;
	enum fieldnames {
		FLD_HASH_INDEX = 0,
		FLD_QUEUE,
		_NUM_FLD
	};
	unsigned long int_fld[_NUM_FLD];
	char *str_fld[_NUM_FLD];

	while ((p = strchr(p0, '(')) != NULL) {
		++p;
		if ((p0 = strchr(p, ')')) == NULL)
			return -1;

		size = p0 - p;
		if (size >= sizeof(s))
			return -1;

		snprintf(s, sizeof(s), "%.*s", size, p);
		if (rte_strsplit(s, sizeof(s), str_fld, _NUM_FLD, ',') != _NUM_FLD)
			return -1;
		for (i = 0; i < _NUM_FLD; i++) {
			errno = 0;
			int_fld[i] = strtoul(str_fld[i], &end, 0);
			if (errno != 0 || end == str_fld[i] || int_fld[i] > 65535)
				return -1;
		}

		hash_index = (uint16_t) int_fld[FLD_HASH_INDEX];
		nb_queue = (uint8_t) int_fld[FLD_QUEUE];

		if (hash_index >= nb_entries) {
			printf("Invalid RETA hash index=%d\n", hash_index);
			return -1;
		}

		idx = hash_index / RTE_RETA_GROUP_SIZE;
		shift = hash_index % RTE_RETA_GROUP_SIZE;
		reta_conf[idx].mask |= (1ULL << shift);
		reta_conf[idx].reta[shift] = nb_queue;
	}

	return 0;
}

static void
cmd_set_rss_reta_parsed(void *parsed_result, __attribute__ ((unused))
						struct cmdline *cl, __attribute__ ((unused))
						void *data)
{
	int ret;
	struct rte_eth_dev_info dev_info;
	struct rte_eth_rss_reta_entry64 reta_conf[8];
	struct cmd_config_rss_reta *res = parsed_result;

	memset(&dev_info, 0, sizeof(dev_info));
	rte_eth_dev_info_get(res->port_id, &dev_info);
	if (dev_info.reta_size == 0) {
		printf("Redirection table size is 0 which is "
			   "invalid for RSS\n");
		return;
	} else
		printf("The reta size of port %d is %u\n",
			   res->port_id, dev_info.reta_size);
	if (dev_info.reta_size > ETH_RSS_RETA_SIZE_512) {
		printf("Currently do not support more than %u entries of "
			   "redirection table\n", ETH_RSS_RETA_SIZE_512);
		return;
	}

	memset(reta_conf, 0, sizeof(reta_conf));
	if (!strcmp(res->list_name, "reta")) {
		if (parse_reta_config(res->list_of_items, reta_conf,
							  dev_info.reta_size)) {
			printf("Invalid RSS Redirection Table " "config entered\n");
			return;
		}
		ret = rte_eth_dev_rss_reta_update(res->port_id,
										  reta_conf, dev_info.reta_size);
		if (ret != 0)
			printf("Bad redirection table parameter, "
				   "return code = %d \n", ret);
	}
}

cmdline_parse_token_string_t cmd_config_rss_reta_port =
TOKEN_STRING_INITIALIZER(struct cmd_config_rss_reta, port, "port");
cmdline_parse_token_string_t cmd_config_rss_reta_keyword =
TOKEN_STRING_INITIALIZER(struct cmd_config_rss_reta, keyword, "config");
cmdline_parse_token_num_t cmd_config_rss_reta_port_id =
TOKEN_NUM_INITIALIZER(struct cmd_config_rss_reta, port_id, UINT8);
cmdline_parse_token_string_t cmd_config_rss_reta_name =
TOKEN_STRING_INITIALIZER(struct cmd_config_rss_reta, name, "rss");
cmdline_parse_token_string_t cmd_config_rss_reta_list_name =
TOKEN_STRING_INITIALIZER(struct cmd_config_rss_reta, list_name, "reta");
cmdline_parse_token_string_t cmd_config_rss_reta_list_of_items =
TOKEN_STRING_INITIALIZER(struct cmd_config_rss_reta, list_of_items,
						 NULL);
cmdline_parse_inst_t cmd_config_rss_reta = {
	.f = cmd_set_rss_reta_parsed,
	.data = NULL,
	.help_str = "port config X rss reta (hash,queue)[,(hash,queue)]",
	.tokens = {
			   (void *) &cmd_config_rss_reta_port,
			   (void *) &cmd_config_rss_reta_keyword,
			   (void *) &cmd_config_rss_reta_port_id,
			   (void *) &cmd_config_rss_reta_name,
			   (void *) &cmd_config_rss_reta_list_name,
			   (void *) &cmd_config_rss_reta_list_of_items,
			   NULL,
			   },
};

/* *** SHOW PORT RETA INFO *** */
struct cmd_showport_reta {
	cmdline_fixed_string_t show;
	cmdline_fixed_string_t port;
	uint8_t port_id;
	cmdline_fixed_string_t rss;
	cmdline_fixed_string_t reta;
	uint16_t size;
	cmdline_fixed_string_t list_of_items;
};

static int
showport_parse_reta_config(struct rte_eth_rss_reta_entry64 *conf,
						   uint16_t nb_entries, char *str)
{
	uint32_t size;
	const char *p, *p0 = str;
	char s[256];
	char *end;
	char *str_fld[8];
	uint16_t i, num = nb_entries / RTE_RETA_GROUP_SIZE;
	int ret;

	p = strchr(p0, '(');
	if (p == NULL)
		return -1;
	p++;
	p0 = strchr(p, ')');
	if (p0 == NULL)
		return -1;
	size = p0 - p;
	if (size >= sizeof(s)) {
		printf("The string size exceeds the internal buffer size\n");
		return -1;
	}
	snprintf(s, sizeof(s), "%.*s", size, p);
	ret = rte_strsplit(s, sizeof(s), str_fld, num, ',');
	if (ret <= 0 || ret != num) {
		printf("The bits of masks do not match the number of "
			   "reta entries: %u\n", num);
		return -1;
	}
	for (i = 0; i < ret; i++)
		conf[i].mask = (uint64_t) strtoul(str_fld[i], &end, 0);

	return 0;
}

static void
cmd_showport_reta_parsed(void *parsed_result, __attribute__ ((unused))
						 struct cmdline *cl, __attribute__ ((unused))
						 void *data)
{
	struct cmd_showport_reta *res = parsed_result;
	struct rte_eth_rss_reta_entry64 reta_conf[8];
	struct rte_eth_dev_info dev_info;

	memset(&dev_info, 0, sizeof(dev_info));
	rte_eth_dev_info_get(res->port_id, &dev_info);
	if (dev_info.reta_size == 0 || res->size != dev_info.reta_size ||
		res->size > ETH_RSS_RETA_SIZE_512) {
		printf("Invalid redirection table size: %u\n", res->size);
		return;
	}

	memset(reta_conf, 0, sizeof(reta_conf));
	if (showport_parse_reta_config(reta_conf, res->size,
								   res->list_of_items) < 0) {
		printf("Invalid string: %s for reta masks\n", res->list_of_items);
		return;
	}
	port_rss_reta_info(res->port_id, reta_conf, res->size);
}

cmdline_parse_token_string_t cmd_showport_reta_show =
TOKEN_STRING_INITIALIZER(struct cmd_showport_reta, show, "show");
cmdline_parse_token_string_t cmd_showport_reta_port =
TOKEN_STRING_INITIALIZER(struct cmd_showport_reta, port, "port");
cmdline_parse_token_num_t cmd_showport_reta_port_id =
TOKEN_NUM_INITIALIZER(struct cmd_showport_reta, port_id, UINT8);
cmdline_parse_token_string_t cmd_showport_reta_rss =
TOKEN_STRING_INITIALIZER(struct cmd_showport_reta, rss, "rss");
cmdline_parse_token_string_t cmd_showport_reta_reta =
TOKEN_STRING_INITIALIZER(struct cmd_showport_reta, reta, "reta");
cmdline_parse_token_num_t cmd_showport_reta_size =
TOKEN_NUM_INITIALIZER(struct cmd_showport_reta, size, UINT16);
cmdline_parse_token_string_t cmd_showport_reta_list_of_items =
TOKEN_STRING_INITIALIZER(struct cmd_showport_reta,
						 list_of_items, NULL);

cmdline_parse_inst_t cmd_showport_reta = {
	.f = cmd_showport_reta_parsed,
	.data = NULL,
	.help_str = "show port X rss reta (size) (mask0,mask1,...)",
	.tokens = {
			   (void *) &cmd_showport_reta_show,
			   (void *) &cmd_showport_reta_port,
			   (void *) &cmd_showport_reta_port_id,
			   (void *) &cmd_showport_reta_rss,
			   (void *) &cmd_showport_reta_reta,
			   (void *) &cmd_showport_reta_size,
			   (void *) &cmd_showport_reta_list_of_items,
			   NULL,
			   },
};


//----- CMD LPM_LKP

struct cmd_obj_lpm_lkp_result {
	cmdline_fixed_string_t action;
	cmdline_ipaddr_t ip;
};

static void cmd_obj_lpm_lkp_parsed(void *parsed_result,
								   struct cmdline *cl,
								   __rte_unused void *data)
{
	struct cmd_obj_lpm_lkp_result *res = parsed_result;
	uint8_t next_hop;
	int i;
	char buf[INET6_ADDRSTRLEN];

	if (res->ip.family == AF_INET) {
		i = rte_lpm_lookup(ipv4_l3fwd_lookup_struct[0],
						   rte_be_to_cpu_32(res->ip.addr.ipv4.s_addr),
						   &next_hop);
		if (i < 0) {
			cmdline_printf(cl, "not found\n");
		} else {
			struct in_addr *addr =
				&neighbor4_struct[0]->entries.t4[next_hop].addr;
			cmdline_printf(cl, "present, next_hop %s\n",
						   inet_ntop(AF_INET, addr, buf,
									 INET6_ADDRSTRLEN));
		}
	} else if (res->ip.family == AF_INET6) {
		i = rte_lpm6_lookup(ipv6_l3fwd_lookup_struct[0],
							res->ip.addr.ipv6.s6_addr, &next_hop);
		if (i < 0) {
			cmdline_printf(cl, "not found\n");
		} else {
			struct in6_addr *addr =
				&neighbor6_struct[0]->entries.t6[next_hop].addr;
			cmdline_printf(cl, "present, next_hop %s\n",
						   inet_ntop(AF_INET6, addr, buf,
									 INET6_ADDRSTRLEN));
		}
	}
}

cmdline_parse_token_string_t cmd_obj_action_lpm_lkp =
TOKEN_STRING_INITIALIZER(struct cmd_obj_lpm_lkp_result, action, "lpm_lkp");
cmdline_parse_token_ipaddr_t cmd_obj_lpm_ip =
TOKEN_IPADDR_INITIALIZER(struct cmd_obj_lpm_lkp_result, ip);

cmdline_parse_inst_t cmd_obj_lpm_lkp = {
	.f = cmd_obj_lpm_lkp_parsed,	/* function to call */
	.data = NULL,				/* 2nd arg of func */
	.help_str = "Do a lookup in lpm table (ip)",
	.tokens = {					/* token list, NULL terminated */
			   (void *) &cmd_obj_action_lpm_lkp,
			   (void *) &cmd_obj_lpm_ip,
			   NULL,
			   },
};

//----- CMD ACL_ADD

struct cmd_obj_acl_add_result {
	cmdline_fixed_string_t action;
	cmdline_fixed_string_t path;
	cmdline_fixed_string_t proto;
};

static void cmd_obj_acl_add_parsed(void *parsed_result,
								   __rte_unused struct cmdline *cl,
								   __rte_unused void *data)
{
	struct cmd_obj_acl_add_result *res = parsed_result;
	int is_ipv4;

	is_ipv4 = !strcmp(res->proto, "ipv4");
	if (is_ipv4) {
		acl_parm_config.rule_ipv4_name = res->path;
	} else {
		acl_parm_config.rule_ipv6_name = res->path;
	}
	acl_init(is_ipv4);
}

cmdline_parse_token_string_t cmd_obj_action_acl_add =
TOKEN_STRING_INITIALIZER(struct cmd_obj_acl_add_result, action, "acl_add");
cmdline_parse_token_string_t cmd_obj_acl_path =
TOKEN_STRING_INITIALIZER(struct cmd_obj_acl_add_result, path, "");
cmdline_parse_token_string_t cmd_obj_acl_proto =
TOKEN_STRING_INITIALIZER(struct cmd_obj_acl_add_result, proto,
						 "ipv4#ipv6");

cmdline_parse_inst_t cmd_obj_acl_add = {
	.f = cmd_obj_acl_add_parsed,	/* function to call */
	.data = NULL,				/* 2nd arg of func */
	.help_str = "Add an acl (aclfile path, ip version)",
	.tokens = {					/* token list, NULL terminated */
			   (void *) &cmd_obj_action_acl_add,
			   (void *) &cmd_obj_acl_path,
			   (void *) &cmd_obj_acl_proto,
			   NULL,
			   },
};

//----- CMD STATS

struct cmd_stats_result {
	cmdline_fixed_string_t stats;
};

static void cmd_stats_parsed( __attribute__ ((unused))
							 void *parsed_result,
							 struct cmdline *cl, __attribute__ ((unused))
							 void *data)
{
	uint64_t total_packets_dropped, total_packets_tx, total_packets_rx;
	uint64_t total_packets_kni_tx, total_packets_kni_rx;
	unsigned lcoreid;

	total_packets_dropped = 0;
	total_packets_tx = 0;
	total_packets_rx = 0;
	total_packets_kni_tx = 0;
	total_packets_kni_rx = 0;

	cmdline_printf(cl,
				   "\nLcore statistics ====================================");

	for (lcoreid = 0; lcoreid < RTE_MAX_LCORE; lcoreid++) {
		if (!rte_lcore_is_enabled(lcoreid))
			continue;

		cmdline_printf(cl,
					   "\nStatistics for lcore %u portid %lu ---------------"
					   "\nLoop iteration: %lu" "\nPackets sent: %lu"
					   "\nPackets received: %lu" "\nPackets kni sent: %lu"
					   "\nPackets kni received: %lu"
					   "\nPackets dropped: %lu", lcoreid,
					   stats[lcoreid].port_id,
					   stats[lcoreid].nb_iteration_looped,
					   stats[lcoreid].nb_tx, stats[lcoreid].nb_rx,
					   stats[lcoreid].nb_kni_tx, stats[lcoreid].nb_kni_rx,
					   stats[lcoreid].nb_dropped);

		total_packets_dropped += stats[lcoreid].nb_dropped;
		total_packets_tx += stats[lcoreid].nb_tx;
		total_packets_rx += stats[lcoreid].nb_rx;
		total_packets_kni_tx += stats[lcoreid].nb_kni_tx;
		total_packets_kni_rx += stats[lcoreid].nb_kni_rx;
	}
	cmdline_printf(cl,
				   "\nAggregate statistics ==============================="
				   "\nTotal packets sent: %lu"
				   "\nTotal packets received: %lu"
				   "\nTotal packets kni sent: %lu"
				   "\nTotal packets kni received: %lu"
				   "\nTotal packets dropped: %lu", total_packets_tx,
				   total_packets_rx, total_packets_kni_tx,
				   total_packets_kni_rx, total_packets_dropped);
	cmdline_printf(cl,
				   "\n====================================================\n");
}

cmdline_parse_token_string_t cmd_stats_stats =
TOKEN_STRING_INITIALIZER(struct cmd_stats_result, stats, "stats");

cmdline_parse_inst_t cmd_stats = {
	.f = cmd_stats_parsed,		/* function to call */
	.data = NULL,				/* 2nd arg of func */
	.help_str = "show stats",
	.tokens = {					/* token list, NULL terminated */
			   (void *) &cmd_stats_stats,
			   NULL,
			   },
};



//----- CMD HELP

struct cmd_help_result {
	cmdline_fixed_string_t help;
};

static void cmd_help_parsed( __attribute__ ((unused))
							void *parsed_result,
							struct cmdline *cl, __attribute__ ((unused))
							void *data)
{
	cmdline_printf(cl,
				   "commands:\n"
				   "- acl_add IP CIDR PROTONUM PORT\n"
				   "- lpm_lkp IP[/DEPTH]\n" "- stats\n" "- help\n\n");
}

cmdline_parse_token_string_t cmd_help_help =
TOKEN_STRING_INITIALIZER(struct cmd_help_result, help, "help");

cmdline_parse_inst_t cmd_help = {
	.f = cmd_help_parsed,		/* function to call */
	.data = NULL,				/* 2nd arg of func */
	.help_str = "show help",
	.tokens = {					/* token list, NULL terminated */
			   (void *) &cmd_help_help,
			   NULL,
			   },
};

//----- !CMD HELP

cmdline_parse_ctx_t main_ctx[] = {
	(cmdline_parse_inst_t *) & cmd_obj_acl_add,
	(cmdline_parse_inst_t *) & cmd_obj_lpm_lkp,
	(cmdline_parse_inst_t *) & cmd_stats,
	(cmdline_parse_inst_t *) & cmd_config_rss,
	(cmdline_parse_inst_t *) & cmd_config_rss_reta,
	(cmdline_parse_inst_t *) & cmd_showport_reta,
	(cmdline_parse_inst_t *) & cmd_showport_rss_hash,
	(cmdline_parse_inst_t *) & cmd_showport_rss_hash_key,
	(cmdline_parse_inst_t *) & cmd_config_rss_hash_key,
	(cmdline_parse_inst_t *) & cmd_help,
	NULL,
};

static int create_unixsock(const char *path)
{
	int sock;
	struct sockaddr_un local;
	unsigned len;

	if ((sock = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
		perror("failed to create cmdline unixsock");
		rte_exit(EXIT_FAILURE, "create_unixsock failure");
	}

	local.sun_family = AF_UNIX;
	strcpy(local.sun_path, path);
	unlink(local.sun_path);
	len = strlen(local.sun_path) + sizeof(local.sun_family);

	if (bind(sock, (struct sockaddr *) &local, len) == -1) {
		perror("failed to bind cmdline unixsock");
		rte_exit(EXIT_FAILURE, "create_unixsock failure");
	}

	if (listen(sock, 10) == -1) {
		perror("failed to put the cmdline unixsock in listen state");
		rte_exit(EXIT_FAILURE, "create_unixsock failure");
	}

	return sock;
}

static struct cmdline *cmdline_unixsock_new(cmdline_parse_ctx_t * ctx,
											const char *prompt, int sock)
{
	return (cmdline_new(ctx, prompt, sock, sock));
}


static void *cmdline_new_unixsock(int sock)
{
	struct cmdline *cl;

	cl = cmdline_unixsock_new(main_ctx, "rdpdk> ", sock);

	if (cl == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create cmdline instance\n");

	return cl;
}

int rdpdk_cmdline_init(const char *path)
{
	int fd;

	/* everything else is checked in cmdline_new() */
	if (!path)
		return -1;

	fd = create_unixsock(path);
	if (fd < 0) {
		dprintf("open() failed\n");
		return -1;
	}
	return fd;
}

static int rdpdk_cmdline_free(void *cmdline)
{
	struct cmdline *cl = cmdline;
	//cmdline_thread_loop = 0;

	//FIXME uncomment when we will do multisession
	/*if (pthread_join(cmdline_tid, NULL)) {
	   perror("error during free cmdline pthread_join");
	   } */

	cmdline_quit(cl);
	cmdline_free(cl);
	return 0;
}

int rdpdk_cmdline_terminate(int sock, const char *path)
{
	if (pthread_join(cmdline_tid, NULL)) {
		perror("error during free cmdline pthread_join");
	}
	close(sock);
	unlink(path);
	return 0;
}

int rdpdk_cmdline_stop(void)
{
	cmdline_thread_loop = 0;
	return 0;
}

static void *cmdline_run(void *data)
{
	struct pollfd fds[CMDLINE_MAX_SOCK];
	int sock = (intptr_t) data;
	int nfds = 1;
	//int i;
	struct cmdline *cl;

	fds[0].events = POLLIN;
	fds[0].fd = sock;
	while (cmdline_thread_loop) {
		int res = poll(fds, nfds, CMDLINE_POLL_TIMEOUT);
		if (res < 0 && errno != EINTR) {
			perror("error during cmdline_run poll");
			RTE_LOG(ERR, CMDLINE, "failed to deletie route...\n");
			return 0;
		}
		if (fds[0].revents & POLLIN) {
			res = accept(fds[0].fd, NULL, NULL);
			/*
			   fds[nfds].fd = res;
			   fds[nfds++].events = POLLIN;
			 */
			cl = cmdline_new_unixsock(res);
			//FIXME if we want to handle multiple sessions, launch it in a thread
			cmdline_interact(cl);
			rdpdk_cmdline_free(cl);
			close(res);
		}
		/*for (i = 1; i < nfds; ++i) {
		   if (fds[i].revents & (POLLIN | POLLHUP)) {

		   }
		   } */
	}
	return 0;
}


int rdpdk_cmdline_launch(int sock)
{
	char thread_name[16];
	cpu_set_t cpuset;
	int ret;

	cmdline_thread_loop = 1;

	ret =
		pthread_create(&cmdline_tid, NULL, cmdline_run,
					   (void *) (intptr_t) sock);
	if (ret != 0) {
		perror("failed to create cmdline thread");
		rte_exit(EXIT_FAILURE, "failed to launch cmdline thread");
	}

	snprintf(thread_name, 16, "cmdline-%d", 0);
	pthread_setname_np(cmdline_tid, thread_name);

	CPU_ZERO(&cpuset);
	CPU_SET(0, &cpuset);
	ret = pthread_setaffinity_np(cmdline_tid, sizeof(cpu_set_t), &cpuset);
	if (ret != 0) {
		perror("control pthread_setaffinity_np: ");
		rte_exit(EXIT_FAILURE,
				 "control pthread_setaffinity_np returned error: err=%d,",
				 ret);
	}

	return cmdline_tid;
}
