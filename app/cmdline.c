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

#define CMDLINE_MAX_SOCK 32
#define CMDLINE_POLL_TIMEOUT 10000

static pthread_t cmdline_tid;
static int cmdline_thread_loop;

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
						   rte_be_to_cpu_32(res->ip.addr.ipv4.s_addr), &next_hop);
		if (i == -ENOENT) {
			cmdline_printf(cl, "not found\n");
		} else {
			struct in_addr *addr =
				&neighbor4_struct[0]->entries.t4[next_hop].addr;
			cmdline_printf(cl, "present, next_hop %s\n", inet_ntop(AF_INET, addr, buf, INET6_ADDRSTRLEN));
		}
	} else if (res->ip.family == AF_INET6) {
		i = rte_lpm6_lookup(ipv6_l3fwd_lookup_struct[0],
						   res->ip.addr.ipv6.s6_addr, &next_hop);
		if (i == -ENOENT) {
			cmdline_printf(cl, "not found\n");
		} else {
			struct in6_addr *addr =
				&neighbor6_struct[0]->entries.t6[next_hop].addr;
			cmdline_printf(cl, "present, next_hop %s\n", inet_ntop(AF_INET6, addr, buf, INET6_ADDRSTRLEN));
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
	.help_str = "Do a lookup in lpm table (ip, version)",
	.tokens = {					/* token list, NULL terminated */
			   (void *) &cmd_obj_action_lpm_lkp,
			   (void *) &cmd_obj_lpm_ip,
			   NULL,
			   },
};

//----- CMD ACL_ADD

struct cmd_obj_acl_add_result {
	cmdline_fixed_string_t action;
	cmdline_ipaddr_t ip;
	uint8_t depth;
	uint8_t protonum;
	uint16_t port;
};

static void cmd_obj_acl_add_parsed(__rte_unused void *parsed_result,
								   __rte_unused struct cmdline *cl,
								   __rte_unused void *data)
{
//  struct cmd_obj_acl_add_result *res = parsed_result;

}

cmdline_parse_token_string_t cmd_obj_action_acl_add =
TOKEN_STRING_INITIALIZER(struct cmd_obj_acl_add_result, action, "acl_add");
cmdline_parse_token_ipaddr_t cmd_obj_acl_ip =
TOKEN_IPADDR_INITIALIZER(struct cmd_obj_acl_add_result, ip);
cmdline_parse_token_num_t cmd_obj_acl_depth =
TOKEN_NUM_INITIALIZER(struct cmd_obj_acl_add_result, depth, UINT8);
cmdline_parse_token_num_t cmd_obj_acl_protonum =
TOKEN_NUM_INITIALIZER(struct cmd_obj_acl_add_result, protonum, UINT8);
cmdline_parse_token_num_t cmd_obj_acl_port =
TOKEN_NUM_INITIALIZER(struct cmd_obj_acl_add_result, port, UINT16);

cmdline_parse_inst_t cmd_obj_acl_add = {
	.f = cmd_obj_acl_add_parsed,	/* function to call */
	.data = NULL,				/* 2nd arg of func */
	.help_str = "Add an acl (ip, depth, protonum, port)",
	.tokens = {					/* token list, NULL terminated */
			   (void *) &cmd_obj_action_acl_add,
			   (void *) &cmd_obj_acl_ip,
			   (void *) &cmd_obj_acl_depth,
			   (void *) &cmd_obj_acl_protonum,
			   (void *) &cmd_obj_acl_port,
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

int rdpdk_cmdline_stop(int sock, const char *path)
{
	cmdline_thread_loop = 0;

	if (pthread_join(cmdline_tid, NULL)) {
		perror("error during free cmdline pthread_join");
	}
	close(sock);
	unlink(path);

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
	cmdline_thread_loop = 1;
	if (pthread_create
		(&cmdline_tid, NULL, cmdline_run, (void *) (intptr_t) sock)) {
		perror("failed to create cmdline thread");
		rte_exit(EXIT_FAILURE, "failed to launch cmdline thread");
	}
	snprintf(thread_name, 16, "cmdline-%d", 0);
	pthread_setname_np(cmdline_tid, thread_name);
	return cmdline_tid;
}
