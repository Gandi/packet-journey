#ifndef __RDPDK_CMDLINE_H
#define __RDPDK_CMDLINE_H

int rdpdk_cmdline_init(const char *path, uint32_t socket_id);
pthread_t rdpdk_cmdline_launch(int sock);
int rdpdk_cmdline_stop(void);
int rdpdk_cmdline_terminate(int sock, const char *path);

#define CMDLINE_MAX_CLIENTS 32
struct client_data_t {
	struct cmdline	*cl;
	uint8_t			csv_delay;
	time_t			delay_timer;
};
extern struct client_data_t cmdline_clients[CMDLINE_MAX_CLIENTS];

#endif
