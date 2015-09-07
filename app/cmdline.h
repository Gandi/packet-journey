#ifndef __RDPDK_CMDLINE_H
#define __RDPDK_CMDLINE_H

int rdpdk_cmdline_init(const char *path, uint32_t socket_id);
pthread_t rdpdk_cmdline_launch(int sock);
int rdpdk_cmdline_stop(void);
int rdpdk_cmdline_terminate(int sock, const char *path);

#endif
